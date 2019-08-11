from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

LABEL = 0
SFC_TABLE = 5
TTL = 255

sfc_application_instance_name = 'sfc_api_app'
url = "/sfp_instances"
delete_url = "/sfp_instances/{nfp_id}"

class sfc_app(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(sfc_app, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}
        self.match_table = {}
        self.switches = {}
        self.label = LABEL
        wsgi = kwargs['wsgi']
        wsgi.register(
            sfc_service,
            {sfc_application_instance_name: self}
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to

        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly. The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=0):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, table_id=table_id,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=table_id,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,table_id=table_id,
                                match=match)
        datapath.send_msg(mod)

    def install_path_matches(self, dpid, nfp_id, criteria_list, out_port):
        # print("dpid : ", dpid, " ==> nfp_id :",nfp_id)
        datapath = self.switches[dpid]
        print("datapath id is : ", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        eth_VLAN = ether_types.ETH_TYPE_8021Q

        for criteria in criteria_list:
            self.logger.info("criteria to add  : %s  ==> path id : %s", criteria, nfp_id)

            actions = [parser.OFPActionPushVlan(ethertype=33024, type_=None, len_=None),
                       parser.OFPActionSetField(vlan_vid=4096+self.label + nfp_id)]

            if criteria["ip_proto"] == "tcp":
                if  criteria["source-port"] == 0 and criteria['destination-port']==0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            )
                elif criteria["source-port"] == 0:
                    match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            tcp_dst=criteria["destination-port"]
                                            )
                elif criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            tcp_src = criteria["source-port"]
                                            )
                else:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            tcp_src=criteria["source-port"],
                                            tcp_dst=criteria["destination-port"]
                                            )
            elif criteria["ip_proto"] == "udp":
                if criteria["source-port"] == 0 and criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            )
                elif criteria["source-port"] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            udp_dst=criteria["destination-port"]
                                            )
                elif criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            udp_src=criteria["source-port"]
                                            )
                else:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            udp_src=criteria["source-port"],
                                            udp_dst=criteria["destination-port"]
                                            )
            elif criteria["ip_proto"] == "sctp":
                if criteria["source-port"] == 0 and criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            )
                elif criteria["source-port"] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            sctp_dst=criteria["destination-port"]
                                            )
                elif criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            sctp_src=criteria["source-port"]
                                            )
                else:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            sctp_src=criteria["source-port"],
                                            sctp_dst=criteria["destination-port"]
                                            )
            else:
                return "Unknown protocol : ",criteria["ip_proto"]


            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(SFC_TABLE)]

            mod = parser.OFPFlowMod(
                datapath=datapath, priority=1000, match=match, instructions=inst
            )

            datapath.send_msg(mod)


            mpls_fow_match = parser.OFPMatch()
            mpls_fow_match.set_dl_type(ether_types.ETH_TYPE_8021Q)
            mpls_fow_match.set_vlan_vid(self.label + nfp_id)

            mpls_fow_instructions = [parser.OFPInstructionGotoTable(SFC_TABLE)]

            mpls_flow_mod = parser.OFPFlowMod(
                datapath=datapath, priority=1000, match=mpls_fow_match, instructions=mpls_fow_instructions
            )

            datapath.send_msg(mpls_flow_mod)
        return self.label + nfp_id

    def delete_path_matches(self, dpid, nfp_id, criteria_list):
        datapath = self.switches[dpid]
        parser = datapath.ofproto_parser
        for criteria in criteria_list:
            self.logger.info("criteria to delete  : %s  ==> path id : %s", criteria, nfp_id)
            if criteria["ip_proto"] == "tcp":
                if criteria["source-port"] == 0 and criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            )
                elif criteria["source-port"] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            tcp_dst=criteria["destination-port"]
                                            )
                elif criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            tcp_src=criteria["source-port"]
                                            )
                else:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_TCP,
                                            tcp_src=criteria["source-port"],
                                            tcp_dst=criteria["destination-port"]
                                            )
            elif criteria["ip_proto"] == "udp":
                if criteria["source-port"] == 0 and criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            )
                elif criteria["source-port"] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            udp_dst=criteria["destination-port"]
                                            )
                elif criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            udp_src=criteria["source-port"]
                                            )
                else:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_UDP,
                                            udp_src=criteria["source-port"],
                                            udp_dst=criteria["destination-port"]
                                            )
            elif criteria["ip_proto"] == "sctp":
                if criteria["source-port"] == 0 and criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            )
                elif criteria["source-port"] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            sctp_dst=criteria["destination-port"]
                                            )
                elif criteria['destination-port'] == 0:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            sctp_src=criteria["source-port"]
                                            )
                else:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            in_port=criteria['in_port'],
                                            ipv4_src=criteria["source-ip-address"],
                                            ipv4_dst=criteria["destination-ip-address"],
                                            ip_proto=in_proto.IPPROTO_SCTP,
                                            sctp_src=criteria["source-port"],
                                            sctp_dst=criteria["destination-port"]
                                            )
            else:
                return "Unknown protocol : ", criteria["ip_proto"]

            self.del_flow(datapath=datapath, match=match)

        mpls_fow_match = parser.OFPMatch()
        mpls_fow_match.set_dl_type(ether_types.ETH_TYPE_8021Q)
        mpls_fow_match.set_vlan_vid(self.label + nfp_id)
        self.del_flow(datapath=datapath, match=mpls_fow_match)

    def install_rendred_path_steps(self, dpid, nfp_id, rendered_path):
        datapath = self.switches[dpid]
        parser = datapath.ofproto_parser
        rendred_path_length = len(rendered_path)
        i = 0
        for path_element in rendered_path:

            self.logger.info("path element order : %s, in_port : %s, out_port : %s ", path_element["order"],
                             path_element["in_port"], path_element["out_port"])
            if i == rendred_path_length - 1:
                actions = [
                           parser.OFPActionOutput(path_element["out_port"])]
            else:
                actions = [parser.OFPActionOutput(path_element["out_port"])]

            i = i + 1

            match = parser.OFPMatch()
            match.set_in_port(path_element["in_port"])
            match.set_vlan_vid(self.label + nfp_id)
            self.add_flow(datapath=datapath, priority=1000, match=match,actions=actions, table_id=SFC_TABLE)
        return rendred_path_length

    def delete_rendred_path_steps(self, dpid, nfp_id, rendered_path):
        datapath = self.switches[dpid]
        parser = datapath.ofproto_parser
        for path_element in rendered_path:
            self.logger.info("path element order : %s, in_port : %s, out_port : %s ", path_element["order"],
                             path_element["in_port"], path_element["out_port"])

            match = parser.OFPMatch()
            match.set_in_port(path_element["in_port"])
            match.set_vlan_vid(self.label + nfp_id)
            self.del_flow(datapath=datapath,match=match, table_id=SFC_TABLE)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)


class sfc_service(ControllerBase):
    sfp_list = {}

    def __init__(self, req, link, data, **config):
        super(sfc_service, self).__init__(req, link, data, **config)
        self.simple_sfc_app = data[sfc_application_instance_name]

    @route("renderedpath", url, methods=['GET'])
    def get_sfc_paths(self, req, **kwargs):
        try:
            body = json.dumps(self.sfp_list)
            return Response(content_type='application/json', body=body, status=200, charset='UTF-8')
        except Exception as e:
            return Response(status=500)

    @route('renderedpath',url, methods=['POST'])
    def install_path(self, req, **kwargs):
        sfc_app_instance = self.simple_sfc_app
        res = {}
        try:
            sfp_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        dpid = sfp_entry['dpid']
        nfp_id = sfp_entry['nfp_id']
        criteria_list = sfp_entry['criteria']
        rendered_path = sfp_entry['rendered_path']
        try:
            # mpls_label = 12
            # print("mpls label 1 : ", mpls_label)
            # sfc_app_instance.print_hello()
            mpls_label = sfc_app_instance.install_path_matches(dpid,nfp_id,criteria_list, rendered_path[0]["out_port"])
            print("mpls label 2 : ", mpls_label)
            path_hops_number = sfc_app_instance.install_rendred_path_steps(dpid,nfp_id,rendered_path)
            # path_hops_number = 0
            res['sfc_path']={}
            res['sfc_path']['name'] = sfp_entry['nfp_name']
            res['sfc_path']['dpid'] = dpid
            res['sfc_path']['nfp_id'] = nfp_id
            res['sfc_path']['label'] = mpls_label
            res['sfc_path']['steps'] = path_hops_number

            self.sfp_list.setdefault(nfp_id, {})
            self.sfp_list[nfp_id]['sfc_desc'] = sfp_entry
            print(self.sfp_list[nfp_id])

            body = json.dumps(res)
            # return Response(status=200)
            return Response(content_type='application/json', body=body, status=201, charset='UTF-8')
        except Exception as e:
            print("error : ",e)
            return Response(status=501)

    @route("renderedpath", delete_url, methods=['DELETE'])
    def delete_path(self, req, **kwargs):
        sfc_app_instance = self.simple_sfc_app
        nfp_id = int(kwargs['nfp_id'])

        if nfp_id not in self.sfp_list:
            return Response(body="path with id : "+str(nfp_id)+" not found", status=404)

        sfc_desc = self.sfp_list[nfp_id]['sfc_desc']
        dpid = sfc_desc['dpid']
        nfp_id = sfc_desc['nfp_id']
        criteria_list = sfc_desc['criteria']
        rendered_path = sfc_desc['rendered_path']
        try:
            sfc_app_instance.delete_path_matches(dpid,nfp_id,criteria_list)
            sfc_app_instance.delete_rendred_path_steps(dpid, nfp_id, rendered_path)
            self.sfp_list.pop(nfp_id)
            return Response(body="deleted", status=301)
        except Exception as e:
            print("error", e)
            return Response(status=500)