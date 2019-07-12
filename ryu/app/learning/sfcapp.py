from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto

# Algorithm
#    matchs = []
#    foreach match in matchs:
#       create flow entry witch srcip dstip ipport protocol
#       action push label x and send to table 5
#    table 5 :
#       if in_port=i && label x ==> action: output j
#
#

LABEL = 0
SFC_TABLE = 5

class sfc(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(sfc, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}
        self.match_table = {}
        self.label = LABEL

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        match1 = {
            "id" : 1,
            "in_port" : 1,
            "src_ip" : "10.1.1.1",
            "dst_ip" : "10.1.1.4",
            "src_port" : 0,
            "dst_port" : 80,
            "ip_protocol" : in_proto.IPPROTO_TCP
        }

        match2 = {
            "id" : 1,
            "in_port" : 1,
            "src_ip" : "10.1.1.1",
            "dst_ip" : "10.1.1.3",
            "src_port" : 80,
            "dst_port" : 80,
            "ip_protocol" : in_proto.IPPROTO_UDP
        }
        self.match_table.setdefault(dpid, {})
        self.match_table[dpid][0] = match1
        self.match_table[dpid][1] = match2

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.add_default_match(datapath, self.match_table)

    def add_default_match(self,datapath, matchs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        for m in matchs[dpid]:
            criteria = matchs[dpid][m]
            self.logger.info("match : %s",criteria)
            actions = [parser.OFPActionPushMpls(ethertype=34887, type_=None, len_=None),
                       parser.OFPActionSetField(mpls_label=self.label),
                       ]
            self.label = self.label + 10
            if criteria["ip_protocol"] == in_proto.IPPROTO_TCP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        in_port=criteria['in_port'],
                                        ip_proto=in_proto.IPPROTO_TCP,
                                        ipv4_src=criteria["src_ip"],
                                        ipv4_dst=criteria["dst_ip"],
                                        tcp_src=criteria["src_port"],
                                        tcp_dst=criteria["dst_port"]
                                        )
            elif criteria["ip_protocol"] == in_proto.IPPROTO_UDP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        in_port=criteria['in_port'],
                                        ip_proto=in_proto.IPPROTO_UDP,
                                        ipv4_src=criteria["src_ip"],
                                        ipv4_dst=criteria["dst_ip"],
                                        udp_src=criteria["src_port"],
                                        udp_dst=criteria["dst_port"]
                                        )
            elif criteria["ip_protocol"] == in_proto.IPPROTO_SCTP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        in_port=criteria['in_port'],
                                        ip_proto=in_proto.IPPROTO_SCTP,
                                        ipv4_src=criteria["src_ip"],
                                        ipv4_dst=criteria["dst_ip"],
                                        sctp_src=criteria["src_port"],
                                        sctp_dst=criteria["dst_port"]
                                        )
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(SFC_TABLE)]
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=10000, match=match, instructions=inst
            )
            datapath.send_msg(mod)

    def sfc(self, datapath, connections, match_table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(1)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

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
