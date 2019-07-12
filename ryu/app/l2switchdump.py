import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3_parser

class L2Switch(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.match_table = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp =  msg.datapath
        ofp = dp.ofproto
        ofp_parser =  dp.ofproto_parser

        match = ofp_parser.OFPMatch(
            in_port = 1,
            ipv4_src = "10.0.0.1",
            ipv4_dst = "10.0.0.5"
        )

        actions = [ofp_parser.OFPActionSetField(ip_dscp=hex(22)),ofp_parser.OFPActionSetNwTtl]
        inst = [ofp_parser.OFPInstructionGotoTable(2)]
        out = ofp_parser.OFPPacketOut(
            datapath = dp, buffer_id = msg.buffer_id, in_port=msg.in_port, actions = actions
        )
        dp.send_msg(out)

    def create_matchs(self,parser, match_json):
        label=None
        match = ofproto_v1_3_parser.OFPMatch
        matchload = json.load(match_json)
        match_id = match_json["id"]
        match_name = match_json["name"]
        self.match_table.setdefault(match_id, {})
        self.match_table[match_id][match_name] = match_name
        self.match_table[match_id][label] = 200
        for elemeny in matchload:
            if elemeny["ip_proto"] == "tcp":
                match = parser.OFMatch(ip_proto=elemeny["in_port"], in_port=elemeny["ip_port"], tcp_src=elemeny["source_port"], tcp_dst=elemeny["destination_port"],
                                       ipv4_src=elemeny["source_ip_address"], ipv4_dst=elemeny["destination_ip_address"])
            elif elemeny["ip_proto"] == "udp":
                match = parser.OFMatch(ip_proto=elemeny["in_port"], in_port=elemeny["ip_port"],
                                       tcp_src=elemeny["source_port"], tcp_dst=elemeny["destination_port"],
                                       ipv4_src=elemeny["source_ip_address"],
                                       ipv4_dst=elemeny["destination_ip_address"])


    def create_flow_match(self, parser,  network_src_port_id, ip_proto, tcp_source_port=None, tcp_dest_port=None, udp_source_port=None, udp_dest_port=None, source_ip_address=None,
                   destination_ip_address=None, source_mac_address=None, destionation_mac_address=None):
        if ip_proto == 'tcp':
            if source_ip_address != None:
                match = parser.OFMatch(ip_port = network_src_port_id, tcp_src= tcp_source_port, tcp_dst=tcp_dest_port, ipv4_src=source_ip_address, ipv4_dst=destination_ip_address)
            elif source_ip_address != None:
                match = parser.OFMatch(ip_proto=network_src_port_id, tcp_src=tcp_dest_port, tcp_dst=tcp_dest_port, eth_src=source_mac_address, eth_dst=destionation_mac_address)
        elif ip_proto == 'udp':
            if source_ip_address != None:
                match = parser.OFMatch(ip_port = network_src_port_id, udp_src= udp_source_port, udp_dst=udp_dest_port, ipv4_src=source_ip_address, ipv4_dst=destination_ip_address)
            elif source_ip_address != None:
                match = parser.OFMatch(ip_proto=network_src_port_id, udp_src= udp_source_port, udp_dst=udp_dest_port, eth_src=source_mac_address, eth_dst=destionation_mac_address)
        return match