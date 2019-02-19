# ipop-project
# Copyright 2016, University of Florida
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
try:
    import simplejson as json
except ImportError:
    import json
from operator import attrgetter
import socket
import time
import struct
import uuid
from controller.modules.NetworkGraph import ConnectionEdge
from controller.modules.NetworkGraph import ConnEdgeAdjacenctList
#from ryu.lib import addrconv
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
#from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu.topology import event #, switches
from ryu.topology.api import get_switch #, get_link

class netNode():
    SDNI_PORT = 5802
    def __init__(self, datapath, ryu_app):
        self.datapath = datapath
        self.addr = (datapath.address[0], netNode.SDNI_PORT)
        self.node_id = None
        self.adj_list = ConnEdgeAdjacenctList()
        self.leaf_prts = None
        self.switch = None
        self.links = dict() # maps port no to tuple (local_mac, peer_mac, peer_id)
        self.ryu = ryu_app
        self.update_node_id()
        self.mac_local_to_peer = {}

    def __repr__(self):
        return ("NodeId: %s NodeAddress: %s:%s DatapathId: 0x%016x \nAdjPeers: %s" %
                (self.node_id[:7], self.addr[0], self.addr[1], self.datapath.id, self.adj_list))

    def __str__(self):
        msg = str(self.__repr__())
        lnks = str()
        sw = "  " + str(self.switch) + "\n"
        for ln in self.links:
            lnks = lnks + "  " + str(ln) + "\n"
        msg = msg + str("\nSWITCH:\n%sLINKS:\n%s" % (sw, lnks))
        return msg

    def leaf_ports(self):
        self.leaf_prts = set([pt for pt in self.switch.ports]) - set([*self.links.keys()])
        self.ryu.logger.debug("LEAF PORTS: %s", str(self.leaf_prts))
        return self.leaf_prts

    def link_ports(self):
        return [*self.links.keys()]

    def update_node_id(self):
        req = dict(Request=dict(Action="GetNodeId", Params=None))
        resp = self._send_recv(self.addr, req)
        if resp and resp["Response"]["Status"]:
            self.node_id = resp["Response"]["Data"]["NodeId"]
        else:
            self.ryu.logger.warning("Get Node ID failed for {0}".format(self.datapath.id))

    def update_switch(self):
        self.switch = None
        sw = get_switch(self.ryu, self.datapath.id)
        if sw:
            self.switch = sw[0]

    def update_links(self):
        self.update_switch()
        self.update_ipop_topology()
        for prt in self.switch.ports:
            sw_prt_mac = str(prt.hw_addr).capitalize()
            peer = self.mac_local_to_peer.get(sw_prt_mac, None)
            if peer:
                self.links[prt.port_no] = (sw_prt_mac, peer[0], peer[1])
        self.ryu.logger.info("UPDATED_LINKS %s", self.links)

    def update_ipop_topology(self):
        req = dict(Request=dict(Action="GetTunnels", Params=None))
        resp = self._send_recv(self.addr, req)
        if resp and resp["Response"]["Status"]:
            olid = list(resp["Response"]["Data"].keys())[0]
            topo = resp["Response"]["Data"][olid]
            self.ryu.logger.debug("NodeId: %s Topo: %s", self.node_id[:7],
                                  json.dumps(topo))
            self.adj_list.overlay_id = olid
            self.adj_list.node_id = self.node_id
            for peer_id in topo:
                ce = ConnectionEdge.from_json_str(json.dumps(topo[peer_id]))
                self.adj_list.add_connection_edge(ce)
                local = topo[peer_id]["MAC"]
                peer_mac = topo["PeerMac"]
                self.mac_local_to_peer[local] = (peer_mac, peer_id)
            self.ryu.logger.debug("mac_local_to_peer %s", self.mac_local_to_peer)
        else:
            self.ryu.logger.warning("Get Adjacent Peers failed for node:%s dpid:%s",
                                    self.node_id, self.datapath.id)

    def _send_recv(self, host_addr, send_data):
        recv_data = None
        sd = json.dumps(send_data)
        attempts = 0
        while attempts < 2 :
            try:
                attempts += 1
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(host_addr)
                sock.sendall(bytes(sd + "\n", "utf-8"))
                received = str(sock.recv(4096), "utf-8")
                if received:
                    recv_data = json.loads(received)
                    attempts = 2
            except ConnectionRefusedError as err:
                self.ryu.logger.warning("Failed to do send recv: %s", str(err))
                if attempts < 2:
                    time.sleep(1)
            finally:
                sock.close()
        return recv_data

class RingRoute(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
    SDNI_PORT = 5802
    def __init__(self, *args, **kwargs):
        super(RingRoute, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.nodes = dict() # dict of ipop nodes indexed by datapath id
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.debug('OFPSwitchFeatures received: msg.datapath_id=0x%016x n_buffers=%d '
                          'n_tables=%d auxiliary_id=%d capabilities=0x%08x', msg.datapath_id,
                          msg.n_buffers, msg.n_tables, msg.auxiliary_id, msg.capabilities)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        #node = self.nodes.setdefault(datapath.id, netNode(datapath, self))
        #node.update_switch()
        #if ev.switch.ports:
        #    node.update_links()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if eth.ethertype == 0xc0c0:
            self.logger.debug("BoundedFlood pkt rcvd %s %s %s %s", datapath.id, eth.src, eth.dst,
                              in_port)
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            for out_port in self.nodes[datapath.id].leaf_ports():
                actions = [parser.OFPActionOutput(out_port)]
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
        elif self._is_brdcast_from_leaf(msg):
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            out_bounds = self._build_out_bounds()
            if out_bounds:
                self._do_bounded_flood(datapath, in_port, out_bounds, src, msg.data)
        elif dst in self.mac_to_port[dpid]:
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'

        self.logger.debug('OFPPortStatus received: reason=%s desc=%s', reason, msg.desc)
        self.update_net_node(dp.id)

    ###################################################################################
    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        #node = self.nodes.get(ev.switch.dp.id, None)
        #if not node:
        #    node = netNode(ev.switch.dp, self)
        #node.switch = ev.switch
        #self.nodes[ev.switch.dp.id] = node
        #if ev.switch.ports:
        #    node.update_links()
        node = self.nodes.setdefault(ev.switch.dp.id, netNode(ev.switch.dp, self))
        node.switch = ev.switch
        if ev.switch.ports:
            node.update_links()

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info("SwitchLeave EV popping item: %s", str(ev))
        self.nodes.pop(dpid, None)

    #@set_ev_cls(event.EventPortAdd)
    #def port_add_handler(self, ev):
    #    dpid = ev.port.dpid
    #    self.logger.debug(ev)
    #    self._update_adjacent_peers(dpid)

    #@set_ev_cls(event.EventPortDelete)
    #def port_delete_handler(self, ev):
    #    dpid = ev.port.dpid
    #    self.logger.debug(ev)
    #    self._update_adjacent_peers(dpid)

    #@set_ev_cls(event.EventPortModify)
    #def port_modify_handler(self, ev):
    #    self.logger.debug(ev)

    #@set_ev_cls(event.EventLinkAdd)
    #def link_add_handler(self, ev):
    #    dpid = ev.link.src.dpid
    #    self.logger.debug(ev)
    #    self.nodes[dpid].update_links()

    #@set_ev_cls(event.EventLinkDelete)
    #def link_del_handler(self, ev):
    #    dpid = ev.link.src.dpid
    #    self.logger.debug(ev)
    #    self.nodes[dpid].update_links()

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

    @set_ev_cls(ofp_event.EventOFPRequestForward, MAIN_DISPATCHER)
    def request_forward_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.request.msg_type == ofp.OFPT_GROUP_MOD:
            self.logger.debug(
                '!OFPRequestForward received: request=OFPGroupMod('
                'command=%d, type=%d, group_id=%d, buckets=%s)',
                msg.request.command, msg.request.type,
                msg.request.group_id, msg.request.buckets)
        elif msg.request.msg_type == ofp.OFPT_METER_MOD:
            self.logger.debug(
                '!OFPRequestForward received: request=OFPMeterMod('
                'command=%d, flags=%d, meter_id=%d, bands=%s)',
                msg.request.command, msg.request.flags,
                msg.request.meter_id, msg.request.bands)
        else:
            self.logger.debug(
                'OFPRequestForward received: request=Unknown')

    ###################################################################################
    def update_net_node(self, datapath):
        dpid = datapath.id
        #node = self.nodes.get(dpid, None)
        #if not node:
        #    node = netNode(datapath, self)
        #node.update_links()
        #self.nodes[dpid] = node
        #self.logger.debug("update_net_node:%s\n", self.nodes[dpid])
        node = self.nodes.setdefault(dpid, netNode(datapath, self))
        node.update_links()
        self.logger.debug("update_net_node:%s\n", self.nodes[dpid])

        return node

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def not_forwarded(self, src_mac, dpid, port_no):
        lnk = self.nodes[dpid].links[port_no]
        if not lnk: return True
        peer_mac = lnk[1]
        return not str(src_mac).casefold() == peer_mac

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _monitor(self):
        while True:
            msg = str("========================================================\n")
            for dpid in self.nodes:
                msg += "{0}\nLeaf-Ports:{1}\n".format(self.nodes[dpid], self.nodes[dpid].leaf_ports())
                self._request_stats(self.nodes[dpid].datapath)
            if msg:
                self.logger.info(msg)
            hub.sleep(30)

    def _is_brdcast_from_leaf(self, msg):
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        in_port = msg.match['in_port']
        dp = msg.datapath

        node = self.nodes.get(dp.id, None)
        if not node:
            self.logger.info("refreshing net node %s", dp.id)
            node = self.update_net_node(dp)

        lfs = node.leaf_ports()
        return dst == "ff:ff:ff:ff:ff:ff" and in_port in lfs

    def _do_bounded_flood(self, datapath, in_port, tx_bounds, src_mac, payload):
        """
        datapath is the local switch datapath object.
        in_port is the ingress port number 
        tx_bounds is a list of tuples, each describing the outgoing port number and the
        corresponding bound UID associated with the transmission of 'payload' on that port.
        (out_port, bound_uid)

        This method uses the custom EtherType 0xc0c0, an assumes it will not be used on the network
        for any other purpose.
        The source MAC is set to the original frame src mac for convenience.
        """
        if not in_port or not tx_bounds or not payload:
            return

        eth = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                                src=src_mac,
                                ethertype=0xc0c0)
        for out_port, bound_uid in tx_bounds:
            bf = BoundedFlood.parser(bound_uid)
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf)
            p.add_protocol(payload)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=p.data)
            self.logger.info("Doing bounded flood packet %s %s", datapath.id, out_port)
            datapath.send_msg(out)


    def _build_out_bounds(self):
        out_bounds = []
        for dpid in self.nodes:
            node = self.nodes[dpid]
            nid = node.node_id
            succ_node = node.adj_list.filter("CETypeSuccessor", "CEStateConnected")
            if succ_node:
                for prtno in node.links:
                    if node.links[prtno][2] == succ_node:
                        out_bounds.append((prtno, nid))
                        break
        self.logger.info("OutBounds calculated as %s:", out_bounds)
        return out_bounds


    #def _build_out_bounds(self):
    #    out_bounds = []
    #    peer_ids = []
    #    my_idx = None
    #    for dpid in self.nodes:
    #        node = self.nodes[dpid]
    #        nid = node.node_id
    #        peer_ids.append(nid)
    #        for olid in node.adj_list:
    #            adjl = node.adj_list[olid]
    #            peer_ids.extend([*adjl.keys()])
    #            peer_ids.sort()
    #            my_idx = peer_ids.index(nid)
    #            succ_node = peer_ids.index((my_idx+1)%len(peer_ids))
    #            bound_node = [*adjl.keys()].sort()
    #            bound_node = bound_node[-1]
    #            #bound_node = peer_ids.index[(len(peer_ids)+1)//2]
    #            prt1 = adjl[olid][succ_node]
    #            prt2 = adjl[olid][bound_node]
    #            out_bounds.append((prt1, bound_node), (prt2, nid))
    #            break
    #    return out_bounds
###################################################################################################
class BoundedFlood(packet_base.PacketBase):
    """
    bound_uid is the ascii UUID representation of the upper exclusive node id bound that limits the
    extent of the retransmission.
    """
    _PACK_STR = '!16s'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    def __init__(self, bound_uid):
        super(BoundedFlood, self).__init__()
        self.bound_uid = bound_uid

    @classmethod
    def parser(cls, buf):
        (bound_uid, data) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(bound_uid), None, data

    def serialize(self, payload, prev):
        buid = uuid.UUID(self.bound_uid).bytes
        return struct.pack(BoundedFlood._PACK_STR, buid)
