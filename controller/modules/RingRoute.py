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
import socket
import time
import struct
import uuid
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch
from NetworkGraph import ConnectionEdge
from NetworkGraph import ConnEdgeAdjacenctList

CONFIG = {
    "OverlayId": "101000F",
    "LogFile": "/var/log/ipop-vpn/ring-route.log",
    "LogLevel": "INFO"
    }
class netNode():
    SDNI_PORT = 5802
    def __init__(self, datapath, ryu_app):
        self.datapath = datapath
        self.addr = (datapath.address[0], netNode.SDNI_PORT)
        self.node_id = None
        self.topo = ConnEdgeAdjacenctList()
        self._leaf_prts = None
        self.switch = None
        self.links = dict() # maps port no to tuple (local_mac, peer_mac, peer_id)
        self.ryu = ryu_app
        self.update_node_id()
        self.mac_local_to_peer = {}

    def __repr__(self):
        return ("node_id=%s, node_address=%s:%s, datapath_id=0x%016x, switch=%s, topo=%s" %
                (self.node_id[:7], self.addr[0], self.addr[1], self.datapath.id, str(self.switch),
                 self.topo))

    def __str__(self):
        msg = ("netNode<{0}\nLink={1}, LeafPorts={2}>"
               .format(str(self.__repr__()), self.links, str(self.leaf_ports())))
        return msg

    def leaf_ports(self):
        return self._leaf_prts

    def link_ports(self):
        return [*self.links.keys()]

    def update_node_id(self):
        req = dict(Request=dict(Action="GetNodeId", Params=None))
        resp = self._send_recv(self.addr, req)
        if resp and resp["Response"]["Status"]:
            self.node_id = resp["Response"]["Data"]["NodeId"]
            self.ryu.logger.info("Updated node id %s", self.node_id)
        else:
            self.ryu.logger.warning("Get Node ID failed for {0}".format(self.datapath.id))

    def query_port_no(self, node_id):
        for prtno in self.links:
            if self.links[prtno][2] == node_id:
                return prtno
        return None

    def update(self):
        self.ryu.logger.info("Updating node %s", self.node_id)
        self.update_switch()
        self.update_ipop_topology()
        self.update_links()
        self.update_leaf_ports()

    def update_switch(self):
        self.switch = None
        sw = get_switch(self.ryu, self.datapath.id)
        if sw:
            self.switch = sw[0]
        self.ryu.logger.info("Updated switch %s", self.switch)

    def update_ipop_topology(self):
        req = dict(Request=dict(Action="GetTunnels", Params=None))
        resp = self._send_recv(self.addr, req)
        if resp and resp["Response"]["Status"]:
            #self.ryu.logger.info("Resp data: %s",resp["Response"]["Data"])
            olid = CONFIG["OverlayId"]
            topo = resp["Response"]["Data"].get(olid, None)
            if not topo:
                self.ryu.logger.info("No IPOP Topo data available as yet")
                return # nothing created in ipop as yet
            self.topo = ConnEdgeAdjacenctList(olid, self.node_id)
            self.mac_local_to_peer.clear()
            for peer_id in topo:
                ce = ConnectionEdge.from_json_str(json.dumps(topo[peer_id]))
                self.topo.add_connection_edge(ce)
                local = topo[peer_id]["MAC"]
                peer_mac = topo[peer_id]["PeerMac"]
                self.mac_local_to_peer[local] = (peer_mac, peer_id)
            self.ryu.logger.info("Updated mac_local_to_peer %s", self.mac_local_to_peer)
            self.ryu.logger.info("Updated ipop topo %s", self.topo)
        else:
            self.ryu.logger.warning("Failed for to update topo for node:%s dpid:%s",
                                    self.node_id, self.datapath.id)

    def update_links(self):
        self.links.clear()
        for prt in self.switch.ports:
            peer = self.mac_local_to_peer.get(prt.hw_addr, None)
            if peer:
                self.links[prt.port_no] = (prt.hw_addr, peer[0], peer[1])
        self.ryu.logger.info("Updated links %s", self.links)

    def update_leaf_ports(self):
        self._leaf_prts = set([pt.port_no for pt in self.switch.ports]) - set([*self.links.keys()])
        self.ryu.logger.info("Updated leaf ports: %s", str(self._leaf_prts))

    def delete_port(self, ofpport):
        port_no = ofpport.port_no
        self.ryu.logger.info("Deleting port %d info", port_no)
        prt = switches.Port(self.datapath.id, self.datapath.ofproto, ofpport)
        self.switch.ports.remove(prt)
        td = self.links.get(port_no)
        if td:
            self.topo.remove_connection_edge(td[2])
            self.mac_local_to_peer.pop(td[0], None)
        self.links.pop(port_no, None)
        self.update_leaf_ports()
        self.ryu.logger.info("NetNode=%s", self)

    def _send_recv(self, host_addr, send_data):
        recv_data = None
        sd = json.dumps(send_data)
        attempts = 0
        while attempts < 2:
            try:
                attempts += 1
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(host_addr)
                sock.sendall(bytes(sd + "\n", "utf-8"))
                received = str(sock.recv(4096), "utf-8")
                if received:
                    recv_data = json.loads(received)
                    break
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
        ethernet.ethernet.register_packet_type(frb, frb.ETH_TYPE_BF)
        self.flooding_bounds = dict()

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
        self.add_flow(datapath, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            self.logger.info("OFPPortStatus: port ADDED desc=%s", msg.desc)
            self.update_net_node(dp)
        elif msg.reason == ofp.OFPPR_DELETE:
            self.logger.info("OFPPortStatus: port DELETED desc=%s", msg.desc)
            self.del_flow_outgress(dp, msg.desc.port_no)
            self.net_node_del_port(dp, msg.desc)
            ##self.mac_to_port[dp.id] = {}
        elif msg.reason == ofp.OFPPR_MODIFY:
            self.logger.debug("OFPPortStatus: port MODIFIED desc=%s", msg.desc)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.protocols[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if self._is_brdcast_from_leaf(msg):
            self.logger.info("Brdcst from leaf rcvd")
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            #perform bounded flood
            fld = self.flooding_bounds.get(dpid, None)
            if not fld:
                fld = FloodingBounds(self.nodes[dpid])
                self.flooding_bounds[dpid] = fld
            out_bounds = fld.bounds()
            self.logger.info("flooding bounds calculated=%s:", out_bounds)
            if out_bounds:
                self._do_bounded_flood(datapath, in_port, out_bounds, src, msg.data)
        elif eth.ethertype == 0xc0c0:
            self.logger.info("BoundedFlood pkt rcvd %s %s %s %s", datapath.id, eth.src, eth.dst,
                             in_port)
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            proto_bf = pkt.protocols[1]
            payload = pkt.protocols[2]
            self.logger.info("proto_frb=%s", proto_bf)
            # deliver to leaf devices
            for out_port in self.nodes[datapath.id].leaf_ports():
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=payload)
                datapath.send_msg(out)
            # continue the bounded flood as necessary
            fld = self.flooding_bounds.get(dpid, None)
            if not fld:
                fld = FloodingBounds(self.nodes[dpid])
                self.flooding_bounds[dpid] = fld
            out_bounds = fld.bounds(proto_bf)
            self.logger.info("flooding bounds calculated=%s:", out_bounds)
            if out_bounds:
                self._do_bounded_flood(datapath, in_port, out_bounds, src, payload)
        elif dst in self.mac_to_port[dpid]:
            self.logger.info("packet in HIT %s %s %s %s", dpid, src, dst, in_port)
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            #match = parser.OFPMatch(eth_dst=dst)
            self.add_flow(datapath, match, actions, 1)
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        else:
            self.logger.info("default packet in %s %s %s %s", dpid, src, dst, in_port)
            self.mac_to_port[dpid][src] = in_port
    ###################################################################################
    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        node = self.nodes.get(ev.switch.dp.id, None)
        if not node:
            node = netNode(ev.switch.dp, self)
        node.switch = ev.switch
        self.nodes[ev.switch.dp.id] = node
        if ev.switch.ports:
            self.logger.info("Switch enter event but it already has ports!")
            node.update_ipop_topology()
            node.update_links()
            node.update_leaf_ports()

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info("Switch leave event, popping item: %s", str(ev))
        self.nodes.pop(dpid, None)

    #@set_ev_cls(event.EventPortAdd)
    #def port_add_handler(self, ev):
    #    dpid = ev.port.dpid
    #    self.logger.info(ev)
    #    self._update_adjacent_peers(dpid)

    #@set_ev_cls(event.EventPortDelete)
    #def port_delete_handler(self, ev):
    #    dpid = ev.port.dpid
    #    dp = self.nodes[dpid].datapath
    #    self.logger.info("EventPortDelete: event=%s", ev)
    #    self.del_flow_outgress(dp, ev.port.port_no)
    #    self.update_net_node(dp)

    #@set_ev_cls(event.EventPortModify)
    #def port_modify_handler(self, ev):
    #    self.logger.info(ev)

    #@set_ev_cls(event.EventLinkAdd)
    #def link_add_handler(self, ev):
    #    dpid = ev.link.src.dpid
    #    self.logger.info(ev)
    #    self.nodes[dpid].update_links()

    #@set_ev_cls(event.EventLinkDelete)
    #def link_del_handler(self, ev):
    #    dpid = ev.link.src.dpid
    #    self.logger.info(ev)
    #    self.nodes[dpid].update_links()

    #@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    #def _flow_stats_reply_handler(self, ev):
    #    body = ev.msg.body

    #    self.logger.info('datapath         '
    #                     'in-port  eth-dst           '
    #                     'out-port packets  bytes')
    #    self.logger.info('---------------- '
    #                     '-------- ----------------- '
    #                     '-------- -------- --------')
    #    for stat in sorted([flow for flow in body if flow.priority == 1],
    #                       key=lambda flow: (flow.match['in_port'],
    #                                         flow.match['eth_dst'])):
    #        self.logger.info('%016x %8x %17s %8x %8d %8d',
    #                         ev.msg.datapath.id,
    #                         stat.match['in_port'], stat.match['eth_dst'],
    #                         stat.instructions[0].actions[0].port,
    #                         stat.packet_count, stat.byte_count)

    #@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    #def _port_stats_reply_handler(self, ev):
    #    body = ev.msg.body

    #    self.logger.info('datapath         port     '
    #                     'rx-pkts  rx-bytes rx-error '
    #                     'tx-pkts  tx-bytes tx-error')
    #    self.logger.info('---------------- -------- '
    #                     '-------- -------- -------- '
    #                     '-------- -------- --------')
    #    for stat in sorted(body, key=attrgetter('port_no')):
    #        self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
    #                         ev.msg.datapath.id, stat.port_no,
    #                         stat.rx_packets, stat.rx_bytes, stat.rx_errors,
    #                         stat.tx_packets, stat.tx_bytes, stat.tx_errors)

    @set_ev_cls(ofp_event.EventOFPRequestForward, MAIN_DISPATCHER)
    def request_forward_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.request.msg_type == ofp.OFPT_GROUP_MOD:
            self.logger.info(
                '!OFPRequestForward received: request=OFPGroupMod('
                'command=%d, type=%d, group_id=%d, buckets=%s)',
                msg.request.command, msg.request.type,
                msg.request.group_id, msg.request.buckets)
        elif msg.request.msg_type == ofp.OFPT_METER_MOD:
            self.logger.info(
                '!OFPRequestForward received: request=OFPMeterMod('
                'command=%d, flags=%d, meter_id=%d, bands=%s)',
                msg.request.command, msg.request.flags,
                msg.request.meter_id, msg.request.bands)
        else:
            self.logger.info(
                'OFPRequestForward received: request=Unknown')

    ###################################################################################
    def update_net_node(self, datapath):
        dpid = datapath.id
        node = self.nodes.get(dpid, None)
        if not node:
            node = netNode(datapath, self)
        node.update()
        self.nodes[dpid] = node
        return node

    def net_node_del_port(self, datapath, ofpport):
        dpid = datapath.id
        node = self.nodes.get(dpid, None)
        if not node:
            node = netNode(datapath, self)
        node.delete_port(ofpport)

    def add_flow(self, datapath, match, actions, priority=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow_outgress(self, datapath, port_no):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cmd = ofproto.OFPFC_DELETE
        match = parser.OFPMatch()  #wildcard
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0, cookie_mask=0,
                                table_id=ofproto.OFPTT_ALL, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                match=match, command=cmd, out_port=port_no)
        self.logger.info("Deleting all flows on outgress %s", port_no)
        datapath.send_msg(mod)

    #def _request_stats(self, datapath):
    #    self.logger.info('send stats request: %016x', datapath.id)
    #    ofproto = datapath.ofproto
    #    parser = datapath.ofproto_parser

    #    req = parser.OFPFlowStatsRequest(datapath)
    #    datapath.send_msg(req)

    #    req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
    #    datapath.send_msg(req)

    def _monitor(self):
        while True:
            msg = str(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
            for dpid in self.nodes:
                msg += "{0}\n".format(self.nodes[dpid])
                #self._request_stats(self.nodes[dpid].datapath)
                msg += "Learning table{0}\n".format(str(self.mac_to_port))
            msg += str("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
            self.logger.info(msg)
            hub.sleep(60)

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

    def _do_bounded_flood(self, datapath, ingress, tx_bounds, src_mac, payload):
        """
        datapath is the local switch datapath object.
        ingress is the recv port number of the brdcast
        tx_bounds is a list of tuples, each describing the outgoing port number and the
        corresponding bound UID associated with the transmission of 'payload' on that port.
        (out_port, bound_nid)

        This method uses the custom EtherType 0xc0c0, an assumes it will not be used on the network
        for any other purpose.
        The source MAC is set to the original frame src mac for convenience.
        """
        if not ingress or not tx_bounds or not payload:
            self.logger.warning("Missing parameters to perform bounded flood ingress=%s, "
                                "tx_bounds=%s, payload=%s", ingress, tx_bounds, payload)
            return

        eth = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                                src=src_mac,
                                ethertype=frb.ETH_TYPE_BF)
        for out_port, bf in tx_bounds:
            #bf = frb(root_nid, bound_nid, hops)
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf)
            p.add_protocol(payload)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ingress, actions=actions, data=p.data)
            self.logger.info("Doing bounded flood packet %s %s", datapath.id, out_port)
            datapath.send_msg(out)

    #def _build_out_bounds(self):
    #    out_bounds = []
    #    peer_ids = []
    #    my_idx = None
    #    for dpid in self.nodes:
    #        node = self.nodes[dpid]
    #        nid = node.node_id
    #        peer_ids.append(nid)
    #        for olid in node.topo:
    #            adjl = node.topo[olid]
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
class frb(packet_base.PacketBase):
    """
    Flooding Route and Bound is an custom ethernet layer protocol used by IPOP SDN switching to
    perform link layer broadcasts in cyclic switched fabrics.
    bound_nid is the ascii UUID representation of the upper exclusive node id bound that limits the
    extent of the retransmission.
    hop_count is the number of switching hops to the destination, the initial switch sets this
    value to zero
    root_nid is the node id of the switch that initiated the bounded flood operation
    """
    _PACK_STR = '!16s16sB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    ETH_TYPE_BF = 0xc0c0
    #_TYPE = {
    #    "ascii": [
    #        "root_nid",
    #        "bound_nid",
    #        "hop_count"
    #    ]
    #}

    def __init__(self, root_nid, bound_nid, hop_count):
        super(frb, self).__init__()
        self.root_nid = root_nid
        self.bound_nid = bound_nid
        self.hop_count = hop_count

    def __repr__(self):
        return str("frb<root_nid={0}, bound_nid={1}, hop_count={2}>"
                   .format(self.root_nid, self.bound_nid, self.hop_count))
    @classmethod
    def parser(cls, buf):
        unpk_data = struct.unpack(cls._PACK_STR, buf[:cls._MIN_LEN])
        rid = uuid.UUID(bytes=unpk_data[0])
        bid = uuid.UUID(bytes=unpk_data[1])
        hops = unpk_data[2]
        #rid = uuid.UUID(bytes=buf[:16])
        #bid = uuid.UUID(bytes=buf[16:32])
        #hops = int.from_bytes(buf[32:33], byteorder=sys.byteorder)
        return cls(rid.hex, bid.hex, hops), None, buf[cls._MIN_LEN:]

    def serialize(self, payload, prev):
        rid = uuid.UUID(hex=self.root_nid).bytes
        bid = uuid.UUID(hex=self.bound_nid).bytes
        return struct.pack(frb._PACK_STR, rid, bid, self.hop_count)

class FloodingBounds():
    _MAX_NID = "ffffffffffffffffffffffffffffffff"
    def __init__(self, net_node):
        self._root_nid = None
        self._bound_nid = None
        self._hops = None
        self._net_node = net_node

    def _build_frb(self, peer1, peer2, prev_frb=None):
        """
        Create a FRB class for the broadbcast to peer1_idx. Assumes a list of adjacent nodes with
        lager NIDs, sorted in ascending order. The caller must handle wrap around of peers in the
        ring.
        peer1    - the peer in node list for which frb must be determined. NID must be greater than
                   self NID.
        peer2    - the next greater node immediately following peer1 in node list
        prev_frb - the FRB on the received Bounded Flood. If a broadcast was initiated by a leaf
                   node this value is None.
        """
        if (self._net_node.node_id >= peer1) or (peer2 and (peer1 >= peer2)):
            raise ValueError("invalid NID ordering self<%s>, peer1<%s>, peer2<%s>"%
                             self._net_node.node_id, peer1, peer2)
        if not prev_frb:
            return self._build_leaf_frb(peer2)
        root_nid = self._net_node.node_id
        hops = 1
        bound_nid = FloodingBounds._MAX_NID # if no prev_frb init to max value
        if prev_frb:
            root_nid = prev_frb.root_nid
            hops = prev_frb.hop_count + 1
            bound_nid = prev_frb.bound_nid # use the prev_frb bound_nid if it exists

        if (bound_nid < self._net_node.node_id) and (bound_nid < peer1):
            # the prev_frb contained a bound to a wrap aound nNID which is smaller than ours.
            if peer2 is None:
                return frb(root_nid, bound_nid, hops)
            else:
                bound_nid = peer2
                return frb(root_nid, bound_nid, hops)
        elif (bound_nid > self._net_node.node_id) and (peer1 >= bound_nid):
            return None # the peer being considered is beyond the bound
        elif not peer2:
            bound_nid = prev_frb.bound_nid # alread set in default, handling no peer2
        elif peer2 < bound_nid:
            # the bound NID is the lesser of the bounds, ie., the bound_nid in the received frb,
            # or the NID of the next adjacent peer.
            bound_nid = peer2
        return frb(root_nid, bound_nid, hops)

    def _build_leaf_frb(self, peer2):
        """
        Creates FRB in scenario where the brdcast originated from a leaf node and there is no
        prev_frb.
        """
        root_nid = self._net_node.node_id
        hops = 1
        bound_nid = FloodingBounds._MAX_NID # if no prev_frb init to max value
        if peer2 is None:
            bound_nid = self._net_node.node_id
        elif peer2 < bound_nid:
            bound_nid = peer2
        return frb(root_nid, bound_nid, hops)

    def _build_succ_frb(self, succ_nid, prev_frb):
        """
        Used when all adj peers have a lower nid, ie, both peer1 and peer 2 are None. In this case
        we expect wrap around to determine the successor as the node with the smallest NID.
        """
        root_nid = self._net_node.node_id
        hops = 1
        bound_nid = self._net_node.node_id # if no prev_frb init to max value
        if prev_frb:
            root_nid = prev_frb.root_nid
            hops = prev_frb.hop_count + 1
            bound_nid = prev_frb.bound_nid # use the prev_frb bound_nid if it exists
        if succ_nid == bound_nid:
            return None
        return frb(root_nid, bound_nid, hops)


    def bounds(self, prev_frb=None):
        """
        Creates a list of out_bound tuples, in the format (outgress, frb).
        """
        out_bounds = []
        node_list = []
        node_list = [*self._net_node.topo.conn_edges.keys()]
        node_list.append(self._net_node.node_id)
        node_list.sort()
        idx = node_list.index(self._net_node.node_id)
        num_peers = len(node_list)
        # prev_i = (idx + num_peers - 1) % num_peers # ring wraps around
        greater_peers = node_list[idx+1:]
        if not greater_peers:
            succ_i = (idx + 1) % num_peers
            nid = node_list[succ_i]
            frb_hdr = self._build_succ_frb(nid, prev_frb)
            if frb_hdr:
                prtno = self._net_node.query_port_no(nid)
                if prtno:
                    out_bounds.append((prtno, frb_hdr))
            return out_bounds

        for i, nid in enumerate(greater_peers):
            peer2 = None # default val when i is last node in list
            if i+1 <= len(greater_peers) - 1:
                peer2 = greater_peers[i+1]
            frb_hdr = self._build_frb(nid, peer2, prev_frb)
            if not frb_hdr:
                continue
            prtno = self._net_node.query_port_no(nid)
            if prtno:
                out_bounds.append((prtno, frb_hdr))
        return out_bounds

    #def _build_scc_out_bounds(self, prev):
    #    out_bounds = []
    #    root_nid = self._net_node.node_id
    #    bound_nid = self._net_node.node_id
    #    hops = 1
    #    if prev:
    #        root_nid = prev.root_nid
    #        bound_nid = prev.bound_nid
    #        hops = prev.hop_count + 1

    #    succ_nodes = self._net_node.topo.filter("CETypeSuccessor", "CEStateConnected")
    #    if succ_nodes:
    #        succ_id_list = sorted([*succ_nodes.keys()])
    #        first_succ_id = succ_id_list[0]

    #        if bound_nid == first_succ_id:
    #            return out_bounds

    #        for prtno in self._net_node.links:
    #            if self._net_node.links[prtno][2] == first_succ_id:
    #                out_bounds.append((prtno, frb(root_nid, bound_nid, hops)))
    #                break

    #    return out_bounds

    #def succ_bounds(self, prev_frb=None):
    #    """
    #    returns a list of tuples (outgress, frb_proto)
    #    """
    #    return self._build_scc_out_bounds(prev_frb)
