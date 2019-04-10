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
from collections import namedtuple
try:
    import simplejson as json
except ImportError:
    import json
import socket
import time
import struct
import uuid
#from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.lib import mac as mac_lib
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
        self.topo = None
        self._leaf_prts = None
        self.switch = None
        self.links = {} # maps port no to tuple (local_mac, peer_mac, peer_id)
        self.mac_local_to_peer = {}
        self.counters = {}
        self.ryu = ryu_app
        self.logger = ryu_app.logger
        self.traffic_analyzer = TrafficAnalyzer(self.mac_local_to_peer, datapath.id)
        self.update_node_id()

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
            self.logger.info("Updated node id %s", self.node_id)
        else:
            self.logger.warning("Get Node ID failed for {0}".format(self.datapath.id))

    def query_port_no(self, node_id):
        for prtno in self.links:
            if self.links[prtno][2] == node_id:
                return prtno
        return None

    def peer_id(self, port_no):
        link_item = self.links.get(port_no, (None, None, None))
        return link_item[2]

    def update(self):
        if not self.node_id:
            self.update_node_id()
        self.logger.info("Updating node %s", self.node_id)
        self.update_switch()
        self.update_ipop_topology()
        self.update_links()
        self.update_leaf_ports()

    def update_switch(self):
        self.switch = None
        sw = get_switch(self.ryu, self.datapath.id)
        if sw:
            self.switch = sw[0]
        self.logger.info("Updated switch %s", self.switch)

    def update_ipop_topology(self):
        olid = CONFIG["OverlayId"]
        req = dict(Request=dict(Action="GetTunnels", Params={"OverlayId": olid}))
        resp = self._send_recv(self.addr, req)
        if resp and resp["Response"]["Status"]:
            topo = resp["Response"]["Data"].get(olid, None)
            if not topo:
                self.logger.info("No IPOP Topo data available as yet")
                return # nothing created in ipop as yet
            self.topo = ConnEdgeAdjacenctList(olid, self.node_id)
            self.mac_local_to_peer.clear()
            for peer_id in topo:
                ce = ConnectionEdge.from_json_str(json.dumps(topo[peer_id]))
                self.topo.add_connection_edge(ce)
                local = topo[peer_id]["MAC"]
                peer_mac = topo[peer_id]["PeerMac"]
                self.mac_local_to_peer[local] = (peer_mac, peer_id)
            self.logger.info("Updated mac_local_to_peer %s", self.mac_local_to_peer)
            self.logger.info("Updated ipop topo %s", self.topo)
        else:
            self.logger.warning("Failed for to update topo for node:%s dpid:%s",
                                self.node_id, self.datapath.id)

    def update_links(self):
        self.links.clear()
        for prt in self.switch.ports:
            peer = self.mac_local_to_peer.get(prt.hw_addr, None)
            if peer:
                self.links[prt.port_no] = (prt.hw_addr, peer[0], peer[1])
        self.logger.info("Updated links %s", self.links)

    def update_leaf_ports(self):
        self._leaf_prts = set([pt.port_no for pt in self.switch.ports]) - set([*self.links.keys()])
        self.logger.info("Updated leaf ports: %s", str(self._leaf_prts))

    def delete_port(self, ofpport):
        port_no = ofpport.port_no
        self.logger.info("Deleting port %d info", port_no)
        prt = switches.Port(self.datapath.id, self.datapath.ofproto, ofpport)
        self.switch.ports.remove(prt)
        td = self.links.get(port_no)
        if td and self.topo:
            self.topo.remove_connection_edge(td[2])
            self.mac_local_to_peer.pop(td[0], None)
        self.links.pop(port_no, None)
        self.update_leaf_ports()
        self.logger.info("NetNode=%s", self)

    def req_add_tunnel(self, peer_id):
        olid = CONFIG["OverlayId"]
        self.logger.info("Requesting ADD On Demand tunnel to peer %s", peer_id)
        req = dict(Request=dict(Action="TunnelRquest", Params=dict(OverlayId=olid,
                                                                   PeerId=peer_id,
                                                                   Operation="ADD")))
        resp = self._send_recv(self.addr, req)
        self.logger.info("Response={}".format(resp))

    def req_remove_tunnel(self, peer_id):
        olid = CONFIG["OverlayId"]
        self.logger.info("Requesting REMOVE On Demand tunnel to peer %s", peer_id)
        req = dict(Request=dict(Action="TunnelRquest", Params=dict(OverlayId=olid,
                                                                   PeerId=peer_id,
                                                                   Operation="Remove")))
        resp = self._send_recv(self.addr, req)
        self.logger.info("Response={}".format(resp))

    def ond_tunnel(self, flow_metrics, learning_table):
        tunnel_ops = self.traffic_analyzer.ond_recc(flow_metrics, learning_table)
        for op in tunnel_ops:
            if op[1] == "ADD":
                self.req_add_tunnel(op[0])
            elif op[1] == "REMOVE":
                self.req_remove_tunnel(op[0])

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
                self.logger.warning("Failed to do send recv: %s", str(err))
                if attempts < 2:
                    time.sleep(1)
            except json.errors.JSONDecodeError as err:
                self.logger.warning("JSON ERROR=%s, rcvd string=%s", str(err), received)
            finally:
                sock.close()
        return recv_data

###################################################################################################
###################################################################################################
class PeerSwitch():
    def __init__(self, rnid):
        self.rnid = rnid
        self.port_no = None
        self.leaf_macs = set()

    def __repr__(self):
        return "PeerSwitch<rnid={0}, port_no={1}, leaf_macs={2}>".\
            format(self.rnid[:7], self.port_no, self.leaf_macs)

class LearningTable():
    FlowDescriptor = namedtuple("FlowDescriptor", ["src", "dst", "ingress", "outgress", "revert"])
    def __init__(self, ryu):
        self._dpid = None
        self._nid = None            # local node id
        self.mac_to_port = {}       # the last observed ingress for the src mac
        self._leaf_ports = set()    # provided by net node
        self.rnid_tbl = {}          # maps nid peer switch to track each switch's leaf devices
        self.logger = ryu.logger
        self.mac_to_peersw = {}

    def __contains__(self, key_mac):
        return self.mac_to_port.__contains__(key_mac)

    def __repr__(self):
        state = "dpid={0}, nid={1}, mac_to_port={2}, leaf_ports={3}, rnid_tbl={4}"\
                .format(self._dpid, self._nid, self.mac_to_port, self.leaf_ports, self.rnid_tbl)
        return state

    def __str__(self):
        return str("LearningTable<{}>".format(self.__repr__()))

    def __getitem__(self, key_mac):
        psw = self.mac_to_peersw.get(key_mac)
        if psw and psw.port_no:
            return psw.port_no
        return self.mac_to_port.get(key_mac, None)

    def __setitem__(self, key_mac, value):
        if isinstance(value, tuple):
            self.learn(src_mac=key_mac, in_port=value[0], rnid=value[1])
        else:
            self.learn(key_mac, value)

    def __delitem__(self, key_mac):
        """ Remove the MAC address """
        self.mac_to_port.pop(key_mac, None)
        self.mac_to_peersw.pop(key_mac, None)

    @property
    def dpid(self):
        return self._dpid

    @dpid.setter
    def dpid(self, value):
        self._dpid = value

    @property
    def node_id(self):
        return self._nid

    @node_id.setter
    def node_id(self, nid):
        self._nid = nid
        self.rnid_tbl[nid] = PeerSwitch(nid)

    @property
    def local_leaf_macs(self):
        if not self._nid:
            return None
        return self.rnid_tbl[self._nid].leaf_macs

    @property
    def leaf_ports(self):
        return self._leaf_ports

    @leaf_ports.setter
    def leaf_ports(self, ports_set):
        self._leaf_ports = ports_set

    def learn(self, src_mac, in_port, rnid=None):
        self.mac_to_port[src_mac] = in_port
        if in_port in self.leaf_ports:
            self.rnid_tbl[self._nid].leaf_macs.add(src_mac)
        elif rnid:
            if rnid not in self.rnid_tbl:
                # not an adjacent peer switch
                self.rnid_tbl[rnid] = PeerSwitch(rnid)
            self.rnid_tbl[rnid].leaf_macs.add(src_mac)
            if self.rnid_tbl[rnid].port_no:
                self.mac_to_peersw[src_mac] = self.rnid_tbl[rnid]

    def leaf_to_peersw(self, leaf_mac):
        return self.mac_to_peersw.get(leaf_mac)

    def forget(self):
        """ Removes learning table entries associated with port no """
        self.mac_to_port.clear()

    def register_peer_switch(self, peer_id, in_port):
        """ Track the adjacent switch and the port no """
        if peer_id:
            if peer_id not in self.rnid_tbl:
                self.rnid_tbl[peer_id] = PeerSwitch(peer_id)
            self.rnid_tbl[peer_id].port_no = in_port

    def unregister_peer_switch(self, peer_id):
        """
        Clear port_no to indicate the tunnel is removed, ie., switch is no longer adjacent
        although it may be accessible via hops.
        """
        if peer_id and peer_id in self.rnid_tbl:
            self.rnid_tbl[peer_id].port_no = None

    def remote_leaf_macs(self, rnid):
        return self.rnid_tbl[rnid]

    def clear(self):
        self._dpid = None
        self._nid = None
        self.mac_to_port.clear()
        self.leaf_ports.clear()
        self.rnid_tbl.clear()

###################################################################################################
###################################################################################################
class RingRoute(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
    SDNI_PORT = 5802
    def __init__(self, *args, **kwargs):
        super(RingRoute, self).__init__(*args, **kwargs)
        self.monitor_thread = hub.spawn(self._monitor)
        ethernet.ethernet.register_packet_type(FloodRouteBound, FloodRouteBound.ETH_TYPE_BF)
        self.lt = LearningTable(self)   # The local nodes learning table
        self.nodes = dict()             # net node instance for datapath
        self.flooding_bounds = dict()   # flooding bounds isntance for datapath

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
        # deliver bounded flood frames to controller
        match = parser.OFPMatch(eth_type=FloodRouteBound.ETH_TYPE_BF)
        self.add_flow(datapath, match, actions, priority=100)
        # drop multicast frames
        self.add_flow_drop_multicast(datapath, None)
        self.lt.dpid = datapath.id

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        node = self.nodes.get(ev.switch.dp.id, None)
        if not node:
            node = netNode(ev.switch.dp, self)
        node.switch = ev.switch
        self.nodes[ev.switch.dp.id] = node
        if ev.switch.ports:
            node.update_ipop_topology()
            node.update_links()
            node.update_leaf_ports()
        self.lt.node_id = node.node_id

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info("Switch leave event, popping item: %s", str(ev))
        self.nodes.pop(dpid, None)
        self.lt.clear()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        port_no = msg.desc.port_no
        node = self.nodes[dp.id]

        if msg.reason == ofp.OFPPR_ADD:
            self.logger.info("OFPPortStatus: port ADDED desc=%s", msg.desc)
            self.update_net_node(dp)
            self.lt.leaf_ports = node.leaf_ports()
            self.lt.register_peer_switch(node.peer_id(port_no), port_no)
            self.do_bf_leaf_transfer(dp, msg.desc.port_no)
            #self.create_direct_path_flows(dp, msg.desc)
        elif msg.reason == ofp.OFPPR_DELETE:
            self.logger.info("OFPPortStatus: port DELETED desc=%s", msg.desc)
            self.del_flows_port(dp, port_no, tblid=0)
            self.lt.unregister_peer_switch(node.peer_id(port_no))
            self.net_node_del_port(dp, msg.desc)
            self.lt.leaf_ports = node.leaf_ports()
            self.lt.forget()
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

        if eth.ethertype == 0xc0c0:
            self.logger.info("BoundedFlood pkt rcvd %s %s %s %s",
                             datapath.id, eth.src, eth.dst, in_port)
            self.handle_bounded_flood_msg(datapath, pkt, in_port, msg)
        elif dst in self.lt:
            self.logger.info("packet in HIT %s %s %s %s", dpid, src, dst, in_port)
            # learn a mac address
            self.lt[src] = in_port
            out_port = self.lt[dst]
            # create new flow rule
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, match, actions, priority=1, tblid=0)
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        else:
            # this dst mac is not in our LT
            self.logger.info("default packet in %s %s %s %s", dpid, src, dst, in_port)
            self.lt[src] = in_port
            #perform bounded flood same as leaf case
            fld = self.flooding_bounds.get(dpid, None)
            if not fld:
                fld = FloodingBounds(self.nodes[dpid])
                self.flooding_bounds[dpid] = fld
            out_bounds = fld.bounds(None, [in_port])
            self.logger.info("flooding bounds calculated=%s:", out_bounds)
            if out_bounds:
                self.do_bounded_flood(datapath, in_port, out_bounds, src, msg.data)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                            'duration_sec=%d duration_nsec=%d '
                            'priority=%d '
                            'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                            'importance=%d cookie=%d packet_count=%d '
                            'byte_count=%d match=%s instructions=%s' %
                            (stat.table_id,
                            stat.duration_sec, stat.duration_nsec,
                            stat.priority,
                            stat.idle_timeout, stat.hard_timeout,
                            stat.flags, stat.importance,
                            stat.cookie, stat.packet_count, stat.byte_count,
                            stat.match, stat.instructions))
        self.logger.info('FlowStats: %s', flows)
        self.nodes[ev.msg.datapath.id].ond_tunnel(ev.msg.body, self.lt)

    ###################################################################################
    def _monitor(self):
        while True:
            #msg = str(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
            for dpid in self.nodes:
                self.request_stats(self.nodes[dpid].datapath)
            #    msg += "{0}\n".format(self.nodes[dpid])
            #    msg += "{0}\n".format(str(self.lt))
            #    msg += "Max Flooding Hop Count {0}\n".\
            #        format(self.nodes[dpid].counters.get("MaxFloodingHopCount", 1))
            #msg += str("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
            #self.logger.info(msg)
            hub.sleep(30)

    def request_stats(self, datapath, tblid=0):
        self.logger.info('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, table_id=tblid)
        datapath.send_msg(req)

    def add_flow(self, datapath, match, actions, priority=0, tblid=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, table_id=tblid)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.info("Add flow failed match=%s, action=%s", match, actions)

    def add_flow_drop_multicast(self, datapath, in_port, priority=1, tblid=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_dst=("33:33:00:00:00:00", "ff:ff:00:00:00:00"))
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_ADD, instructions=inst, table_id=tblid)
        resp = datapath.send_msg(mod)
        match = parser.OFPMatch(eth_dst=("01:00:5e:00:00:00", "ff:ff:ff:ff:ff:00"))
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_ADD, instructions=inst, table_id=tblid)
        resp = datapath.send_msg(mod)

    def del_flows_port(self, datapath, port_no, tblid=None):
        self.logger.info("Deleting all flows on outgress %s", port_no)
        ofproto = datapath.ofproto
        if tblid is None:
            tblid = ofproto.OFPTT_ALL
        parser = datapath.ofproto_parser
        cmd = ofproto.OFPFC_DELETE
        match = parser.OFPMatch()  #wildcard
        mod = parser.OFPFlowMod(datapath=datapath, cookie=0, cookie_mask=0,
                                table_id=tblid, flags=ofproto.OFPFF_SEND_FLOW_REM,
                                match=match, command=cmd, out_port=port_no)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.info("Failed to delete flow on outgress %s", port_no)
        match = parser.OFPMatch(in_port=port_no)
        mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                match=match, command=cmd)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.info("Failed to delete flow on outgress %s", port_no)


    def update_flow_match_dstmac(self, datapath, dst_mac, new_egress, tblid=None):
        self.logger.info("Updating all flows matching dst mac %s", dst_mac)
        if tblid is None:
            tblid = datapath.ofproto.OFPTT_ALL
        cmd = datapath.ofproto.OFPFC_MODIFY
        acts = [datapath.ofproto_parser.OFPActionOutput(new_egress, 1500)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, acts)]
        mt = datapath.ofproto_parser.OFPMatch(eth_dst=dst_mac)
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=tblid,
                                                 match=mt, command=cmd, instructions=inst)
        datapath.send_msg(mod)

    ###############################################################################################

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
        node = self.nodes[dpid]
        #node = self.nodes.get(dpid, None)
        #if not node:
        #    node = netNode(datapath, self)
        node.delete_port(ofpport)

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

    def do_bounded_flood(self, datapath, ingress, tx_bounds, src_mac, payload):
        """
        datapath is the local switch datapath object.
        ingress is the recv port number of the brdcast
        tx_bounds is a list of tuples, each describing the outgoing port number and the
        corresponding FRB associated with the transmission of 'payload' on that port.
        (out_port, frb)

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
                                ethertype=FloodRouteBound.ETH_TYPE_BF)
        for out_port, bf in tx_bounds:
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
            #self.logger.info("Doing bounded flood packet %s %s", datapath.id, out_port)
            datapath.send_msg(out)

    def do_bf_leaf_transfer(self, datapath, tunnel_port_no):
        node = self.nodes[datapath.id]
        tun_item = node.links.get(tunnel_port_no)
        if not tun_item:
            return
        peer_id = tun_item[2]
        peer_mac = tun_item[1]
        src_mac = tun_item[0]

        if not self.lt.local_leaf_macs:
            return
        payload = bytearray(6*len(self.lt.local_leaf_macs))
        offset = 0
        for leaf_mac in self.lt.local_leaf_macs:
            bmac = mac_lib.haddr_to_bin(leaf_mac)
            struct.pack_into("!6s", payload, offset, bmac)
            offset += 6

        nid = node.node_id
        bf_hdr = FloodRouteBound(nid, nid, 0, FloodRouteBound.FRB_LEAF_TX, offset//6)

        eth = ethernet.ethernet(dst=peer_mac,
                                src=src_mac,
                                ethertype=FloodRouteBound.ETH_TYPE_BF)
        p = packet.Packet()
        p.add_protocol(eth)
        p.add_protocol(bf_hdr)
        p.add_protocol(payload)
        p.serialize()
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        acts = [parser.OFPActionOutput(tunnel_port_no)]
        pkt_out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      actions=acts, data=p.data, in_port=ofproto.OFPP_LOCAL)
        datapath.send_msg(pkt_out)
        self.logger.info("Doing BF Leaf Tx packet %s %s %s %s %s", datapath.id, peer_id, peer_mac,
                         tunnel_port_no, payload)

    def handle_bounded_flood_msg(self, datapath, pkt, in_port, msg):
        eth = pkt.protocols[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        parser = datapath.ofproto_parser
        rcvd_frb = pkt.protocols[1]
        self.logger.info("rcvd_frb=%s", rcvd_frb)
        if len(pkt.protocols) < 2:
            return
        payload = pkt.protocols[2]
        #learn src mac and rnid
        self.lt[src] = (in_port, rcvd_frb.root_nid)
        if rcvd_frb.hop_count == 0:
            self.update_leaf_macs_and_flows(datapath, rcvd_frb.root_nid, payload,
                                            rcvd_frb.pl_count, in_port)
        else:
            if rcvd_frb.hop_count > self.nodes[dpid].counters.get("MaxFloodingHopCount", 1):
                self.nodes[dpid].counters["MaxFloodingHopCount"] = rcvd_frb.hop_count
            # deliver the broadcast frame to leaf devices
            self.logger.info("delivering BF payload on leaf ports=%s", self.nodes[datapath.id].leaf_ports())
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
            out_bounds = fld.bounds(rcvd_frb, [in_port])
            self.logger.info("flooding bounds calculated=%s:", out_bounds)
            if out_bounds:
                self.do_bounded_flood(datapath, in_port, out_bounds, src, payload)

    def update_leaf_macs_and_flows(self, datapath, rnid, macs, num_items, ingress):
        self.lt.rnid_tbl[rnid].leaf_macs.clear()
        mlen = num_items*6
        for mactup in struct.iter_unpack("!6s", macs[:mlen]):
            macstr = mac_lib.haddr_to_str(mactup[0])
            self.lt.rnid_tbl[rnid].add(macstr)
            self.logger.info("Added leaf mac %s to rnid %s", macstr, rnid)
        for mac in self.lt.remote_leaf_macs(rnid):
            self.update_flow_match_dstmac(datapath, mac, ingress, tblid=0)

    #def create_direct_path_flows(self, datapath, new_ofpport):
    #    peer_id = self.nodes[datapath.id].peer_id(new_ofpport.port_no)
    #    if not peer_id: return
    #    macs = self.lt.remote_leaf_macs(peer_id)
    #    for dst_mac in macs:
    #        self.update_flow_match_dstmac(datapath, dst_mac, new_ofpport.port_no, table_id=1)

###################################################################################################
###################################################################################################
class FloodRouteBound(packet_base.PacketBase):
    """
    Flooding Route and Bound is an custom ethernet layer protocol used by IPOP SDN switching to
    perform link layer broadcasts in cyclic switched fabrics.
    bound_nid is the ascii UUID representation of the upper exclusive node id bound that limits the
    extent of the retransmission.
    hop_count is the number of switching hops to the destination, the initial switch sets this
    value to zero
    root_nid is the node id of the switch that initiated the bounded flood operation
    """
    _PACK_STR = '!16s16sBBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    ETH_TYPE_BF = 0xc0c0
    FRB_BRDCST = 0
    FRB_LEAF_TX = 1
    #_TYPE = {
    #    "ascii": [
    #        "root_nid",
    #        "bound_nid",
    #        "hop_count"
    #    ]
    #}

    def __init__(self, root_nid, bound_nid, hop_count, frb_type=0, pl_count=0):
        super(FloodRouteBound, self).__init__()
        self.root_nid = root_nid
        self.bound_nid = bound_nid
        self.hop_count = hop_count
        self.frb_type = frb_type
        self.pl_count = pl_count
        assert self.hop_count < (1<<16), "hop_count exceeds max val"
        assert self.frb_type < (1<<16), "frb_type exceeds max val"
        assert self.pl_count < (1<<16), "pl_count exceeds max val"

    def __repr__(self):
        return str("frb<root_nid={0}, bound_nid={1}, hop_count={2}>"
                   .format(self.root_nid, self.bound_nid, self.hop_count))
    @classmethod
    def parser(cls, buf):
        unpk_data = struct.unpack(cls._PACK_STR, buf[:cls._MIN_LEN])
        rid = uuid.UUID(bytes=unpk_data[0])
        bid = uuid.UUID(bytes=unpk_data[1])
        hops = unpk_data[2]
        ty = unpk_data[3]
        cnt = unpk_data[4]
        #rid = uuid.UUID(bytes=buf[:16])
        #bid = uuid.UUID(bytes=buf[16:32])
        #hops = int.from_bytes(buf[32:33], byteorder=sys.byteorder)
        return cls(rid.hex, bid.hex, hops, ty, cnt), None, buf[cls._MIN_LEN:]

    def serialize(self, payload, prev):
        rid = uuid.UUID(hex=self.root_nid).bytes
        bid = uuid.UUID(hex=self.bound_nid).bytes
        if self.hop_count == 0:
            self.frb_type = FloodRouteBound.FRB_LEAF_TX
        if self.frb_type == FloodRouteBound.FRB_LEAF_TX:
            self.pl_count = len(payload) // 6
        return struct.pack(FloodRouteBound._PACK_STR, rid, bid, self.hop_count, self.frb_type,
                           self.pl_count)

###################################################################################################
###################################################################################################
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
                return FloodRouteBound(root_nid, bound_nid, hops)
            else:
                bound_nid = peer2
                return FloodRouteBound(root_nid, bound_nid, hops)
        elif (bound_nid > self._net_node.node_id) and (peer1 >= bound_nid):
            return None # the peer being considered is beyond the bound
        elif not peer2:
            bound_nid = prev_frb.bound_nid # alread set in default, handling no peer2
        elif peer2 < bound_nid:
            # the bound NID is the lesser of the bounds, ie., the bound_nid in the received frb,
            # or the NID of the next adjacent peer.
            bound_nid = peer2
        return FloodRouteBound(root_nid, bound_nid, hops)

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
        return FloodRouteBound(root_nid, bound_nid, hops)

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
        return FloodRouteBound(root_nid, bound_nid, hops)


    def bounds(self, prev_frb=None, exclude_ports=None):
        """
        Creates a list of out_bound tuples, in the format (outgress, frb).
        """
        if not exclude_ports:
            exclude_ports = []
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
                if prtno and prtno not in exclude_ports:
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
            if prtno and prtno not in exclude_ports:
                out_bounds.append((prtno, frb_hdr))
        return out_bounds

    def _build_scc_out_bounds(self, prev):
        out_bounds = []
        root_nid = self._net_node.node_id
        bound_nid = self._net_node.node_id
        hops = 1
        if prev:
            root_nid = prev.root_nid
            bound_nid = prev.bound_nid
            hops = prev.hop_count + 1

        succ_nodes = self._net_node.topo.filter([("CETypeSuccessor", "CEStateConnected")])
        if succ_nodes:
            succ_id_list = sorted([*succ_nodes.keys()])
            first_succ_id = succ_id_list[0]

            if bound_nid == first_succ_id:
                return out_bounds

            for prtno in self._net_node.links:
                if self._net_node.links[prtno][2] == first_succ_id:
                    out_bounds.append((prtno, FloodRouteBound(root_nid, bound_nid, hops)))
                    break

        return out_bounds

    def succ_bounds(self, prev_frb=None):
        """
        returns a list of tuples (outgress, frb_proto)
        """
        return self._build_scc_out_bounds(prev_frb)

###################################################################################################
###################################################################################################
class TrafficAnalyzer():
    """ A very simple traffic analyzer to trigger an on demand tunnel """
    _DEMAND_THRESHOLD = (1<<20)
    def __init__(self, mac_to_peer_id, dpid, demand_threshold=None):
        self._mac_to_peer_id = mac_to_peer_id
        self._dpid = dpid
        self.demand_threshold = demand_threshold if demand_threshold else \
            TrafficAnalyzer._DEMAND_THRESHOLD
        self.ond = set()

    def ond_recc(self, flow_metrics, learning_table):
        tunnel_reqs = []
        for stat in flow_metrics:
            if "eth_src" not in stat.match:
                continue
            src_mac = stat.match["eth_src"]
            psw = learning_table.leaf_to_peersw(src_mac)
            if not psw:
                continue
            assert bool(psw.rnid)
            if stat.byte_count > self.demand_threshold and psw.rnid not in self.ond:
                tunnel_reqs.append((psw.rnid, "ADD"))
                self.ond.add(psw.rnid)
            elif stat.byte_count < self.demand_threshold and psw.rnid in self.ond:
                tunnel_reqs.append((psw.rnid, "REMOVE"))
                self.ond.discard(psw.rnid)
        return tunnel_reqs
