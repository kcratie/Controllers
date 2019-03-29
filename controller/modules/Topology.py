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
import random
import threading
import time
from controller.framework.CFx import CFX
from controller.framework.ControllerModule import ControllerModule
from controller.modules.NetworkBuilder import NetworkBuilder
from controller.modules.NetworkBuilder import EdgeRequest
from controller.modules.NetworkBuilder import EdgeResponse
from controller.modules.NetworkBuilder import EdgeNegotiate
from controller.modules.GraphBuilder import GraphBuilder
from controller.framework.ipoplib import RemoteAction

class Topology(ControllerModule, CFX):
    def __init__(self, cfx_handle, module_config, module_name):
        super(Topology, self).__init__(cfx_handle, module_config, module_name)
        self._overlays = {}
        self._lock = threading.Lock()
        self._topo_changed_publisher = None

    def initialize(self):
        self._topo_changed_publisher = self._cfx_handle.publish_subscription("TOP_TOPOLOGY_CHANGE")
        self._cfx_handle.start_subscription("Signal", "SIG_PEER_PRESENCE_NOTIFY")
        self._cfx_handle.start_subscription("LinkManager", "LNK_TUNNEL_EVENTS")
        nid = self.node_id
        for olid in self._cfx_handle.query_param("Overlays"):
            MaxSuccessors = int(self.config["Overlays"][olid].get("MaxSuccessors", 1))
            MaxLongDistEdges = int(self.config["Overlays"][olid].get("MaxLongDistEdges", 2))
            thres = self.config["Overlays"][olid].get(
                "MaxConcurrentEdgeSetup", int(MaxSuccessors + MaxLongDistEdges))
            self._overlays[olid] = dict(NetBuilder=NetworkBuilder(self, olid, nid, thres),
                                        KnownPeers=[], NewPeerCount=0, Banlist=dict(),
                                        NegoConnEdges=dict(), OndPeers=[])
        try:
            # Subscribe for data request notifications from OverlayVisualizer
            self._cfx_handle.start_subscription("OverlayVisualizer",
                                                "VIS_DATA_REQ")
        except NameError as err:
            if "OverlayVisualizer" in str(err):
                self.register_cbt("Logger", "LOG_WARNING",
                                  "OverlayVisualizer module not loaded."
                                  " Visualization data will not be sent.")
        self.register_cbt("Logger", "LOG_INFO", "Module loaded")

    def terminate(self):
        pass

    def _do_topo_change_post(self, overlay_id):
        # create and post the dict of adjacent connection edges
        adjl = self._overlays[overlay_id]["NetBuilder"].get_adj_list()
        topo = {}
        for peer_id in adjl.conn_edges:
            if adjl.conn_edges[peer_id].edge_state == "CEStateConnected":
                topo[peer_id] = dict(adjl.conn_edges[peer_id]) # create a dict from CE
        update = {"OverlayId": overlay_id, "Topology": topo}
        self._topo_changed_publisher.post_update(update)

    def resp_handler_create_tnl(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        peer_id = params["PeerId"]
        if not cbt.response.status:
            self.register_cbt("Logger", "LOG_WARNING", "Failed to create topology edge to {0}. {1}"
                              .format(cbt.request.params["PeerId"], cbt.response.data))
            interval = self._cm_config["TimerInterval"]
            self._overlays[olid]["Banlist"][peer_id] = \
                {"RemovalTime": (random.randint(0, 5) * interval) + time.time()}
        self.free_cbt(cbt)

    def resp_handler_remove_tnl(self, cbt):
        if not cbt.response.status:
            self.register_cbt("Logger", "LOG_WARNING",
                              "Failed to remove topology edge {0}".format(cbt.response.data))
            params = cbt.request.params
            params["UpdateType"] = "RemoveEdgeFailed"
            params["TunnelId"] = None
            olid = params["OverlayId"]
            self._overlays[olid]["NetBuilder"].update_edge_state(params)
        self.free_cbt(cbt)

    def req_handler_peer_presence(self, cbt):
        """
        Handles peer presence notification. Determines when to build a new graph and refresh
        connections.
        """
        peer = cbt.request.params
        peer_id = peer["PeerId"]
        olid = peer["OverlayId"]
        with self._lock:
            if peer_id not in self._overlays[olid]["KnownPeers"]:
                self._overlays[olid]["KnownPeers"].append(peer_id)
                self._overlays[olid]["NewPeerCount"] += 1
                nb = self._overlays[olid]["NetBuilder"]
                if (nb.is_ready and self._overlays[olid]["NewPeerCount"]
                        >= self._cm_config["PeerDiscoveryCoalesce"]):
                    self.register_cbt("Logger", "LOG_DEBUG", "Coalesced {0} new peer discovery, "
                                      "initiating network refresh"
                                      .format(self._overlays[olid]["NewPeerCount"]))
                    enf_lnks = self._cm_config["Overlays"][olid].get("EnforcedLinks", {})
                    peer_list = [item for item in self._overlays[olid]["KnownPeers"] \
                        if item not in self._overlays[olid]["Banlist"]]
                    manual_topo = self._cm_config["Overlays"][olid].get("ManualTopology", False)
                    params = {"OverlayId": olid, "NodeId": self.node_id,
                              "Peers": peer_list,
                              "EnforcedEdges": enf_lnks,
                              "MaxSuccessors": self._cm_config["Overlays"][olid].get(
                                  "MaxSuccessors", 1),
                              "MaxLongDistEdges": self._cm_config["Overlays"][olid].get(
                                  "MaxLongDistEdges", 2),
                              "ManualTopology": manual_topo}
                    gb = GraphBuilder(params)
                    adjl = gb.build_adj_list(nb.get_adj_list(), self._overlays[olid]["OndPeers"])
                    nb.refresh(adjl)
                    self._overlays[olid]["NewPeerCount"] = 0
                else:
                    self.register_cbt("Logger", "LOG_DEBUG", "{0} new peers discovered, delaying "
                                      "refresh".format(self._overlays[olid]["NewPeerCount"]))
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_query_peer_ids(self, cbt):
        peer_ids = {}
        try:
            with self._lock:
                for olid in self._cm_config["Overlays"]:
                    peer_ids[olid] = set(self._overlays[olid]["KnownPeers"])
                cbt.set_response(data=peer_ids, status=True)
                self.complete_cbt(cbt)
        except KeyError:
            cbt.set_response(data=None, status=False)
            self.complete_cbt(cbt)
            self.register_cbt("Logger", "LOG_WARNING", "Overlay Id is not valid {0}".
                              format(cbt.response.data))

    def req_handler_vis_data(self, cbt):
        topo_data = {}
        try:
            with self._lock:
                edges = {}
                for olid in self._overlays:
                    nb = self._overlays[olid]["NetBuilder"]
                    if nb:
                        adjl = nb.get_adj_list()
                        for k in adjl.conn_edges:
                            ce = adjl.conn_edges[k]
                            ced = {"PeerId": ce.peer_id, "EdgeId": ce.edge_id,
                                   "MarkedForDeleted": ce.marked_for_delete,
                                   "CreatedTime": ce.created_time,
                                   "ConnectedTime": ce.connected_time,
                                   "State": ce.edge_state, "Type": ce.edge_type}
                            edges[ce.edge_id] = ced
                        topo_data[olid] = edges
            cbt.set_response({"Topology": topo_data}, bool(topo_data))
            self.complete_cbt(cbt)
        except KeyError:
            cbt.set_response(data=None, status=False)
            self.complete_cbt(cbt)
            self.register_cbt("Logger", "LOG_WARNING", "Topology data not available {0}".
                              format(cbt.response.data))

    def req_handler_tnl_data_update(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        peer_id = params["PeerId"]
        with self._lock:
            self._overlays[olid]["NetBuilder"].update_edge_state(params)
            if params["UpdateType"] == "REMOVED":
                self.top_log("Removing peer id from peer list {0}".format(peer_id))
                i = self._overlays[olid]["KnownPeers"].index(peer_id)
                self._overlays[olid]["KnownPeers"].pop(i)
                self._do_topo_change_post(olid)
            elif params["UpdateType"] == "CONNECTED":
                self._do_topo_change_post(olid)
            self._update_overlay(olid)
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def request_handler_tunnel_req(self, cbt):
        cbt.set_response("Accept", True)
        self.complete_cbt(cbt)

    def req_handler_req_ond_tunnel(self, cbt):
        """ params[0] - overlay_id, [1] - peer_id, [2] - ADD/REMOVE op string """
        olid = cbt.request.params[0]
        peer = (cbt.request.params[1], cbt.request.params[2])
        with self._lock:
            if olid in self._overlays and peer[0] in self._overlays[olid]["KnownPeers"]:
                self._overlays[olid]["OndPeers"].append(peer)
            else:
                self.register_cbt("Logger", "LOG_WARNING", "Invalid on demand tunnel request "
                                  "parameter, OverlayId={0}, PeerId={1}".format(olid, peer[0]))

    def req_handler_negotiate_edge(self, edge_cbt):
        """ Role B, decide if the request for an incoming edge is accepted or rejected """
        edge_req = EdgeRequest(**edge_cbt.request.params)
        olid = edge_req.overlay_id
        if olid not in self.config["Overlays"]:
            self.register_cbt("Logger", "LOG_WARNING", "The requested overlay is not specified in "
                              "local config, the edge request is discarded")
            edge_cbt.set_response("Unknown overlay id specified in edge request", False)
            self.complete_cbt(edge_cbt)
            return
        #edge_resp = self._overlays[olid]["NetBuilder"].on_negotiate_edge_req(edge_req)
        #edge_cbt.set_response(edge_resp.data, edge_resp.is_accepted)
        #self.complete_cbt(edge_cbt)
        edge_resp = self._overlays[olid]["NetBuilder"].negotiate_incoming_edge(edge_req)
        if edge_resp.is_accepted:
            peer_id = edge_req.initiator_id
            edge_id = edge_req.edge_id
            self._overlays[olid]["NegoConnEdges"][peer_id] = (edge_req, edge_resp)
            #self.register_cbt("Logger", "LOG_DEBUG", "NegoConnEdges={0}".format(self._overlays[olid]["NegoConnEdges"]))
            self._authorize_edge(olid, peer_id, edge_id, parent_cbt=edge_cbt)
        else:
            edge_cbt.set_response(edge_resp.data, False)
            self.complete_cbt(edge_cbt)

    def resp_handler_auth_tunnel(self, cbt):
        """ Role B
            LNK auth completed, add the CE to Netbuilder and send response to initiator ie., Role A
        """
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        if cbt.response.status:
            _, edge_resp = self._overlays[olid]["NegoConnEdges"].pop(peer_id)
            self._overlays[olid]["NetBuilder"].add_incoming_auth_conn_edge(peer_id)
        else:
            self._overlays[olid]["NegoConnEdges"].pop(peer_id)
            edge_resp = EdgeResponse("E4 - Tunnel service unavailable", False)
        nego_cbt = cbt.parent
        self.free_cbt(cbt)
        nego_cbt.set_response(edge_resp.data, edge_resp.is_accepted)
        self.complete_cbt(nego_cbt)

    def resp_handler_remote_action(self, cbt):
        """ Role Node A, initiate edge creation on successful neogtiation """
        rem_act = RemoteAction.from_cbt(cbt)
        olid = rem_act.overlay_id
        if olid not in self.config["Overlays"]:
            self.register_cbt("Logger", "LOG_WARNING", "The specified overlay is not in the"
                              "local config, the rem act response is discarded")
            self.free_cbt(cbt)
            return
        if rem_act.action == "TOP_NEGOTIATE_EDGE":
            edge_nego = rem_act.params
            edge_nego["is_accepted"] = rem_act.status
            edge_nego["data"] = rem_act.data
            edge_nego = EdgeNegotiate(**edge_nego)
            self._overlays[olid]["NetBuilder"].complete_edge_negotiation(edge_nego)
            self.free_cbt(cbt)
        else:
            self.register_cbt("Logger", "LOG_WARNING", "Unrecognized remote action {0}"
                              .format(rem_act.action))


    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "SIG_PEER_PRESENCE_NOTIFY":
                self.req_handler_peer_presence(cbt)
            elif cbt.request.action == "VIS_DATA_REQ":
                self.req_handler_vis_data(cbt)
            elif cbt.request.action == "TOP_QUERY_PEER_IDS":
                self.req_handler_query_peer_ids(cbt)
            elif cbt.request.action == "LNK_TUNNEL_EVENTS":
                self.req_handler_tnl_data_update(cbt)
            elif cbt.request.action == "TOP_INCOMING_TUNNEL_REQ":
                self.request_handler_tunnel_req(cbt)
            elif cbt.request.action == "TOP_REQUEST_OND_TUNNEL":
                self.req_handler_req_ond_tunnel(cbt)
            elif cbt.request.action == "TOP_NEGOTIATE_EDGE":
                self.req_handler_negotiate_edge(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            if cbt.request.action == "LNK_CREATE_TUNNEL":
                self.resp_handler_create_tnl(cbt)
            elif cbt.request.action == "LNK_REMOVE_TUNNEL":
                self.resp_handler_remove_tnl(cbt)
            elif cbt.request.action == "SIG_REMOTE_ACTION":
                self.resp_handler_remote_action(cbt)
            elif cbt.request.action == "LNK_AUTH_TUNNEL":
                self.resp_handler_auth_tunnel(cbt)
            else:
                parent_cbt = cbt.parent
                cbt_data = cbt.response.data
                cbt_status = cbt.response.status
                self.free_cbt(cbt)
                if (parent_cbt is not None and parent_cbt.child_count == 1):
                    parent_cbt.set_response(cbt_data, cbt_status)
                    self.complete_cbt(parent_cbt)

    def _cleanup_banlist(self):
        # Remove peers from the duration based banlist. Higher successive connection failures
        # results in potentially longer duration in the banlist.
        tmp = []
        for olid in self._overlays:
            for peer_id in self._overlays[olid]["Banlist"]:
                rt = self._overlays[olid]["Banlist"][peer_id]["RemovalTime"]
                if rt >= time.time():
                    tmp.append(peer_id)
            for peer_id in tmp:
                self._overlays[olid]["Banlist"].pop(peer_id, None)
                self.register_cbt("Logger", "LOG_INFO",
                                  "Node {0} removed from banlist".format(peer_id[:7]))

    def _update_overlay(self, olid):
        nb = self._overlays[olid]["NetBuilder"]
        if nb.is_ready:
            self.register_cbt("Logger", "LOG_DEBUG", "Refreshing topology...")
            enf_lnks = self._cm_config["Overlays"][olid].get("EnforcedLinks", {})
            manual_topo = self._cm_config["Overlays"][olid].get("ManualTopology", False)
            params = {"OverlayId": olid, "NodeId": self.node_id,
                      "Peers": self._overlays[olid]["KnownPeers"],
                      "EnforcedEdges": enf_lnks,
                      "MaxSuccessors": self._cm_config["Overlays"][olid].get("MaxSuccessors", 1),
                      "MaxLongDistEdges": self._cm_config["Overlays"][olid].get(
                          "MaxLongDistEdges", 2),
                      "ManualTopology": manual_topo}
            gb = GraphBuilder(params)
            adjl = gb.build_adj_list(nb.get_adj_list(), self._overlays[olid]["OndPeers"])
            nb.refresh(adjl)
            self._overlays[olid]["NewPeerCount"] = 0
        else:
            self.register_cbt("Logger", "LOG_DEBUG", "Net builder not yet ready, skipping...")

    def _authorize_edge(self, overlay_id, peer_id, edge_id, parent_cbt):
        self.register_cbt("Logger", "LOG_INFO", "Authorizing peer edge from {0}:{1}->{2}"
                          .format(overlay_id, peer_id[:7], self.node_id[:7]))
        params = {"OverlayId": overlay_id, "PeerId": peer_id, "TunnelId": edge_id}
        cbt = self.create_linked_cbt(parent_cbt)
        cbt.set_request(self.module_name, "LinkManager", "LNK_AUTH_TUNNEL", params)
        self.submit_cbt(cbt)


    def manage_topology(self):
        # Periodically refresh the topology, making sure desired links exist and exipred ones are
        # removed.
        self._cleanup_banlist()
        for olid in self._overlays:
            self.register_cbt("Logger", "LOG_INFO", "known_peers={}".format(self._overlays[olid]["KnownPeers"]))
            self._update_overlay(olid)

    def timer_method(self):
        with self._lock:
            self.manage_topology()

    def top_add_edge(self, overlay_id, peer_id, edge_id):
        """
        Instruct LinkManager to commence building a tunnel to the specified peer
        """
        self.register_cbt("Logger", "LOG_INFO", "Creating peer edge {0}:{1}->{2}"
                          .format(overlay_id, self.node_id[:7], peer_id[:7]))
        params = {"OverlayId": overlay_id, "PeerId": peer_id, "TunnelId": edge_id}
        self.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)

    def top_remove_edge(self, overlay_id, peer_id):
        self.register_cbt("Logger", "LOG_INFO", "Removing peer edge {0}:{1}->{2}"
                          .format(overlay_id, self.node_id[:7], peer_id[:7]))
        params = {"OverlayId": overlay_id, "PeerId": peer_id}
        self.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)

    def top_log(self, msg, level="LOG_DEBUG"):
        self.register_cbt("Logger", level, msg)

    def top_send_negotiate_edge_req(self, edge_req):
        """Role Node A, Send a request to create an edge to the peer """
        # overlay_id, peer_id, edge_type
        #edge_params = {"OverlayId": overlay_id, "EdgeType": edge_type, "UID": self.node_id}
        edge_params = edge_req._asdict()
        rem_act = RemoteAction(edge_req.overlay_id, recipient_id=edge_req.recipient_id,
                               recipient_cm="Topology", action="TOP_NEGOTIATE_EDGE",
                               params=edge_params)
        rem_act.submit_remote_act(self)
