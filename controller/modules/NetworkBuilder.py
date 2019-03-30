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

import threading
from copy import deepcopy
from collections import namedtuple
from controller.modules.NetworkGraph import ConnectionEdge
from controller.modules.NetworkGraph import ConnEdgeAdjacenctList
import controller.modules.NetworkGraph as ng

EdgeRequest = namedtuple("EdgeRequest",
                         ["overlay_id", "edge_id", "edge_type", "initiator_id", "recipient_id"])
EdgeResponse = namedtuple("EdgeResponse", ["is_accepted", "data"])
EdgeNegotiate = namedtuple("EdgeNegotiate", EdgeRequest._fields + EdgeResponse._fields)

class NetworkBuilder():
    """description of class"""
    def __init__(self, top_man, overlay_id, node_id, max_concurrent_edge_setup):
        self._current_adj_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._refresh_in_progress = 0
        self._pending_adj_list = None
        self._lock = threading.Lock()
        self._top = top_man
        self._max_concurrent_wrkload = max_concurrent_edge_setup
        self._negotiated_edges = {}

    @property
    def is_ready(self):
        """
        Is the NetworkBuilder ready for a new NetGraph? This means all the entries in the
        pending adj list has been cleared.
        """
        with self._lock:
            return self._is_ready()

    def _is_ready(self):
        return not bool(self._pending_adj_list)

    def _is_max_concurrent_workload(self):
        return self._refresh_in_progress >= self._max_concurrent_wrkload

    def get_adj_list(self):
        with self._lock:
            return deepcopy(self._current_adj_list)

    def refresh(self, net_graph):
        """
        Updates the networks connections. Invoked on different threads: 1) Periodically without
        parameters to last to last provided network graph, 2) attempt to refresh now or schedule
        the provide graph for refresh.
        """
        with self._lock:
            self._top.top_log("New net graph:{0}\nCurrent adj list:{1}"
                              .format(net_graph, self._current_adj_list))
            if self._pending_adj_list:
                self._top.top_log("Pending adj list:{0}"
                                  .format(self._pending_adj_list))
            # Nothing to do
            if not self._is_ready() or (self._is_ready() and not net_graph):
                self._top.top_log("Netbuilder nothing to do")
                return

            self._pending_adj_list = net_graph
            self._process_pending_adj_list()
            return

    def update_edge_state(self, connection_event):
        """
        Updates the connection edge's current state based on the provided event. The number of CEs
        not in the EdgeState CEStateConnected is used to limit the number of edges being
        constructed concurrently.
        """
        peer_id = connection_event["PeerId"]
        edge_id = connection_event["TunnelId"]
        overlay_id = connection_event["OverlayId"]
        with self._lock:
            if connection_event["UpdateType"] == "CREATING":
                conn_edge = self._current_adj_list.conn_edges.get(peer_id, None)
                if not conn_edge:
                    assert False, "CE={0} for incoming edge should have been pre negotiated!"\
                        .format(edge_id)
                    # this happens when the neighboring peer initiates the connection bootstrap
                    self._refresh_in_progress += 1
                    conn_edge = ConnectionEdge(peer_id, None, "CETypePredecessor")
                    self._current_adj_list.conn_edges[peer_id] = conn_edge
                conn_edge.edge_state = "CEStateCreated"
            elif connection_event["UpdateType"] == "REMOVED":
                self._current_adj_list.conn_edges.pop(peer_id, None)
                self._refresh_in_progress -= 1
            elif connection_event["UpdateType"] == "CONNECTED":
                self._current_adj_list.conn_edges[peer_id].edge_state = "CEStateConnected"
                self._current_adj_list.conn_edges[peer_id].connected_time = \
                    connection_event["ConnectedTimestamp"]
                self._refresh_in_progress -= 1
            elif connection_event["UpdateType"] == "DISCONNECTED":
                # the local topology did not request removal of the connection
                self._top.top_log("CEStateDisconnected event recvd peer_id: {0}, edge_id: {1}".
                                  format(peer_id, edge_id))
                self._current_adj_list.conn_edges[peer_id].edge_state = "CEStateDisconnected"
                self._refresh_in_progress += 1
                self._top.top_remove_edge(overlay_id, peer_id)
            elif connection_event["UpdateType"] == "RemoveEdgeFailed":
                # leave the node in the adj list and marked for removal to be retried.
                #self._current_adj_list.conn_edges.pop(peer_id, None)
                self._refresh_in_progress -= 1
            else:
                self._top.top_log("Invalid UpdateType specified for connection update",
                                  level="LOG_WARNING")
            assert self._refresh_in_progress >= 0, "refresh in progress is negative {}"\
                .format(self._refresh_in_progress)
            self._process_pending_adj_list()

    def _mark_edges_for_removal(self):
        """
        Anything edge the set (Active - Pending) is marked for deletion but do not remove
        negotiated edges.
        """
        for peer_id in self._current_adj_list:
            if not (self._current_adj_list[peer_id].edge_type in ng.EdgeTypes2 or peer_id in
                    self._pending_adj_list):
                self._current_adj_list.conn_edges[peer_id].marked_for_delete = True

    def _remove_edges(self):
        """
        Minimize churn by removing a single connection per refresh. Only initiate removal of an
        edge if it is not the first successor.
        """
        overlay_id = self._current_adj_list.overlay_id
        if len(self._current_adj_list) < self._current_adj_list.edge_threshold:
            return # don't start deleting links until at the threshold
        for peer_id in self._current_adj_list:
            if self._current_adj_list.conn_edges[peer_id].marked_for_delete:
                if (self._current_adj_list.successor_ce and peer_id !=
                        self._current_adj_list.successor_ce.peer_id):
                    self._refresh_in_progress += 1
                    self._top.top_remove_edge(overlay_id, peer_id)
                    return

    def _create_new_edges(self):
        """ Any edge in set (Pending - Active) is created and added to Active """
        #overlay_id = self._current_adj_list.overlay_id
        rmv_list = []
        for peer_id in self._pending_adj_list:
            if self._pending_adj_list[peer_id].edge_type in ng.EdgeTypes2:
                # negotiated edge in the pending list will be discarded
                rmv_list.append(peer_id)
                continue
            if self._is_max_concurrent_workload():
                break
            rmv_list.append(peer_id)
            if peer_id not in self._current_adj_list.conn_edges:
                if peer_id in self._negotiated_edges:
                    continue
                self._current_adj_list.conn_edges[peer_id] = \
                    self._pending_adj_list.conn_edges[peer_id]
                assert self._current_adj_list.conn_edges[peer_id].edge_state == "CEStateUnknown"
                self._refresh_in_progress += 1
                self._negotiate_new_edge(self._pending_adj_list.conn_edges[peer_id].edge_id,
                                         self._pending_adj_list.conn_edges[peer_id].edge_type,
                                         peer_id)

        for peer_id in rmv_list:
            del self._pending_adj_list[peer_id]

    def _process_pending_adj_list(self):
        """
        Sync the network state by determining the difference between the active and pending net
        graphs. Create new successors edges before removing existing ones.
        """
        if self._current_adj_list.overlay_id != self._pending_adj_list.overlay_id:
            raise ValueError("Overlay ID mismatch adj lists, active:{0}, pending:{1}".
                             format(self._current_adj_list.overlay_id,
                                    self._pending_adj_list.overlay_id))

        self._mark_edges_for_removal()
        if not self._is_max_concurrent_workload():
            self._create_new_edges()
            # edges in both pending and current are left as is, no updates
            self._remove_edges()
        else:
            self._top.top_log("Netbuilder busy")

    def _negotiate_new_edge(self, edge_id, edge_type, peer_id):
        """ Role A1 """
        olid = self._current_adj_list.overlay_id
        nid = self._current_adj_list.node_id
        er = EdgeRequest(overlay_id=olid, edge_id=edge_id, edge_type=edge_type,
                         recipient_id=peer_id, initiator_id=nid)
        self._top.top_send_negotiate_edge_req(er)

    def _resolve_request_collision(self, edge_req):
        nid = self._current_adj_list.node_id
        peer_id = edge_req.initiator_id
        edge_state = self._current_adj_list.conn_edges[peer_id].edge_state
        edge_resp = None
        if edge_state == "CEStateConnected":
            msg = "E1 - A connected edge already exists. TunnelId={0}"\
                .format(self._current_adj_list[peer_id].edge_id)
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self._top.top_log(msg)
        elif edge_state == "CEStateUnknown" and nid < edge_req.initiator_id:
            msg = "E2 - Edge request collision, your request is superceeded by predecessor. "\
                        "TunnelId={0}".format(self._current_adj_list[peer_id].edge_id)
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self._top.top_log(msg)
        elif edge_state == "CEStateUnknown" and nid > edge_req.initiator_id:
            ce = self._current_adj_list.conn_edges[peer_id]
            ce.edge_edge_type = ng.transpose_edge_type(edge_req.edge_type)
            msg = "Edge collision override accepted. Tnl remap {0}->{1}"\
                .format(ce.edge_id, edge_req.edge_id)
            ce._edge_id = edge_req.edge_id
            edge_resp = EdgeResponse(is_accepted=True, data=msg)
            self._top.top_log(msg)

        return edge_resp

    def negotiate_incoming_edge(self, edge_req):
        """ Role B1 """
        self._top.top_log("Rcvd EdgeRequest={0}".format(edge_req))
        edge_resp = None
        peer_id = edge_req.initiator_id
        with self._lock:
            if peer_id in self._current_adj_list.conn_edges:
                edge_resp = self._resolve_request_collision(edge_req)

            elif len(self._current_adj_list) >= (2*self._current_adj_list.edge_threshold):
                edge_resp = EdgeResponse(is_accepted=False, data="E3 - Too many existing edges")

            elif (len(self._current_adj_list) < (2*self._current_adj_list.edge_threshold) and
                  edge_req.edge_type == "CETypeSuccessor"):
                edge_resp = EdgeResponse(is_accepted=True, data="Successor edge permitted")

            elif len(self._current_adj_list) < self._current_adj_list.edge_threshold:
                edge_resp = EdgeResponse(is_accepted=True, data="Any edge permitted")

            if edge_resp.is_accepted:
                et = ng.transpose_edge_type(edge_req.edge_type)
                ce = ConnectionEdge(peer_id=peer_id, edge_id=edge_req.edge_id, edge_type=et)
                self._negotiated_edges[peer_id] = ce
                return edge_resp
            return edge_resp

    def add_incoming_auth_conn_edge(self, peer_id):
        """ Role B2 """
        with self._lock:
            self._refresh_in_progress += 1
            ce = self._negotiated_edges.pop(peer_id)
            self._current_adj_list.add_connection_edge(ce)

    def complete_edge_negotiation(self, edge_nego):
        """ Role A2 """
        self._top.top_log("EdgeNegotiate={0}".format(edge_nego))
        if edge_nego.recipient_id not in self._current_adj_list:
            self._top.top_log("Peer Id from edge negotiation not in current adjacency list. "
                              " The transaction has been discarded.", "LOG_WARNING")
            return
        ce = self._current_adj_list[edge_nego.recipient_id]
        if ce.peer_id != edge_nego.recipient_id or ce.edge_id != edge_nego.edge_id:
            self._top.top_log("EdgeNego parameters does not match current adjacency list, "
                              "The transaction has been discarded.", "LOG_WARNING")
            return
        with self._lock:
            if edge_nego.is_accepted:
                self._top.top_add_edge(self._current_adj_list.overlay_id, ce.peer_id, ce.edge_id)
            else:
                if edge_nego.data[:2] != "E2":
                    del self._current_adj_list[ce.peer_id]
