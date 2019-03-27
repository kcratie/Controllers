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
import uuid
from controller.modules.NetworkGraph import ConnectionEdge
from controller.modules.NetworkGraph import ConnEdgeAdjacenctList

EdgeRequest = namedtuple("EdgeRequest",
                         ["overlay_id", "edge_id", "edge_type", "initiator_id", "recipient_id"])
EdgeResponse = namedtuple("EdgeResponse", ["is_accepted", "data"])
EdgeNegotiate = namedtuple("EdgeNegotiate", EdgeRequest._fields + EdgeResponse._fields)

class NetworkBuilder():
    """description of class"""
    def __init__(self, top_man, overlay_id, node_id):
        self._current_adj_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._refresh_in_progress = 0
        self._pending_adj_list = None
        self._lock = threading.Lock()
        self._top = top_man

    def is_ready(self):
        with self._lock:
            if self._refresh_in_progress < 0:
                raise ValueError("A precondition violation occurred. The refresh reference count"
                                 " is negative {}".format(self._refresh_in_progress))
            return self._refresh_in_progress == 0

    def get_adj_list(self):
        with self._lock:
            return deepcopy(self._current_adj_list)

    def refresh(self, net_graph=None):
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
            """
            This conditon is expected to be met on the timer invocation when no net_graph is
            supplied but when there is _pending_edges waiting to be applied.
            """
            if self._refresh_in_progress == 0 and not net_graph and self._pending_adj_list:
                self._update_net_connections()
                return
            """
            Overwrite any previous pending_edges as we are only interested in the most recent one.
            """
            if net_graph:
                self._pending_adj_list = net_graph
            """
            To minimize network disruption wait until a previous sync operation is completed before
            starting a new one.
            """
            if self._refresh_in_progress > 0:
                return
            """
            Attempt to sync the network state to the pending net graph.
            """
            if self._pending_adj_list:
                self._update_net_connections()

    def on_connection_update(self, connection_event):
        """
        Updates the connection edge's current state based on the provided event. This is the
        completion for a create or remove connection request to Link Manager.
        """
        peer_id = connection_event["PeerId"]
        edge_id = connection_event["TunnelId"]
        overlay_id = connection_event["OverlayId"]
        with self._lock:
            if connection_event["UpdateType"] == "CREATING":
                conn_edge = self._current_adj_list.conn_edges.get(peer_id, None)
                if not conn_edge:
                    # this happens when the neighboring peer initiates the connection bootstrap
                    self._refresh_in_progress += 1
                    conn_edge = ConnectionEdge(peer_id, "CETypePredecessor")
                    self._current_adj_list.conn_edges[peer_id] = conn_edge
                conn_edge.edge_state = "CEStateCreated"
                conn_edge.edge_id = edge_id
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
                self._refresh_in_progress -= 1
            else:
                self._top.top_log("Logger", "LOG_WARNING",
                                  "Invalid UpdateType specified for connection update")

    def _mark_edges_for_removal(self):
        """ Anything edge the set (Active - Pending) is marked for deletion """
        for peer_id in self._current_adj_list.conn_edges:
            if (peer_id not in self._pending_adj_list.conn_edges and
                    self._current_adj_list.conn_edges[peer_id].edge_type != "CETypePredecessor"):
                self._current_adj_list.conn_edges[peer_id].marked_for_delete = True

    def _remove_edges(self):
        """ Minimize churn by removing a single connection per refresh. Only initiate removal of a
        successor edge if a replacement has been previously connected.
        """
        overlay_id = self._current_adj_list.overlay_id
        conn_succ = self._current_adj_list.filter("CETypeSuccessor", "CEStateConnected")
        num_conn_succ = len(conn_succ)
        for peer_id in self._current_adj_list.conn_edges:
            if self._current_adj_list.conn_edges[peer_id].marked_for_delete:
                if (self._current_adj_list.conn_edges[peer_id].edge_type != "CETypeSuccessor" or
                        (self._current_adj_list.conn_edges[peer_id].edge_type == "CETypeSuccessor"
                         and num_conn_succ > self._current_adj_list.max_successors)):
                    self._refresh_in_progress += 1
                    self._top.top_remove_edge(overlay_id, peer_id)
                    return

    def _create_new_edges(self):
        """ Any edge in set (Pending - Active) is created and added to Active """
        overlay_id = self._current_adj_list.overlay_id
        for peer_id in self._pending_adj_list.conn_edges:
            if not peer_id in self._current_adj_list.conn_edges:
                self._current_adj_list.conn_edges[peer_id] = \
                    self._pending_adj_list.conn_edges[peer_id]
                if self._current_adj_list.conn_edges[peer_id].edge_state == "CEStateUnknown":
                    self._refresh_in_progress += 1
                    self._negotiate_new_edge(self._pending_adj_list.conn_edges[peer_id].edge_id,
                                             self._pending_adj_list.conn_edges[peer_id].edge_type,
                                             peer_id)
                    self._top.top_add_edge(overlay_id, peer_id,
                                           self._pending_adj_list.conn_edges[peer_id].edge_id)
            else:
                # Existing edges in both Active and Pending are updated in place. Only the marked
                # for delete and edge type fields can be meaningfully changed in this case.
                self._current_adj_list.conn_edges[peer_id].marked_for_delete = \
                   self._pending_adj_list.conn_edges[peer_id].marked_for_delete
                self._current_adj_list.conn_edges[peer_id].edge_type = \
                   self._pending_adj_list.conn_edges[peer_id].edge_type

    def _update_net_connections(self):
        """
        Sync the network state by determining the difference between the active and pending net
        graphs. Create new successors edges before removing existing ones.
        """
        if self._current_adj_list.overlay_id != self._pending_adj_list.overlay_id:
            raise ValueError("Overlay ID mismatch adj lists, active:{0}, pending:{1}".
                             format(self._current_adj_list.overlay_id,
                                    self._pending_adj_list.overlay_id))

        self._mark_edges_for_removal()
        self._create_new_edges()
        self._pending_adj_list = None
        self._remove_edges()

    def _negotiate_new_edge(self, edge_id, edge_type, peer_id):
        olid = self._current_adj_list.overlay_id
        nid = self._current_adj_list.node_id
        er = EdgeRequest(overlay_id=olid, edge_id=edge_id, edge_type=edge_type,
                         recipient_id=peer_id, initiator_id=nid)
        self._top.top_send_negotiate_edge_req(er)

    def _resolve_request_collision(self, edge_req):
        nid = self._current_adj_list.node_id
        peer_id = edge_req.initiator_id
        edge_state = self._current_adj_list.conn_edges[peer_id].edge_state

        if edge_state == "CEStateConnected":
            edge_resp = EdgeResponse(is_accepted=False,
                                     data="A connected edge already exists. TunnelId={0}"
                                     .format(self._current_adj_list[peer_id].edge_id))

        elif edge_state == "CEStateUnknown" and nid < edge_req.initiator_id:
            edge_resp = EdgeResponse(is_accepted=False,
                                     data="Edge request collision, your request is superceeded by "
                                     "predecessor. TunnelId={0}"
                                     .format(self._current_adj_list[peer_id].edge_id))

        elif edge_state == "CEStateUnknown" and nid > edge_req.initiator_id:
            ce = self._current_adj_list.conn_edges[peer_id]
            ce.edge_edge_type = edge_req.edge_type
            ce._edge_id = uuid.UUID(edge_req.edge_id)
            edge_resp = EdgeResponse(is_accepted=True, data="Edge collision override accepted")

        return edge_resp

    def on_negotiate_edge_req(self, edge_req):
        peer_id = edge_req.initiator_id
        if peer_id in self._current_adj_list:
            edge_resp = self._resolve_request_collision(edge_req)
        if len(self._current_adj_list) >= (2*self._current_adj_list.threshold):
            edge_resp = EdgeResponse(is_accepted=False, data="Too many existing edges")

        if (len(self._current_adj_list) < (2*self._current_adj_list.threshold) and
                edge_req.edge_type == "CETypeSuccessor"):
            edge_resp = EdgeResponse(is_accepted=True, data="Successor edge permitted")

        if len(self._current_adj_list) < self._current_adj_list.threshold:
            edge_resp = EdgeResponse(is_accepted=True, data="Any edge permitted")

        self._top.top_log("Rcvd EdgeRequest={0}".format(edge_req))
        self._top.top_authorize_edge(edge_req.overlay_id, edge_req.initiator_id, edge_req.edge_id)
        return edge_resp

    def on_negotiate_edge_resp(self, edge_nego):
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
        if edge_nego.is_accepted:
            self._top.top_add_edge(self._current_adj_list.overlay_id, ce.peer_id, ce.edge_id)
        else:
            del self._current_adj_list[edge_nego.overlay_id]
