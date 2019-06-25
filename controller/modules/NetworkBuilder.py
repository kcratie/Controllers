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


import time
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
    _DEL_RETRY_INTERVAL = 10
    """description of class"""
    def __init__(self, top_man, overlay_id, node_id, max_wrkld):
        self._current_adj_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._pending_adj_list = None
        self._negotiated_edges = {}
        self._refresh_in_progress = 0
        self._max_concurrent_wrkload = max_wrkld
        #self._lock = threading.Lock()
        self._top = top_man
        self._ops = {}

    def __repr__(self):
        state = "current_adj_list=%s, pending_adj_list=%s, negotiated_edges=%s, "\
                "refresh_in_progress=%s, _max_concurrent_wrkload=%s" % \
                (self._current_adj_list, self._pending_adj_list, self._negotiated_edges,
                 self._refresh_in_progress, self._max_concurrent_wrkload)
        return state

    @property
    def is_ready(self):
        """
        Is the NetworkBuilder ready for a new NetGraph? This means all the entries in the
        pending adj list has been cleared.
        """
        #with self._lock:
        return self._is_ready()

    def _is_ready(self):
        return not bool(self._pending_adj_list)

    def _is_max_concurrent_workload(self):
        return self._refresh_in_progress >= self._max_concurrent_wrkload

    def get_adj_list(self):
        #with self._lock:
        return deepcopy(self._current_adj_list)

    def refresh(self, net_graph=None):
        """
        Transitions the overlay network overlay to the desired state specified by pending
        adjacency list.
        """
        #with self._lock:
        self._top.top_log("New net graph:{0}\nself:{1}".format(net_graph, self))
        assert ((self._is_ready() and bool(net_graph)) or
                (not self._is_ready() and not bool(net_graph))),\
                    "Netbuilder is not ready for a new net graph"

        if net_graph and self._is_ready():
            self._pending_adj_list = net_graph
            self._current_adj_list.max_successors = net_graph.max_successors
            self._current_adj_list.max_ldl = net_graph.max_ldl
            self._current_adj_list.max_ondemand = net_graph.max_ondemand
            self._current_adj_list.degree_threshold = net_graph.degree_threshold
            self._current_adj_list.update_closest()
            self._mark_edges_for_removal()
        self._process_pending_adj_list()
        #self._create_oplist()
        #self._process_ops()

    def update_edge_state(self, event):
        """
        Updates the connection edge's current state based on the provided event. The number of CEs
        not in the EdgeState CEStateConnected is used to limit the number of edges being
        constructed concurrently.
        """
        peer_id = event["PeerId"]
        edge_id = event["TunnelId"]
        overlay_id = event["OverlayId"]
        #with self._lock:
        if event["UpdateType"] == "LnkEvAuthorized":
            self._add_incoming_auth_conn_edge(peer_id)
        elif event["UpdateType"] == "LnkEvDeauthorized":
            ce = self._current_adj_list[peer_id]
            assert ce.edge_state == "CEStateAuthorized", "Deauth CE={0}".format(ce)
            del self._current_adj_list[peer_id]
            self._refresh_in_progress -= 1
        elif event["UpdateType"] == "LnkEvCreating":
            conn_edge = self._current_adj_list.conn_edges.get(peer_id, None)
            conn_edge.edge_state = "CEStateCreated"
        elif event["UpdateType"] == "LnkEvConnected":
            self._current_adj_list[peer_id].edge_state = "CEStateConnected"
            self._current_adj_list[peer_id].connected_time = \
                event["ConnectedTimestamp"]
            self._refresh_in_progress -= 1
        elif event["UpdateType"] == "LnkEvDisconnected":
            # the local topology did not request removal of the connection
            self._top.top_log("CEStateDisconnected event recvd peer_id: {0}, edge_id: {1}".
                              format(peer_id, edge_id))
            self._current_adj_list[peer_id].edge_state = "CEStateDisconnected"
            self._refresh_in_progress += 1
            self._top.top_remove_edge(overlay_id, peer_id)
        elif event["UpdateType"] == "LnkEvRemoved":
            del self._current_adj_list[peer_id]
            self._refresh_in_progress -= 1
        elif event["UpdateType"] == "RemoveEdgeFailed":
            # leave the node in the adj list and marked for removal to be retried.
            # the retry occurs too quickly and causes too many attempts before it succeeds
            self._refresh_in_progress -= 1
            self._current_adj_list[peer_id].created_time = \
                time.time() + NetworkBuilder._DEL_RETRY_INTERVAL
        else:
            self._top.top_log("Invalid UpdateType specified for event",
                              level="LOG_WARNING")
        assert self._refresh_in_progress >= 0, "refresh in progress is negative {}"\
            .format(self._refresh_in_progress)

    def _mark_edges_for_removal(self):
        """
        Anything edge the set (Active - Pending) is marked for deletion but do not remove
        negotiated edges.
        """
        for peer_id in self._current_adj_list:
            if (self._current_adj_list.is_successor(peer_id) or
                    self._current_adj_list.is_predecessor(peer_id)):
                continue # high priority edges
            if peer_id in self._pending_adj_list:
                continue # the edge should be maintained
            if self._current_adj_list[peer_id].edge_state != "CEStateConnected":
                # don't delete an edge before it completes the create process. if it fails LNK will
                # initiate the removal.
                continue
            if time.time() - self._current_adj_list[peer_id].connected_time < 60:
                continue # edge is too young
            self._current_adj_list[peer_id].marked_for_delete = True

    def _remove_edges(self):
        """
        Minimize churn by removing a single connection per refresh. Only initiate removal of an
        edge if it is not the first successor.
        """
        overlay_id = self._current_adj_list.overlay_id
        #if not self._current_adj_list.at_threshold():
        #    return # don't start deleting links until at the threshold
        for peer_id in self._current_adj_list:
            ce = self._current_adj_list[peer_id]
            if (ce.marked_for_delete and ce.edge_state != "CEStateDeleting" and
                    ce.created_time < time.time()):
                self._refresh_in_progress += 1
                ce.edge_state = "CEStateDeleting"
                self._top.top_remove_edge(overlay_id, peer_id)
                return

    def _create_new_edges(self):
        """ Any edge in set (Pending - Active) is created and added to Active """
        rmv_list = []
        nego_list = []
        for peer_id in self._pending_adj_list:
            if self._is_max_concurrent_workload():
                break
            rmv_list.append(peer_id)
            ce = self._pending_adj_list[peer_id]
            #if ce.edge_type == "CETypeLongDistance" and \
            #    self._current_adj_list.num_ldl >= self._current_adj_list.max_ldl:
            #    continue
            if peer_id in self._negotiated_edges:  # an edge has already been negotiated
                continue
            if peer_id not in self._current_adj_list:
                #assert ce.edge_state == "CEStateInitialized", \
                #    "State!=CEStateInitialized CE={0}".format(ce)
                self._current_adj_list[peer_id] = ce
                nego_list.append(ce)
        for peer_id in rmv_list:
            del self._pending_adj_list[peer_id]
        for ce in nego_list:
            self._negotiate_new_edge(ce.edge_id, ce.edge_type, ce.peer_id)

    def _process_pending_adj_list(self):
        """
        Sync the network state by determining the difference between the active and pending net
        graphs. Create new successors edges before removing existing ones.
        """
        if not self._pending_adj_list:
            return # incoming connections can occur before a pending list is created
        if self._current_adj_list.overlay_id != self._pending_adj_list.overlay_id:
            raise ValueError("Overlay ID mismatch adj lists, active:{0}, pending:{1}".
                             format(self._current_adj_list.overlay_id,
                                    self._pending_adj_list.overlay_id))

        if not self._is_max_concurrent_workload():
            self._create_new_edges()
            # edges in both pending and current are left as is, no updates
            self._remove_edges()
        else:
            self._top.top_log("Netbuilder currently busy at max workload")

    def _negotiate_new_edge(self, edge_id, edge_type, peer_id):
        """ Role A1 """
        self._refresh_in_progress += 1
        olid = self._current_adj_list.overlay_id
        nid = self._current_adj_list.node_id
        er = EdgeRequest(overlay_id=olid, edge_id=edge_id, edge_type=edge_type,
                         recipient_id=peer_id, initiator_id=nid)
        self._top.top_send_negotiate_edge_req(er)

    def _resolve_request_collision(self, edge_req):
        nid = self._current_adj_list.node_id
        peer_id = edge_req.initiator_id
        edge_state = self._current_adj_list[peer_id].edge_state
        edge_resp = None
        if edge_state in ("CEStateCreated", "CEStateConnected"):
            msg = "E1 - A connected edge already exists. TunnelId={0}"\
                .format(self._current_adj_list[peer_id].edge_id[:7])
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self._top.top_log(msg)
        elif edge_state == "CEStateInitialized" and nid < edge_req.initiator_id:
            msg = "E2 - Edge request collision, your request is superceeded by predecessor. "\
                        "TunnelId={0}".format(self._current_adj_list[peer_id].edge_id[:7])
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self._top.top_log(msg)
        elif edge_state == "CEStateInitialized" and nid > edge_req.initiator_id:
            ce = self._current_adj_list.remove_connection_edge(peer_id)
            ce.edge_type = ng.transpose_edge_type(edge_req.edge_type)
            self._negotiated_edges[peer_id] = ce
            msg = "E0 - Edge collision override accepted. Tunnel remapped {0}->{1}"\
                .format(ce.edge_id[:7], edge_req.edge_id[:7])
            ce.edge_id = edge_req.edge_id
            edge_resp = EdgeResponse(is_accepted=True, data=msg)
            self._top.top_log(msg)
            self._top.top_log("Existing CE={0} moved to negotiated_edges={1}".
                              format(ce, self._negotiated_edges))
        else:
            edge_resp = EdgeResponse(False, "E6 - Request colides with an edge being destroyed."\
                                            "Try later")
        assert bool(edge_resp), "NetBuilder={0}".format(self)
        return edge_resp

    def negotiate_incoming_edge(self, edge_req):
        """ Role B1 """
        self._top.top_log("Rcvd EdgeRequest={0}".format(edge_req))
        edge_resp = None
        peer_id = edge_req.initiator_id
        if peer_id in self._current_adj_list:
            edge_resp = self._resolve_request_collision(edge_req)
        elif edge_req.edge_type == "CETypeSuccessor":
            edge_resp = EdgeResponse(is_accepted=True, data="Successor edge permitted")
        elif edge_req.edge_type == "CETypeEnforced":
            edge_resp = EdgeResponse(is_accepted=True, data="Enforced edge permitted")
        elif not self._current_adj_list.is_threshold_ldli():
            edge_resp = EdgeResponse(is_accepted=True, data="Any edge permitted")
        else:
            edge_resp = EdgeResponse(is_accepted=False,
                                     data="E5 - Too many existing edges.")

        if edge_resp.is_accepted and edge_resp.data[:2] != "E0":
            et = ng.transpose_edge_type(edge_req.edge_type)
            ce = ConnectionEdge(peer_id=peer_id, edge_id=edge_req.edge_id, edge_type=et)
            self._negotiated_edges[peer_id] = ce
            self._top.top_log("New CE={0} added to negotiated_edges={1}".
                              format(ce, self._negotiated_edges))
        return edge_resp

    def _add_incoming_auth_conn_edge(self, peer_id):
        """ Role B2 """
        self._refresh_in_progress += 1
        ce = self._negotiated_edges.pop(peer_id)
        ce.edge_state = "CEStateAuthorized"
        self._current_adj_list.add_connection_edge(ce)

    def complete_edge_negotiation(self, edge_nego):
        """ Role A2 """
        self._top.top_log("EdgeNegotiate={0}".format(edge_nego))
        #with self._lock:
        if edge_nego.recipient_id not in self._current_adj_list and \
            edge_nego.recipient_id not in self._negotiated_edges:
            self._top.top_log("Peer Id from edge negotiation not in current adjacency list or "
                              " _negotiated_edges. The transaction has been discarded.",
                              "LOG_ERROR")
            return
        peer_id = edge_nego.recipient_id
        edge_id = edge_nego.edge_id

        ce = self._negotiated_edges.pop(edge_nego.recipient_id, None)
        if not ce:
            ce = self._current_adj_list[edge_nego.recipient_id]
        if not edge_nego.is_accepted:
            self._refresh_in_progress -= 1
            # if E2 (request superceeded) do nothing here. The corresponding CE instance will
            # be converted in resolve_collision_request().
            if edge_nego.data[:2] != "E2":
                del self._current_adj_list[peer_id]
        else:
            if ce.edge_id != edge_nego.edge_id:
                self._top.top_log("EdgeNego parameters does not match current adjacency list, "
                                    "The transaction has been discarded.", "LOG_ERROR")
                del self._current_adj_list[ce.peer_id]
                self._refresh_in_progress -= 1
            else:
                self._top.top_add_edge(self._current_adj_list.overlay_id, peer_id, edge_id)
