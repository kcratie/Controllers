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
try:
    import simplejson as json
except ImportError:
    import json
import struct
import uuid

EdgeTypes1 = ["CETypeUnknown", "CETypeEnforced", "CETypeSuccessor", "CETypeLongDistance",
              "CETypeOnDemand"]
EdgeTypes2 = ["CETypeUnknown", "CETypeIEnforced", "CETypePredecessor", "CETypeILongDistance",
              "CETypeIOnDemand"]
EdgeStates = ["CEStateUnknown", "CEStateCreated", "CEStateConnected", "CEStateDisconnected",
              "CEStateDeleting"]

def transpose_edge_type(edge_type):
    edge_type = EdgeTypes1[0]
    if edge_type == "CETypeEnforced":
        edge_type = EdgeTypes2[1]
    elif edge_type == "CETypeSuccessor":
        edge_type = EdgeTypes2[2]
    elif edge_type == "CETypeLongDistance":
        edge_type = EdgeTypes2[3]
    elif edge_type == "CETypeOnDemand":
        edge_type = EdgeTypes2[4]
    elif edge_type == "CETypeIEnforced":
        edge_type = EdgeTypes1[1]
    elif edge_type == "CETypePredecessor":
        edge_type = EdgeTypes1[2]
    elif edge_type == "CETypeILongDistance":
        edge_type = EdgeTypes1[3]
    elif edge_type == "CETypeIOnDemand":
        edge_type = EdgeTypes1[4]
    return edge_type

class ConnectionEdge():
    """ A discriptor of the edge/link between two peers."""
    _PACK_STR = '!16s16sff18s19s?'
    def __init__(self, peer_id=None, edge_id=None, edge_type="CETypeUnknown"):
        self.peer_id = peer_id
        self._edge_id = edge_id
        if not self._edge_id:
            self._edge_id = uuid.uuid4().hex
        self.created_time = time.time()
        self.connected_time = None
        self.edge_state = "CEStateUnknown"
        self.edge_type = edge_type
        #self.edge_role = [edge_type]
        self.marked_for_delete = False

    def __key__(self):
        return int(self.peer_id, 16)

    def __eq__(self, other):
        return self.__key__() == other.__key__()

    def __ne__(self, other):
        return self.__key__() != other.__key__()

    def __lt__(self, other):
        return self.__key__() < other.__key__()

    def __le__(self, other):
        return self.__key__() <= other.__key__()

    def __gt__(self, other):
        return self.__key__() > other.__key__()

    def __ge__(self, other):
        return self.__key__() >= other.__key__()

    def __hash__(self):
        return hash(self.__key__())

    def __repr__(self):
        msg = ("ConnectionEdge<peer_id = %s, edge_id = %s, created_time = %s, connected_time = %s,"
               " state = %s, edge_type = %s, marked_for_delete = %s>" %
               (self.peer_id, self.edge_id, str(self.created_time), str(self.connected_time),
                self.edge_state, self.edge_type, self.marked_for_delete))
        #msg = ("ConnectionEdge<peer_id = %s, edge_id = %s, state = %s, edge_type = %s>" %
        #       (self.peer_id, self.edge_id, self.edge_state, self.edge_type))
        return msg

    def __iter__(self):
        yield("peer_id", self.peer_id)
        yield("edge_id", self.edge_id)
        yield("created_time", self.created_time)
        yield("connected_time", self.connected_time)
        yield("edge_state", self.edge_state)
        yield("edge_type", self.edge_type)
        yield("marked_for_delete", self.marked_for_delete)

    @property
    def edge_id(self):
        return self._edge_id

    def serialize(self):
        return struct.pack(ConnectionEdge._PACK_STR, self.peer_id, self.edge_id, self.created_time,
                           self.connected_time, self.edge_state, self.edge_type,
                           self.marked_for_delete)

    @classmethod
    def from_bytes(cls, data):
        ce = cls()
        (ce.peer_id, ce._edge_id, ce.created_time, ce.connected_time, ce.edge_state,
         ce.edge_type, ce.marked_for_delete) = struct.unpack_from(cls._PACK_STR, data)
        return ce

    def to_json(self):
        return json.dumps(dict(self))

    #def to_json(self):
    #    return json.dumps(dict(peer_id=self.peer_id, edge_id=self.edge_id,
    #                           created_time=self.created_time, connected_time=self.connected_time,
    #                           state=self.edge_state, edge_type=self.edge_type,
    #                           marked_for_delete=self.marked_for_delete))
    @classmethod
    def from_json_str(cls, json_str):
        ce = cls()
        jce = json.loads(json_str)
        ce.peer_id = jce["peer_id"]
        ce._edge_id = jce["edge_id"]
        ce.created_time = jce["created_time"]
        ce.connected_time = jce["connected_time"]
        ce.edge_state = jce["edge_state"]
        ce.edge_type = jce["edge_type"]
        ce.marked_for_delete = jce["marked_for_delete"]
        return ce

class ConnEdgeAdjacenctList():
    """ A series of ConnectionEdges that are incident on the local node"""
    #def __init__(self, overlay_id, node_id, cfg):
    def __init__(self, overlay_id, node_id, max_succ=0, max_ldl=0, max_ond=0):
        self.overlay_id = overlay_id
        self.node_id = node_id
        self.conn_edges = {}
        self._successor_nid = None
        self.degree_threshold = (2 * (max_succ + max_ldl)) + max_ond
        self.max_successors = max_succ
        self.max_ldl = max_ldl
        self.max_ondemand = max_ond

    def __len__(self):
        return len(self.conn_edges)

    def __repr__(self):
        msg = "ConnEdgeAdjacenctList<overlay_id = %s, node_id = %s, successor_nid=%s, "\
              "conn_edges = %s>" % (self.overlay_id, self.node_id, self._successor_nid,
                                    self.conn_edges)
        return msg

    def __bool__(self):
        return bool(self.conn_edges)

    def __contains__(self, peer_id):
        if peer_id in self.conn_edges:
            return True
        return False

    def __setitem__(self, peer_id, ce):
        #self.conn_edges[peer_id] = ce
        self.add_connection_edge(ce)

    def __getitem__(self, peer_id):
        return self.conn_edges[peer_id]

    def __delitem__(self, peer_id):
        #del self.conn_edges[peer_id]
        self.remove_connection_edge(peer_id)

    def __iter__(self):
        return self.conn_edges.__iter__()

    @property
    def successor_ce(self):
        return self.conn_edges.get(self._successor_nid)

    def add_connection_edge(self, ce):
        self.conn_edges[ce.peer_id] = ce
        if not self._successor_nid:
            self._successor_nid = ce.peer_id
        elif ce.peer_id > self.node_id and ce.peer_id < self._successor_nid:
            self._successor_nid = ce.peer_id

    def remove_connection_edge(self, peer_id):
        ce = self.conn_edges.pop(peer_id, None)
        if not self.conn_edges:
            self._successor_nid = None
        elif ce and ce.peer_id == self._successor_nid:
            nl = [*self.conn_edges.keys()]
            nl.append(self.node_id)
            nl = sorted(nl)
            idx = nl.index(self.node_id)
            succ_i = (idx+1) % len(nl)
            self._successor_nid = nl[succ_i]

    def get_edges(self, edge_type):
        conn_edges = {}
        for peer_id in self.conn_edges:
            if self.conn_edges[peer_id].edge_type == edge_type:
                conn_edges[peer_id] = self.conn_edges[peer_id]
        return conn_edges

    def edge_type_count(self, edge_type):
        cnt = 0
        for peer_id in self.conn_edges:
            if self.conn_edges[peer_id].edge_type == edge_type:
                cnt = cnt + 1
        return cnt

    def filter(self, edge_type, edge_state):
        conn_edges = {}
        for peer_id in self.conn_edges:
            if (self.conn_edges[peer_id].edge_type == edge_type and
                    self.conn_edges[peer_id].edge_state == edge_state):
                conn_edges[peer_id] = self.conn_edges[peer_id]
        return conn_edges
