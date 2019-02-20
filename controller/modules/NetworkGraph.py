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

class ConnectionEdge():
    """ A discriptor of the edge/link between two peers."""
    _PACK_STR = '!16s16sff18s19s?'
    _EdgeTypes = ["CETypeUnknown", "CETypeEnforced", "CETypeSuccessor", "CETypeLongDistance",
                  "CETypePredecessor", "CETypeIncoming"]
    _EdgeStates = ["CEStateUnknown", "CEStateCreated", "CEStateConnected", "CEStateDisconnected"]

    def __init__(self, peer_id=None, edge_type="CETypeUnknown"):
        self.peer_id = peer_id
        self.link_id = None
        self.created_time = time.time()
        self.connected_time = None
        self.edge_state = "CEStateUnknown"
        self.edge_type = edge_type
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
        msg = ("ConnectionEdge<peer_id = %s, link_id = %s, created_time = %s, connected_time = %s,"
               " state = %s, edge_type = %s, marked_for_delete = %s>" %
               (self.peer_id, self.link_id, str(self.created_time), str(self.connected_time),
                self.edge_state, self.edge_type, self.marked_for_delete))
        #msg = "<peer_id = %s, edge_type = %s>" % (self.peer_id, self.edge_type)
        return msg

    def __iter__(self):
        yield("peer_id", self.peer_id)
        yield("link_id", self.link_id)
        yield("created_time", self.created_time)
        yield("connected_time", self.connected_time)
        yield("edge_state", self.edge_state)
        yield("edge_type", self.edge_type)
        yield("marked_for_delete", self.marked_for_delete)

    def serialize(self):
        return struct.pack(ConnectionEdge._PACK_STR, self.peer_id, self.link_id, self.created_time,
                           self.connected_time, self.edge_state, self.edge_type,
                           self.marked_for_delete)

    @classmethod
    def from_bytes(cls, data):
        ce = cls()
        (ce.peer_id, ce.link_id, ce.created_time, ce.connected_time, ce.edge_state,
         ce.edge_type, ce.marked_for_delete) = struct.unpack_from(cls._PACK_STR, data)
        return ce

    def to_json(self):
        return json.dumps(dict(self))

    #def to_json(self):
    #    return json.dumps(dict(peer_id=self.peer_id, link_id=self.link_id,
    #                           created_time=self.created_time, connected_time=self.connected_time,
    #                           state=self.edge_state, edge_type=self.edge_type,
    #                           marked_for_delete=self.marked_for_delete))
    @classmethod
    def from_json_str(cls, json_str):
        ce = cls()
        jce = json.loads(json_str)
        ce.peer_id = jce["peer_id"]
        ce.link_id = jce["link_id"]
        ce.created_time = jce["created_time"]
        ce.connected_time = jce["connected_time"]
        ce.edge_state = jce["edge_state"]
        ce.edge_type = jce["edge_type"]
        ce.marked_for_delete = jce["marked_for_delete"]
        return ce

class ConnEdgeAdjacenctList():
    """ A series of ConnectionEdges that are incident on the local node"""
    def __init__(self, overlay_id=None, node_id=None, cfg=None):
        self.overlay_id = overlay_id
        self.node_id = node_id
        self.conn_edges = {}
        self.max_successors = 1
        self.max_ldl = 4
        if cfg:
            self.max_successors = int(cfg["MaxSuccessors"])
            self.max_ldl = int(cfg["MaxLongDistEdges"])

    def __len__(self):
        return len(self.conn_edges)

    def __repr__(self):
        msg = "ConnEdgeAdjacenctList<overlay_id = %s, node_id = %s, conn_edges = %s>" \
               %(self.overlay_id, self.node_id, self.conn_edges)
        return msg

    def add_connection_edge(self, ce):
        self.conn_edges[ce.peer_id] = ce

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

    def validate(self):
        edge_count = self.edge_type_count("CETypeSuccessor")
        if edge_count > self.max_successors:
            raise ValueError("Too many Successor edges in adj list, current:{0}, max:{1}".
                             format(edge_count, self.max_successors))
        edge_count = self.edge_type_count("CETypeLongDistance")
        if self.edge_type_count("CETypeLongDistance") > self.max_ldl:
            raise ValueError("Too many Long Distance edges in adj list, current:{0}, max:{1}".
                             format(edge_count, self.max_ldl))

class NetworkGraph():
    """Describes the structure of the Topology as a dict of node IDs to ConnEdgeAdjacenctList"""
    def __init__(self, graph=None):
        self._graph = graph
        if self._graph is None:
            self._graph = {}

    def vertices(self):
        """ returns the vertices of a graph """
        return list(self._graph.keys())

    def edges(self):
        """ returns the edges of a graph """
        return self._generate_edges()

    def find_isolated_nodes(self):
        """ returns a list of isolated nodes. """
        isolated = []
        for node in self._graph:
            if not self._graph[node]:
                isolated += node
        return isolated

    def add_adj_list(self, adj_list):
        self._graph[adj_list.node_id] = adj_list

    def add_vertex(self, vertex):
        """ Adds vertex "vertex" as a key with an empty ConnEdgeAdjacenctList to self._graph. """
        if vertex not in self._graph:
            self._graph[vertex] = ConnEdgeAdjacenctList()

    def add_edge(self, edge):
        pass

    def _generate_edges(self):
        """
        Generating the edges of the graph "graph". Edges are represented as sets
        with one (a loop back to the vertex) or two vertices
        """
        edges = set()
        for vertex in self._graph:
            for neighbour in self._graph[vertex].get_edges():
                edge = (vertex, neighbour)
                edges.add(edge)
        return sorted(edges)

    def __str__(self):
        res = "vertices: "
        for k in self._graph:
            res += str(k) + " "
        res += "\nedges:\n"
        for edge in self._generate_edges():
            res += str(edge) + "\n"
        return res

    # todo: fix methods below
    def find_path(self, start_vertex, end_vertex, path=None):
        """
        Find a path from start_vertex to end_vertex in graph
        """
        if path is None:
            path = []
        graph = self._graph
        path = path + [start_vertex]
        if start_vertex == end_vertex:
            return path
        if start_vertex not in graph:
            return None
        for vertex in graph[start_vertex]:
            if vertex not in path:
                extended_path = self.find_path(vertex,
                                               end_vertex,
                                               path)
                if extended_path:
                    return extended_path
        return None

    def find_all_paths(self, start_vertex, end_vertex, path=None):
        """ find all paths from start_vertex to
            end_vertex in graph """
        if not path:
            path = []
        graph = self._graph
        path = path + [start_vertex]
        if start_vertex == end_vertex:
            return [path]
        if start_vertex not in graph:
            return []
        paths = []
        for vertex in graph[start_vertex]:
            if vertex not in path:
                extended_paths = self.find_all_paths(vertex,
                                                     end_vertex,
                                                     path)
                for p in extended_paths:
                    paths.append(p)
        return paths

    def vertex_degree(self, vertex):
        """ The degree of a vertex is the number of edges connecting
            it, i.e. the number of adjacent vertices. Loops are counted
            double, i.e. every occurence of vertex in the list
            of adjacent vertices. """
        adj_vertices = self._graph[vertex]
        degree = len(adj_vertices) + adj_vertices.count(vertex)
        return degree

    def delta(self):
        """ the minimum degree of the graph """
        minv = 100000000
        for vertex in self._graph:
            vertex_degree = self.vertex_degree(vertex)
            if vertex_degree < minv:
                minv = vertex_degree
        return minv

    def Delta(self):
        """ the maximum degree of the graph """
        maxv = 0
        for vertex in self._graph:
            vertex_degree = self.vertex_degree(vertex)
            if vertex_degree > maxv:
                maxv = vertex_degree
        return maxv
