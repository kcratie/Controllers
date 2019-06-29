import uuid
import controller.modules.NetworkGraph
from controller.modules.NetworkGraph import ConnectionEdge
from controller.modules.NetworkGraph import ConnEdgeAdjacenctList

class NetworkGraphTest():
    def __init__(self):
        self._node_id = None
        self._node_ids = []
        self._max_nodes = 12
        self._max_succ = 3
        self._max_ond = 1
        self._max_ldl = 2
        self._manual_topo = False
        self._enf_lnks = []
        self._olid = "101000F"
        self._peer_list = None
        self._current_netg = None 
        self._next_netg = None


    def log(self, level, msg, *args):
        print(level + msg, args)

    @property
    def node_id(self):
        return self._node_id

    @property
    def num_peers(self):
        return  len(self._peer_list)


    def gen_nodes(self, max_nodes):
        for _ in range(0, max_nodes):
            self._node_ids.append(str(uuid.uuid4().hex)[:7])
        self._node_ids.sort()
        print("Node IDs %s"%(self._node_ids))

    def gen_network(self, idx):
        self._node_id = self._node_ids[idx]
        self._peer_list = self._node_ids.copy()
        self._peer_list.pop(idx)
        self._peer_list.sort()

    def gen_next_netgraph(self, idx):
        self.gen_network(idx)
        self._next_netg = ConnEdgeAdjacenctList(self._olid, self._node_id, self._max_succ,
                                                self._max_ldl, self._max_ond)
        for peer_id in self._peer_list:
            ce = ConnectionEdge(peer_id, edge_type="CETypeILongDistance")
            self._next_netg.add_conn_edge(ce)
            self._next_netg[ce.peer_id] = ce


    def is_netgraph_empty(self, netgraph):
        return not bool(netgraph)

def main():
    test = NetworkGraphTest()
    test.gen_nodes(test._max_nodes)
######################################################
    for i in range(0, test._max_nodes):
        test.gen_next_netgraph(i)
        print("Net Graph", test._next_netg)
        del test._next_netg[test._peer_list[2]]
        test._next_netg.remove_conn_edge(test._peer_list[3])
        del test._next_netg["0000000"]
        assert test._peer_list[3] not in test._next_netg, "Error {} was removed".format(test._peer_list[3])
        ce = test._next_netg[test._peer_list[6]]
        print("Is netgraph empty?", test.is_netgraph_empty(test._next_netg))
        print("Net Graph", test._next_netg)


if __name__ == "__main__":
    main()
