import uuid
from controller.modules.GraphBuilder import GraphBuilder
import controller.modules.NetworkGraph as ng

#def draw_hist(samples):
#    count, bins, ignored = plt.hist(samples, 50, density=True)
#    plt.plot(bins, np.ones_like(bins), linewidth=2, color='r')
#    plt.show()
def count_elements(seq) -> dict:
    """Tally elements from `seq`."""
    hist = {}
    for i in seq:
        hist[i] = hist.get(i, 0) + 1
    return hist

def ascii_histogram(seq) -> None:
    """A horizontal frequency-table/histogram plot."""
    counted = count_elements(seq)
    for k in sorted(counted):
        print('{0:5f} {1}'.format(k, '+' * counted[k]))


class GraphBuilderTest():
    def __init__(self):
        self._node_id = None
        self._node_ids = []
        self._max_succ = 3
        self._max_ond = 1
        self._max_ldl = 2
        self._manual_topo = False
        self._enf_lnks = []
        self._olid = "101000F"
        self._peer_list = None
        self._gb = None
        self._netgraph = None

    def log(self, level, msg, *args):
        print(msg, args)

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

    def set_network(self, idx):
        self._node_id = self._node_ids[idx]
        # print("NodeId %s"% (node_id))
        self._peer_list = self._node_ids.copy()
        self._peer_list.pop(idx)
        self._peer_list.sort()
        # print("Peers %s"%(self._peer_list))
        self._netgraph = ng.ConnEdgeAdjacenctList(self._olid, self._node_id)

        return True

    def make_graph_builder(self):
        params = {"OverlayId": self._olid, "NodeId": self._node_id,
                  "ManualTopology": self._manual_topo, "EnforcedEdges": self._enf_lnks,
                  "MaxSuccessors": self._max_succ, "MaxLongDistEdges": self._max_ldl,
                  "MaxOnDemandEdges": self._max_ond}
        self._gb = GraphBuilder(params, top=self)
        self._gb._prep(self._peer_list)
        return True

    def is_too_close(self):
        cnt = 0
        for i in range(self.num_peers):
            tc = self._gb.is_too_close(self._peer_list[i])
            if tc:
                cnt += 1
            #print("Is %s too close to me %s  %s" % (self._peer_list[i][:7], self._node_id[:7], tc))
        print("{0}/{1} are too close".format(cnt, self.num_peers))
        return True

    def build_enforced(self):
        pass
        # l = len(peers)
        #enforced = [] #node_ids #[math.floor(l/4):math.floor(l/3)]
        # print("Enforced %s"%(str(sorted(enforced))))

    def build_successors(self):
        empty_adjl = ng.ConnEdgeAdjacenctList(self._olid, self._node_id)
        self._gb._build_successors(self._netgraph, empty_adjl)
        return True

    def build_ldl(self):
        empty_adjl = ng.ConnEdgeAdjacenctList(self._olid, self._node_id)
        self._gb._build_long_dist_links(self._netgraph, empty_adjl)
        return True

    def get_netgraph(self, prev_netgr=None):
        if not prev_netgr:
            prev_netgr = ng.ConnEdgeAdjacenctList(self._olid, self._node_id)
        self._netgraph = self._gb.build_adj_list(self._peer_list, prev_netgr)
        return True

def main():
    max_nodes = 12
    #test = GraphBuilderTest()
    #test.gen_nodes(max_nodes)
    #for i in range(0, max_nodes):
    #    test.set_network(i)
    #    test.make_graph_builder()
    #    test.is_too_close()
    #    test.build_successors()
    #    test.build_ldl()
    #    print("Net Graph", test._netgraph)
######################################################
    test = GraphBuilderTest()
    test.gen_nodes(max_nodes)
    test.set_network(0)
    test.make_graph_builder()
    test.get_netgraph()
    print("Net Graph", test._netgraph)
    for peer_id in test._netgraph:
        ce = test._netgraph[peer_id]
        if ce.edge_type == "CETypeLongDistance":
            ce.edge_state = "CEStateConnected"
            break
    test.get_netgraph(test._netgraph)
    print("Transitioned Net Graph", test._netgraph)


if __name__ == "__main__":
    main()
