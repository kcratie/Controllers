import uuid
from controller.modules.NetworkGraph import ConnectionEdge
from controller.modules.NetworkGraph import ConnEdgeAdjacenctList
from controller.modules.GraphBuilder import GraphBuilder

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
def main():
    max_nodes = 100
    node_ids = []
    for _ in range(0, max_nodes):
        node_ids.append(str(uuid.uuid4().hex)[:7])
    print("Node IDs %s"%(node_ids))
    net_graph = ConnEdgeAdjacenctList()
    cnt = 0
    for i in range(0, max_nodes):
        node_id = node_ids[i]
        # print("NodeId %s"% (node_id))
        peers = node_ids.copy()
        peers.pop(i)
        peers.sort()
        # print("Peers %s"%(peers))

        # l = len(peers)
        enforced = [] #node_ids #[math.floor(l/4):math.floor(l/3)]
        # print("Enforced %s"%(str(sorted(enforced))))

        params = {"OverlayId": "101", "NodeId": node_id,
                  "Peers": peers,
                  "EnforcedEdges": enforced,
                  "MaxSuccessors": 1,
                  "LongDistLinkCount": 4,
                  "ManualTopology": False}
        gb = GraphBuilder(params)
        tc = gb.is_too_close(node_id)
        if tc:
            cnt += 1
        print("Is %s too close to me %s  %s" % (node_id[:7], node_id[:7], tc))

        #res = gb.symphony_prob_distribution(1000, 1000)
        #with open("results.txt", "w") as f:
        #    f.write(str(res))

        #ascii_histogram(res)
        #adjl = gb.build_adj_list()
        #net_graph.add_adj_list(adjl)

    with open("results.txt", "w") as f:
        f.write("Network Graph %s"% (net_graph))
    #print("Network Graph %s"% (net_graph))

if __name__ == "__main__":
    main()
