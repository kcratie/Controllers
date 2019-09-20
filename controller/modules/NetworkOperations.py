from controller.modules.NetworkGraph import ConnEdgeAdjacenctList
from controller.modules.NetworkGraph import ConnectionEdge
from controller.modules.NetworkGraph import EdgeTypesOut


class OperationsModel():
    def __init__(self, conn_edge, op_type, priority):
        self.conn_edge = conn_edge
        self.op_type = op_type
        self.op_priority = priority

    def __repr__(self):
        msg = "connEdge = %s, opType = %s, opPriority=%s>" % \
              (self.conn_edge, self.op_type, self.op_priority)
        return msg


class NetworkOperations():
    def __init__(self, current_Network_State, desired_Network_State):
        self.current_Network_State = current_Network_State
        self.desired_Network_State = desired_Network_State
        self.operations = {}

    def __iter__(self):
        sorted_list = sorted(
            self.operations, key=lambda x: self.operations[x].op_priority)
        for x in sorted_list:
            yield self.operations[x]

    def __repr__(self):
        msg = "currentNetworkState = %s, desiredNetworkState = %s, numOfOperations=%d, " \
              "Operations=%s>" % \
              (self.current_Network_State, self.desired_Network_State,
               len(self.operations), self.operations)
        return msg

    def find_Difference(self):

        for edge in self.desired_Network_State.conn_edges:
            if edge not in self.current_Network_State.conn_edges:
                if self.desired_Network_State.conn_edges[edge].edge_type == 'CETypeEnforced':
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 1)
                    self.operations[edge] = op
                elif self.desired_Network_State.conn_edges[edge].edge_type == "CETypeSuccessor":
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 2)
                    self.operations[edge] = op
                elif self.desired_Network_State.conn_edges[edge].edge_type == "CETypeOnDemand":
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 4)
                    self.operations[edge] = op
                elif self.desired_Network_State.conn_edges[edge].edge_type == "CETypeLongDistance":
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 7)
                    self.operations[edge] = op
            else:
                op = OperationsModel(
                    self.desired_Network_State.conn_edges[edge], "opTypeUpdate", 0)
                self.operations[edge] = op

        for edge in self.current_Network_State.conn_edges:
            if edge not in self.desired_Network_State.conn_edges:
                if self.current_Network_State.conn_edges[edge].edge_type in EdgeTypesOut:
                    if self.current_Network_State.conn_edges[edge].edge_state == "CEStateConnected":
                        if self.current_Network_State.conn_edges[edge].edge_type == "CETypeOnDemand":
                            op = OperationsModel(
                                self.current_Network_State.conn_edges[edge], "opTypeRemove", 3)
                            self.operations[edge] = op
                        elif self.current_Network_State.conn_edges[edge].edge_type == "CETypeSuccessor":
                            op = OperationsModel(
                                self.current_Network_State.conn_edges[edge], "opTypeRemove", 5)
                            self.operations[edge] = op
                        elif self.current_Network_State.conn_edges[edge].edge_type == "CETypeLongDistance":
                            op = OperationsModel(
                                self.current_Network_State.conn_edges[edge], "opTypeRemove", 6)
                            self.operations[edge] = op
