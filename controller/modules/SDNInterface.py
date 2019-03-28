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
try:
    import simplejson as json
except ImportError:
    import json
import threading
import time
import socketserver
from controller.framework.ControllerModule import ControllerModule
import controller.framework.ipoplib as ipoplib

class SDNIRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # task structure
        # dict(Request=dict(Action=None, Params=None),
        #      Response=dict(Status=False, Data=None))
        data = self.request.recv(4096)
        if not data:
            return
        task = json.loads(data.decode("utf-8"))
        if task["Request"]["Action"] == "GetTunnels":
            task = self._handle_get_topo(task)
        elif task["Request"]["Action"] == "GetNodeId":
            task["Response"] = dict(Status=True,
                                    Data=dict(NodeId=str(self.server.sdni.sdn_get_node_id())))
        elif task["Request"]["Action"] == "TunnelRquest":
            task["Response"] = dict(Status=True,
                                    Data="Request shall be considered")
            self.server.sdni.sdn_tunnel_request((task["Request"]["OverlayId"],
                                                 task["Request"]["PeerId"],
                                                 task["Request"]["Operation"])) # op is ADD/REMOVE
        else:
            self.server.sdni.sdn_log("An unrecognized SDNI task request was discarded {0}".
                                     format(task), "LOG_WARNING")
            task["Response"] = dict(Status=False, Data="Unsupported request")
        self.request.sendall(bytes(json.dumps(task) + "\n", "utf-8"))

    def _handle_get_topo(self, task):
        status = False
        topo = self.server.sdni.sdn_get_node_topo()
        if topo:
            status = True
        task["Response"] = dict(Status=status, Data=topo)
        return task

class SDNITCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, host_port_tuple, streamhandler, sdni):
        super().__init__(host_port_tuple, streamhandler)
        self.sdni = sdni

class SDNInterface(ControllerModule):
    def __init__(self, cfx_handle, module_config, module_name):
        super(SDNInterface, self).__init__(cfx_handle, module_config,
                                           module_name)
        self._server = dict()
        self._server_thread = dict()
        self._lock = threading.Lock()
        self._adj_lists = dict()
        self._is_updating = False

    def initialize(self):
        self._cfx_handle.start_subscription("Topology", "TOP_TOPOLOGY_CHANGE")
        for olid in self._cm_config["Overlays"]:
            self._server[olid] = SDNITCPServer(
                (self._cm_config["Overlays"][olid]["SdnListenAddress"],
                 self._cm_config["Overlays"][olid]["SdnListenPort"]), SDNIRequestHandler, self)
            self._server_thread[olid] = threading.Thread(target=self._server[olid].serve_forever,
                                                         name="SDNITCPServer")
            self._server_thread[olid].setDaemon(True)
            self._server_thread[olid].start()
            self._adj_lists[olid] = dict()
        self.register_cbt("Logger", "LOG_INFO", "Module loaded")

    def req_handler_topology_change(self, cbt):
        olid = cbt.request.params["OverlayId"]
        if not olid in self._adj_lists:
            return # not tracking this overlay
        self.register_cbt("LinkManager", "LNK_QUERY_TUNNEL_INFO")
        with self._lock:
            self._is_updating = True
            self._adj_lists[olid] = cbt.request.params["Topology"]
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def resp_handler_tunnel_info(self, cbt):
        if not cbt.response.status:
            self.free_cbt(cbt)
            return
        resp_data = cbt.response.data
        discard = []
        with self._lock:
            for olid in self._adj_lists:
                for peer_id in self._adj_lists[olid]:
                    tnlid = self._adj_lists[olid][peer_id]["edge_id"]
                    if not resp_data.get(tnlid, None):
                        discard.append((olid, peer_id))
                    else:
                        self._adj_lists[olid][peer_id]["MAC"] = ipoplib.delim_mac_str(
                            resp_data[tnlid]["MAC"])
                        self._adj_lists[olid][peer_id]["PeerMac"] = ipoplib.delim_mac_str(
                            resp_data[tnlid]["PeerMac"])
            for olid, peer_id in discard:
                self._adj_lists[olid].pop(peer_id)
            self._is_updating = False
        self.free_cbt(cbt)

    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "TOP_TOPOLOGY_CHANGE":
                self.req_handler_topology_change(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            if cbt.request.action == "LNK_QUERY_TUNNEL_INFO":
                self.resp_handler_tunnel_info(cbt)
            else:
                parent_cbt = cbt.parent
                cbt_data = cbt.response.data
                cbt_status = cbt.response.status
                self.free_cbt(cbt)
                if (parent_cbt is not None and parent_cbt.child_count == 1):
                    parent_cbt.set_response(cbt_data, cbt_status)
                    self.complete_cbt(parent_cbt)

    def timer_method(self):
        pass

    def terminate(self):
        for olid in self._cm_config["Overlays"]:
            self._server[olid].shutdown()
            self._server[olid].server_close()

    def sdn_log(self, msg, level="LOG_DEBUG"):
        self.register_cbt("Logger", level, msg)

    def sdn_get_node_id(self):
        return self.node_id

    def sdn_get_node_topo(self):
        tries = 0
        topo = None
        self._lock.acquire()
        while self._is_updating and tries < 3:
            tries += 1
            self._lock.release()
            time.sleep(1)
            self._lock.acquire()
        if tries == 3:
            self._lock.release()
            return topo
        topo = self._adj_lists
        self._lock.release()
        return topo

    def sdn_tunnel_request(self, peer):
        self.register_cbt("Topology", "TOP_REQUEST_OND_TUNNEL", peer)
