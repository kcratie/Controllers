from time import sleep
import importlib
import unittest
from unittest.mock import MagicMock, Mock, patch
from controller.framework.CBT import CBT
from controller.framework.CFx import CFX
import controller.framework.Modlib as modlib

from controller.modules.BridgeController import BridgeController, VNIC, OvsBridge, LinuxBridge, BoundedFloodProxy, BFRequestHandler, BridgeFactory


class BridgeControllerTest(unittest.TestCase):
    module = BridgeController
    controller_module_config = {
        "BridgeController": {
            "Enabled": True,
            "BoundedFlood": {
                "OverlayId": "A0FB389",
                "LogDir": ".",
                "LogFilename": "bf.log",
                "LogLevel": "INFO",
                "BridgeName": "edgbr",
                "DemandThreshold": "100M",
                "FlowIdleTimeout": 60,
                "FlowHardTimeout": 60,
                "MulticastBroadcastInterval": 60,
                "MaxBytes": 10000000,
                "BackupCount": 0,
                "ProxyListenAddress": "",
                "ProxyListenPort": 5802,
                "MonitorInterval": 60,
                "MaxOnDemandEdges": 0
            },
            "Overlays": {
                "A0FB387": {
                    "NetDevice": {
                        "AutoDelete": False,
                        "Type": "VNIC",
                        "MTU": 1410,
                        "IP4": "10.10.10.1",
                        "PrefixLen": 24,
                    },
                    "SwitchProtocol": "Leaf",
                },
                "A0FB388": {
                    "NetDevice": {
                        "AutoDelete": True,
                        "Type": "LXBR",
                        "NamePrefix": "ipopbr",
                        "MTU": 1410,
                    },
                    "SwitchProtocol": "STP",
                },
                "A0FB389": {
                    "NetDevice": {
                        "AutoDelete": True,
                        "Type": "OVS",
                        "SwitchProtocol": "BF",
                        "NamePrefix": "edgbr",
                        "MTU": 1410,
                        "AppBridge": {
                            "AutoDelete": True,
                            "Type": "OVS",
                            "NamePrefix": "brl",
                            "IP4": "10.10.100.2",
                            "PrefixLen": 24,
                            "MTU": 1410,
                            "NetworkAddress": "10.10.100.0/24"
                        }
                    },
                    "SDNController": {
                        "ConnectionType": "tcp",
                        "HostName": "127.0.0.1",
                        "Port": "6633"
                    }
                }
            }
        },
        "NodeId": "1234434323"
    }
    @property
    def mod_config(self):
        return self.controller_module_config[self.module.__name__]

    def create_cm_instance(self):
        """
        Setup the variables and the mocks required by the unit tests.
        :return: The Controller Module object and signal dictionary
        """
        cfx_handle = Mock()
        module = importlib.import_module("controller.modules.{0}"
                                         .format(self.module.__name__))
        module_class = getattr(module, self.module.__name__)

        cm = module_class(cfx_handle, self.mod_config, self.module.__name__)
        cfx_handle._cm_instance = cm
        cfx_handle._cm_config = self.mod_config
        return cm
        
    # def test1_bridge_factory(self):
    #     olid = "A0FB387"
    #     vn = BridgeFactory(olid,
    #                        self.mod_config["Overlays"][olid]["NetDevice"]["Type"],
    #                        self.mod_config["Overlays"][olid],
    #                        self)
    #     assert vn.bridge_type == VNIC.bridge_type
    #     olid = "A0FB388"
    #     lx_br = BridgeFactory(olid,
    #                           self.mod_config["Overlays"][olid]["NetDevice"]["Type"],
    #                           self.mod_config["Overlays"][olid],
    #                           self)
    #     assert lx_br.bridge_type == LinuxBridge.bridge_type
    #     olid = "A0FB389"
    #     ovs_br = BridgeFactory(olid,
    #                            self.mod_config["Overlays"][olid]["NetDevice"]["Type"],
    #                            self.mod_config["Overlays"][olid],
    #                            self)
    #     assert ovs_br.bridge_type == OvsBridge.bridge_type
    #     print("Passed : test1_bridge_factory")

    # def test2_ovs_add_del_port(self):
    #     olid = "A0FB389"
    #     tap_name = "tap01"
    #     ovs_br = BridgeFactory(olid,
    #                            self.mod_config["Overlays"][olid]["NetDevice"]["Type"],
    #                            self.mod_config["Overlays"][olid],
    #                            self)
    #     ovs_br.add_port(tap_name)
    #     ovs_br.del_port(tap_name)
    #     print("Passed : test2_ovs_add_del_port")

    # def test3_lxbr_add_del_port(self):
    #     olid = "A0FB388"
    #     tap_name = "tap02"
    #     lxbr = BridgeFactory(olid,
    #                            self.mod_config["Overlays"][olid]["NetDevice"]["Type"],
    #                            self.mod_config["Overlays"][olid],
    #                            self)
    #     lxbr.add_port(tap_name)
    #     lxbr.del_port(tap_name)
    #     print("Passed : test3_lxbr_add_del_port")

    def test4_bridgecontroller_start_stop(self):
        br_mod = self.create_cm_instance()
        br_mod.initialize()
        print("Passed : test4 bridgecontroller_start")
        sleep(10)
        br_mod.terminate()
        print("Passed : test4 bridgecontroller_stop")

             
if __name__ == '__main__':
    unittest.main()
