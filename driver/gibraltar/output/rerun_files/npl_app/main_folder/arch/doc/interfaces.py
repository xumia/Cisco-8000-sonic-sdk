# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

import json
import os


def getJson(fname):
    jsonFile = open(fname)
    outFile = open("arch/doc/databases_temp.json", "w+")

    for line in jsonFile:
        line = line.split('//')[0]
        outFile.write(line)

    jsonFile = open("arch/doc/databases_temp.json")
    outFile = open("arch/doc/databases.txt", "w+")

    jsonData = json.load(jsonFile)
    os.system("rm arch/doc/databases_temp.json")

    return jsonData["hw_definitions"]["engines"]


class Interface:
    def __init__(self):
        self.name = None
        self.engine = None
        self.db_type = None
        self.size = 0
        self.incomingInterface = []
        self.keyWidth = 0


class Interfaces:

    def __init__(self, fname):
        interfaceJson = getJson(fname)
        self.interfaces = []
        self.interfaceJson = {}

        for engine in interfaceJson:

            if "outgoing_interfaces" in interfaceJson[engine]:
                for interfaceName in interfaceJson[engine]["outgoing_interfaces"]:
                    interface = Interface()
                    interface.displayName = interfaceName + "." + engine
                    interface.name = self.changeName(interface.displayName)
                    interface.engine = engine
                    interface.size = str(interfaceJson[engine]["outgoing_interfaces"][interfaceName]["key_width"])
                    interface.db_type = interfaceJson[engine]["outgoing_interfaces"][interfaceName]["db_type"]
                    for incomingInterface in interfaceJson[engine]["outgoing_interfaces"][interfaceName]["incoming_interfaces"]:
                        interface.incomingInterface.append(incomingInterface)
                    self.interfaces.append(interface)
                    self.interfaceJson[interface.name] = interface

    def changeName(self, tableName):
        self.mappingTable = {
            "Palladium": {
                "OUTGOING_EGRESS_SMALL_EM_COMPOUND.transmit": "OUTGOING_EGRESS_ENC_EM1.transmit",
                "OUTGOING_EGRESS_DIRECT0_COMPOUND.transmit": "OUTGOING_EGRESS_ENC_EM4.transmit",
                "OUTGOING_EGRESS_L3_DLP0_COMPOUND.transmit": "OUTGOING_EGRESS_ENC_EM3.transmit",
                "OUTGOING_EGRESS_LARGE_EM_COMPOUND.transmit": "OUTGOING_EGRESS_ENC_EM0.transmit",
                "OUTGOING_EGRESS_DIP_INDEX_COMPOUND.transmit": "OUTGOING_EGRESS_ENC_EM2.transmit"
            }
        }
        if tableName in self.mappingTable["Palladium"]:
            return self.mappingTable["Palladium"][tableName]
        return tableName

    def matchInterfaces(self, newInterfaces, outFile):
        outFile.write("{0:40.38} {1:10} {2:15} {3:20} {4:40.38} {5:10} {6:15} {7:20} {8:20}\n".format(
            "NP1 IF Name", "Type", "Engine", "Size", "NP2 IF Name", "Type", "Engine", "Size", "Check"))
        outFile.write("{0:40.38} {1:10} {2:15} {3:20} {4:40.38} {5:10} {6:15} {7:20} {8:20}\n".format(
            "===========", "====", "======", "====", "===========", "====", "======", "====", "====="))
        for oldIntf in self.interfaces:
            if oldIntf.name in newInterfaces.interfaceJson:
                newIntf = newInterfaces.interfaceJson[oldIntf.name]
                if newIntf.size >= oldIntf.size and newIntf.engine == oldIntf.engine:
                    check = "Match"
                else:
                    check = "Mismatch"
                outFile.write(
                    "{0:40.38} {1:10} {2:15} {3:20} {4:40.38} {5:10} {6:15} {7:20} {8:20}\n".format(
                        oldIntf.displayName,
                        oldIntf.db_type,
                        oldIntf.engine,
                        oldIntf.size,
                        newIntf.displayName,
                        newIntf.db_type,
                        newIntf.engine,
                        newIntf.size,
                        check))
            else:
                outFile.write("{0:40.38} {1:10} {2:15} {3:20} {4:40.38} {5:10} {6:15} {7:20} {8:20}\n".format(
                    oldIntf.displayName, oldIntf.db_type, oldIntf.engine, oldIntf.size, "", "", "", "", "NO MATCH"))

        for newIntf in newInterfaces.interfaces:
            if newIntf.name not in self.interfaceJson:
                outFile.write("{0:40.38} {1:10} {2:15} {3:20} {4:40.38} {5:10} {6:15} {7:20} {8:20}\n".format(
                    "", "", "", "", newIntf.displayName, newIntf.db_type, newIntf.engine, newIntf.size, "NO MATCH"))


oldInterfaces = Interfaces("../../devices/pacific/leaba_defined/hw_definitions/hw_definitions.json")

newInterfaces = Interfaces(
    "../../devices/akpg/palladium/leaba_defined/hw_definitions/palladium_databases_definitions.json")

outFile = open("arch/doc/interfaces_match.txt", "w+")

oldInterfaces.matchInterfaces(newInterfaces, outFile)
