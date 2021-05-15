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

    return jsonData["hw_definitions"]["external_databases"]


class Table:
    def __init__(self):
        self.name = None
        self.db_type = None
        self.sizes = []

    def __str__(self):
        return("{0:60} {1:20} {2:20}".format(self.name, self.db_type, str(self.sizes[0:4])))


class Tables:
    def __init__(self, fname):
        tableJson = getJson(fname)

        self.tables = []
        self.tableJson = {}
        for tableName in tableJson:
            table = Table()
            table.name = self.changeName(tableName)
            table.displayName = tableName
            table.db_type = tableJson[tableName]["db_type"]
            for size in tableJson[tableName]["sizes"]:
                table.sizes.append((size["key_width"], size["payload_width"]))
            self.tables.append(table)
            self.tableJson[table.name] = table

    def printTables(self):
        for table in self.tables:
            print(table)

    def changeName(self, tableName):
        self.mappingTable = {
            "Palladium": {
                "EXTERNAL_EGRESS_DIP_INDEX": "EXTERNAL_EGRESS_ENC_EM2",
                "EXTERNAL_EGRESS_DIRECT0": "EXTERNAL_EGRESS_ENC_EM4",
                "EXTERNAL_EGRESS_L3_DLP0": "EXTERNAL_EGRESS_ENC_EM3",
                "EXTERNAL_EGRESS_LARGE_EM": "EXTERNAL_EGRESS_ENC_EM0",
                "EXTERNAL_EGRESS_SMALL_EM": "EXTERNAL_EGRESS_ENC_EM1"
            }
        }
        if tableName in self.mappingTable["Palladium"]:
            return self.mappingTable["Palladium"][tableName]
        return tableName

    def mergeTables(self, newTables, outFile):
        outFile.write("{0:40.38} {1:10} {2:30} {3:40.38} {4:10} {5:27.25} {6:40}\n".format(
            "NP1 Table", "Type", "Sizes", "NP2 Table", "Type", "Sizes", "Check"))
        outFile.write("{0:40.38} {1:10} {2:30} {3:40.38} {4:10} {5:27.25} {6:40}\n".format(
            "=========", "====", "=====", "=========", "====", "=====", "====="))
        self.tables = sorted(self.tables, key=lambda t: t.name)
        for table in self.tables:
            if table.name in newTables.tableJson:
                newTable = newTables.tableJson[table.name]
                if table.db_type != newTable.db_type and not (table.db_type == "direct" and newTable.db_type == "em"):
                    check = "DB type mismatch"
                else:
                    check = "MATCH"
                    for size in table.sizes:
                        found = False
                        for newSize in newTable.sizes:
                            if newSize[0] >= size[0] and newSize[1] >= size[1]:
                                found = True
                        if not found:
                            check = "No size match found {0}".format(size)
                outFile.write(
                    "{0:40.38} {1:10} {2:30.25} {3:40.38} {4:10} {5:27.25} {6:40}\n".format(
                        table.displayName, table.db_type, str(
                            table.sizes), newTable.displayName, newTable.db_type, str(
                            newTable.sizes), check))
            else:
                outFile.write("{0:40.38} {1:10} {2:30.25} {3:40.38} {4:10} {5:27.25} {6:40}\n".format(
                    table.displayName, table.db_type, table.sizes, "", "", "", "NOT FOUND"))

        for newTable in newTables.tables:
            if newTable.name not in self.tableJson:
                outFile.write("{0:40.38} {1:10} {2:30.25} {3:40.38} {4:10} {5:27.25} {6:40}\n".format(
                    "", "", "", newTable.displayName, newTable.db_type, newTable.sizes, "NOT FOUND"))


oldTables = Tables("../../devices/pacific/leaba_defined/hw_definitions/hw_definitions.json")

newTables = Tables("../../devices/akpg/palladium/leaba_defined/hw_definitions/palladium_databases_definitions.json")

outFile = open("arch/doc/database_match.txt", "w+")

oldTables.mergeTables(newTables, outFile)
