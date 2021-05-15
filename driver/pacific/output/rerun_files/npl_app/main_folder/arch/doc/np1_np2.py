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


def peekJson(name, jsonData):
    for field in jsonData:
        fieldName = field.partition(' ')[0]
        if "np2" in field:

            inName = name.replace('.metadata.pd.', '').replace('(union).', '', 5)
            inName = inName.replace('rx_tx_npu_host.rx.rx_nw_or_fabric', "Rx")
            inName = inName.replace('rx_tx_npu_host.rx', "Rx")
            inName = inName.replace('npu_header_or_ene_data.npu_header_cont.', '')
            inName = inName.replace('rx_tx_npu_host.tx_npu_host.tx_npu_host_u.tx', 'Tx')
            inName = inName.replace('rx_tx_npu_host.tx_npu_host', 'Tx')
            inName = inName.replace('pd_rx_tx_npu_host_u.pd_rx_tx_common_leaba.', '')
            outName = ""
            outMethod = ""
            outComment = ""
            if "name" in jsonData["np2"]:
                outName = jsonData["np2"]["name"]
            if "size" in jsonData["np2"]:
                outSize = str(jsonData["np2"]["size"])
            if "method" in jsonData["np2"]:
                outMethod = jsonData["np2"]["method"]
            if "comment" in jsonData["np2"]:
                outComment = jsonData["np2"]["comment"]
            outFile.write("{0:80} {1:70} {2:40} {3:40}\n".format(inName, outName, outMethod, outComment))
        else:
            peekJson(name + '.' + fieldName, jsonData[field])


os.system("pwd")
jsonFile = open("arch/doc/np1_parsed_items.json")
jsonData = json.load(jsonFile)
outFile = open("arch/doc/np1_np2_match.txt", "w+")
outFile.write("{0:80} {1:70} {2:40} {3:40}\n".format("NP1 Name", "NP2 Name", "Method", "Comment"))
outFile.write("{0:80} {1:70} {2:40} {3:40}\n".format("========", "========", "======", "======="))

peekJson('', jsonData)
