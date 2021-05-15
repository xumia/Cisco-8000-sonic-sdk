# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


from leaba import sdk
from sdk_test_case_base import *
import decor

MC_GROUP_GID = 1


@unittest.skipUnless(decor.is_gibraltar(), "Relevant to GB only")
class test_large_cud_map_id(sdk_test_case_base):

    def setUp(self):
        super().setUp()

        self.mc_groups = []
        for i in range(12250):
            mcg = self.device.create_ip_multicast_group(MC_GROUP_GID + i, sdk.la_replication_paradigm_e_EGRESS)
            mcg.add(
                self.topology.tx_svi.hld_obj,
                self.topology.tx_l2_ac_port_reg.hld_obj,
                self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)
            self.mc_groups.append(mcg)

    def test_removal(self):
        for mcg in self.mc_groups:
            mcg.remove(self.topology.tx_svi.hld_obj, self.topology.tx_l2_ac_port_reg.hld_obj)


if __name__ == '__main__':
    unittest.main()
