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

#!/usr/bin/env python3

from sai_topology import sai_topology
import saicli as S


class voq_topology(sai_topology):
    def __init__(self, st_base, ip_type):
        sai_topology.__init__(self, st_base, ip_type)

    def configure_two_port_no_sp_topology(self):
        self.tb.configure_ports([self.in_port_cfg, self.out_port_cfg])

    def deconfigure_two_port_no_sp_topology(self):
        self.tb.remove_ports()

    def configure_two_sp_topology(self):
        # In a VOQ switch, now configure system ports for the front
        # panel ports that were created.
        sp_cfgs = [self.port_cfg.in_sys_port_cfg, self.port_cfg.out_sys_port_cfg]
        for sp_cfg in sp_cfgs:
            self.tb.create_system_port(sp_cfg)

    def deconfigure_two_sp_topology(self):
        # Deconfigure the front-panel system ports
        for sp_oid in self.tb.get_fp_system_ports():
            self.tb.remove_object(sp_oid)
