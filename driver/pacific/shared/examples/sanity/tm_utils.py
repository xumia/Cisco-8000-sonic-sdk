#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


###
# TM utility functions
###

from leaba import sdk
from sanity_constants import *

SYSTEM_PORT_SPEEDUP = 1.1


def init_system_port_default_tm(la_dev, sys_port, base_voq, base_vsc_vec, underlying_port_speed):
    erm = sdk.get_error_mode()
    sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)

    ingress_device_id = la_dev.get_id()

    port_max_speed = int(SYSTEM_PORT_SPEEDUP * underlying_port_speed)

    sp_sch = sys_port.get_scheduler()
    if sp_sch is None:
        raise Exception('Error: sys_port.get_scheduler failed.')

    sp_sch.set_priority_propagation(False)
    sp_sch.set_logical_port_enabled(False)

    for oqpg in range(8):
        sp_sch.set_oq_priority_group(oqpg, sdk.la_system_port_scheduler.priority_group_e_SP8)
        sp_sch.set_credit_pir(oqpg, port_max_speed)
        sp_sch.set_transmit_pir(oqpg, port_max_speed)
        sp_sch.set_transmit_uc_mc_weight(oqpg, 1, 1)

    for pg in range(sdk.la_system_port_scheduler.priority_group_e_SP8 + 1):
        sp_sch.set_priority_group_credit_cir(pg, port_max_speed)
        sp_sch.set_priority_group_transmit_cir(pg, port_max_speed)
        sp_sch.set_priority_group_eir_weight(pg, 7)

    for oq_id in range(VOQ_SET_SIZE):
        oq_sch = sp_sch.get_output_queue_scheduler(oq_id)
        oq_sch.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_2SP_3WFQ)
        for group in range(4):
            oq_sch.set_group_weight(group, 1)

        for slice_idx in range(len(base_vsc_vec)):
            #                print('init_system_port_default_tm: attach_vsc slice %d: vsc=%d voq=%s' % (slice_idx, base_vsc_vec[slice_idx] + oq_id, base_voq + oq_id))
            if base_vsc_vec[slice_idx] == sdk.LA_VSC_GID_INVALID:
                continue
            oq_sch.attach_vsc(base_vsc_vec[slice_idx] + oq_id,
                              sdk.la_oq_vsc_mapping_e_RR1_RR3,
                              ingress_device_id, slice_idx, base_voq + oq_id)

    sdk.set_error_mode(erm)


# Default TM initialization for MAC/PCI/RCY ports
def init_port_default_tm(port, speed):
    erm = sdk.get_error_mode()
    sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)

    ifc_sch = port.get_scheduler()
    if ifc_sch is None:
        raise Exception('Error: port::get_scheduler failed')

    ifc_sch.set_credit_cir(speed)
    ifc_sch.set_transmit_cir(speed)
    ifc_sch.set_credit_eir_or_pir(speed, False)
    ifc_sch.set_transmit_eir_or_pir(speed, False)
    ifc_sch.set_cir_weight(1)
    ifc_sch.set_eir_weight(1)
    sdk.set_error_mode(erm)


def init_default_tm(la_dev):
    ifg_speed = 985 * GIGA
    txpdr_port_speed = 100 * GIGA

    erm = sdk.get_error_mode()
    sdk.set_error_mode(sdk.error_mode_e_EXCEPTION)

    for slice_id in range(NUM_SLICES_PER_DEVICE):
        for ifg_id in range(NUM_IFGS_PER_SLICE):
            ifg_sch = la_dev.get_ifg_scheduler(slice_id, ifg_id)
            if ifg_sch is None:
                raise Exception('Error: get_ifg_scheduler failed.')

            ifg_sch.set_credit_rate(ifg_speed)
            ifg_sch.set_credit_burst_size(16)
            ifg_sch.set_transmit_rate(ifg_speed)
            ifg_sch.set_transmit_burst_size(16)

            ifg_sch.set_txpdr_cir(txpdr_port_speed)
            ifg_sch.set_txpdr_eir_or_pir(txpdr_port_speed, False)
            ifg_sch.set_txpdr_cir_weight(1)
            ifg_sch.set_txpdr_eir_weight(1)

    sdk.set_error_mode(erm)
