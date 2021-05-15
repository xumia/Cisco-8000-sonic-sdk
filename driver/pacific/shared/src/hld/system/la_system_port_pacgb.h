// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __LA_SYSTEM_PORT_PACGB_H__
#define __LA_SYSTEM_PORT_PACGB_H__

#include "la_system_port_base.h"

#include <sstream>

namespace silicon_one
{

class la_system_port_pacgb : public la_system_port_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_system_port_pacgb(const la_device_impl_wptr& device);
    ~la_system_port_pacgb() override;

    la_status initialize_for_pci(la_object_id_t oid,
                                 const la_pci_port_wptr& pci_port,
                                 la_system_port_gid_t gid,
                                 const la_voq_set_wptr& voq_set,
                                 const la_tc_profile_wcptr& tc_profile) override;

    la_status set_source_pif_table(npl_source_pif_hw_table_value_t value);
    la_status configure_pif_source_pif_table(npl_source_pif_hw_table_value_t value, la_uint_t pif);
    la_status configure_port_extender_map_rx_data_table(npl_source_pif_hw_table_value_t value);

    la_status erase_pif_source_pif_table_entry(la_uint_t pif) override;
    la_status erase_port_extender_map_rx_data_table() override;

protected:
    la_system_port_pacgb() = default;
    la_status program_voq_mapping(const la_voq_set_wptr& voq_set, bool is_lp) const override;

    la_status configure_ibm_command(la_uint_t ibm_cmd,
                                    la_uint_t sampline_rate,
                                    bool mirror_to_dest,
                                    la_uint_t voq_offset) const override;

    la_status program_stack_control_traffic_voq_mapping(const la_voq_set_wptr& voq_set) const override;
    la_status teardown_tm_tables() override;
    la_status set_tc_profile_core(const la_tc_profile_wcptr& tc_profile) override;
    virtual la_status set_tc_profile_core_ect(const la_tc_profile_wcptr& tc_profile) = 0;
    virtual la_status teardown_tm_tables_ect() = 0;
};

} // namespace silicon_one

#endif // __LA_SYSTEM_PORT_PACGB_H__
