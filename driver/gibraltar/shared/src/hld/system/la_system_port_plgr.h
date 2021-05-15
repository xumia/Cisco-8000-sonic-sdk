// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_SYSTEM_PORT_PLGR_H__
#define __LA_SYSTEM_PORT_PLGR_H__

#include "la_system_port_akpg.h"

namespace silicon_one
{

class la_system_port_plgr : public la_system_port_akpg
{
public:
    explicit la_system_port_plgr(const la_device_impl_wptr& device);
    ~la_system_port_plgr() override;

    la_status configure_pif_source_pif_table(npl_ifg0_ssp_mapping_table_value_t value, la_uint_t pif) override;
    la_status erase_pif_source_pif_table_entry(la_uint_t pif) override;

    la_status configure_ibm_command(la_uint_t ibm_cmd,
                                    la_uint_t sampline_rate,
                                    bool mirror_to_dest,
                                    la_uint_t voq_offset) const override;

    la_status program_stack_control_traffic_voq_mapping(const la_voq_set_wptr& voq_set) const override;

protected:
    la_status teardown_tm_tables() override;
    la_status set_tc_profile_core(const la_tc_profile_wcptr& tc_profile) override;
    virtual size_t get_slice_system_port_value(la_uint_t pif) = 0;
};

} // namespace silicon_one

#endif // __LA_SYSTEM_PORT_PLGR_H__
