// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_ETHERNET_PORT_AKPG_H__
#define __LA_ETHERNET_PORT_AKPG_H__

#include "la_ethernet_port_base.h"

namespace silicon_one
{

class la_ethernet_port_akpg : public la_ethernet_port_base
{
public:
    explicit la_ethernet_port_akpg(const la_device_impl_wptr& device);
    ~la_ethernet_port_akpg() override;
    la_status set_service_mapping_type(service_mapping_type_e type) override;
    la_status set_security_group_tag(la_sgt_t sgt) override;
    la_status get_security_group_tag(la_sgt_t& out_sgt) const override;
    la_status set_security_group_policy_enforcement(bool enforcement) override;
    la_status get_security_group_policy_enforcement(bool& out_enforcement) const override;
    la_status configure_security_group_policy_attributes() override;

private:
    la_status update_npp_sgt_attributes();
    la_status update_dsp_sgt_attributes();
    la_status set_source_pif_entry(const la_ac_profile_impl* ac_profile) override;
    la_status erase_source_pif_entry() override;
    npl_mac_af_npp_attributes_table_t::value_type populate_mac_af_npp_attributes() const override;
};

} // namespace silicon_one

#endif // __LA_ETHERNET_PORT_AKPG_H__
