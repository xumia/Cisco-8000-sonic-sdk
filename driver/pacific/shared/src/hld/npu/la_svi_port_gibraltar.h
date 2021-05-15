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

#ifndef __LA_SVI_PORT_GIBRALTAR_H__
#define __LA_SVI_PORT_GIBRALTAR_H__

#include "npu/la_svi_port_base.h"

namespace silicon_one
{

class la_svi_port_gibraltar : public la_svi_port_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_svi_port_gibraltar(const la_device_impl_wptr& device);
    ~la_svi_port_gibraltar() override;

    virtual la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    virtual la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    la_status update_additional_l3_lp_attributes(const npl_l3_lp_additional_attributes_t& additional_attribs) override;

private:
    la_svi_port_gibraltar() = default; // Needed for cereal
    // SVI egress flood
    virtual la_status populate_recycled_inject_up_info_table(const la_l2_service_port_base_wptr& inject_up_port) override;
    la_status clear_recycled_inject_up_info_table() override;

    // NPL key population
    void fill_npl_mac_termination_em_table_key(la_switch_gid_t sw_gid,
                                               const la_mac_addr_t& mac_addr,
                                               uint64_t prefix,
                                               npl_mac_termination_em_table_key_t& out_key) override;
};
}

#endif // __LA_SVI_PORT_GIBRALTAR_H__
