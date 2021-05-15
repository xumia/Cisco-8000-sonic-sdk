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

#ifndef __HLD_SERIALIZATION_H__
#define __HLD_SERIALIZATION_H__

#include "npu/la_acl_generic.h"

namespace silicon_one
{

template <class Archive, typename ACL_TRAIT>
void
save(Archive& ar, const la_acl_generic<ACL_TRAIT>& acl_gen)
{
    acl_gen.save_impl(ar);
}
template <class Archive, typename ACL_TRAIT>
void
load(Archive& ar, la_acl_generic<ACL_TRAIT>& acl_gen)
{
    acl_gen.load_impl(ar);
}

// This struct is needed for cereal to instantiate all the used types of la_acl_generic
struct all_acl_generic_types {
    la_acl_generic<acl_ingress_rtf_eth_db1_160_f0_trait> _acl_ingress_rtf_eth_db1_160_f0;
    la_acl_generic<acl_ingress_rtf_eth_db2_160_f0_trait> _acl_ingress_rtf_eth_db2_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db1_160_f0_trait> _acl_ingress_rtf_ipv4_db1_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db2_160_f0_trait> _acl_ingress_rtf_ipv4_db2_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db3_160_f0_trait> _acl_ingress_rtf_ipv4_db3_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db4_160_f0_trait> _acl_ingress_rtf_ipv4_db4_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db1_320_f0_trait> _acl_ingress_rtf_ipv4_db1_320_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db2_320_f0_trait> _acl_ingress_rtf_ipv4_db2_320_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db3_320_f0_trait> _acl_ingress_rtf_ipv4_db3_320_f0;
    la_acl_generic<acl_ingress_rtf_ipv4_db4_320_f0_trait> _acl_ingress_rtf_ipv4_db4_320_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db1_160_f0_trait> _acl_ingress_rtf_ipv6_db1_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db2_160_f0_trait> _acl_ingress_rtf_ipv6_db2_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db3_160_f0_trait> _acl_ingress_rtf_ipv6_db3_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db4_160_f0_trait> _acl_ingress_rtf_ipv6_db4_160_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db1_320_f0_trait> _acl_ingress_rtf_ipv6_db1_320_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db2_320_f0_trait> _acl_ingress_rtf_ipv6_db2_320_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db3_320_f0_trait> _acl_ingress_rtf_ipv6_db3_320_f0;
    la_acl_generic<acl_ingress_rtf_ipv6_db4_320_f0_trait> _acl_ingress_rtf_ipv6_db4_320_f0;
};

} // namespace silicon_one
#endif // __HLD_SERIALIZATION_H
