// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __SAI_NEXT_HOP_H__
#define __SAI_NEXT_HOP_H__

extern "C" {
#include <sai.h>
}

#include "api/types/la_mpls_types.h"
#include "api/npu/la_l2_service_port.h"

#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{
class next_hop_entry
{
public:
    la_obj_wrap<la_next_hop> next_hop;
    sai_next_hop_type_t type = SAI_NEXT_HOP_TYPE_IP;
    sai_ip_address_t ip_addr{};
    sai_object_id_t rif_tun_oid = SAI_NULL_OBJECT_ID; // RIF or TUNNEL
    la_mpls_label_vec_t m_labels;                     // For SAI_NEXT_HOP_TYPE_MPLS
    la_obj_wrap<la_prefix_object> m_prefix_object;

    // tunnel next hop, TODO la next hop id/gid holes by tunnel next hop
    la_obj_wrap<la_l2_service_port> m_vxlan_port;
    sai_mac_t m_tunnel_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t m_encap_vni = 0;

    bool has_mpls_labels()
    {
        return m_labels.size() != 0;
    }

    next_hop_entry()
    {
    }

    next_hop_entry(la_next_hop* nh, sai_next_hop_type_t t, sai_ip_address_t ipaddr) : next_hop(nh), type(t), ip_addr(ipaddr)
    {
    }

    explicit next_hop_entry(sai_next_hop_type_t t) : type(t)
    {
    }
};
}
}
#endif
