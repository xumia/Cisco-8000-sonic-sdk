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

#ifndef __SAI_NEXT_HOP_GROUP_H__
#define __SAI_NEXT_HOP_GROUP_H__

#include <string>
#include <memory>
#include <set>

extern "C" {
#include <sai.h>
}

#include "api/npu/la_ecmp_group.h"
#include "la_sai_object.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{
class next_hop_group_member
{
    friend class lsai_next_hop_group;

public:
    next_hop_group_member()
    {
    }

    next_hop_group_member(sai_object_id_t nh_oid, sai_object_id_t group_oid) : m_nexthop_oid(nh_oid), m_group_oid(nh_oid)
    {
    }

public:
    sai_object_id_t m_nexthop_oid = 0;
    sai_object_id_t m_group_oid = 0;
    sai_uint32_t m_weight = 1; // SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT
};

class lsai_next_hop_group
{
public:
    lsai_next_hop_group()
    {
    }

    lsai_next_hop_group(la_ecmp_group* ecmp_ptr) : m_ecmp_group(ecmp_ptr)
    {
    }

public:
    la_obj_wrap<la_ecmp_group> m_ecmp_group;
    std::set<sai_object_id_t> m_members;
};
}
}
#endif
