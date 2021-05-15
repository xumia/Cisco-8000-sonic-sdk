// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

// -----------------------------------------
// Some portions are also:
//
// Copyright (C) 2014 Mellanox Technologies, Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License); You may
// Obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//
// -----------------------------------------
//

#include "sai_scheduler_group.h"

#include <cassert>
#include "api/system/la_device.h"
#include "common/gen_utils.h"
#include "common/ranged_index_generator.h"
#include "sai_config_parser.h"
#include "sai_constants.h"
#include "sai_device.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

// clang-format off

static const sai_attribute_entry_t sch_group_attribs[] = {
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t sch_group_vendor_attribs[] = {
};

// clang-format on

sai_status_t
laobj_db_scheduler_group::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    // TODO
    uint32_t num = 0;
    *count = num;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_scheduler_group::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                          uint32_t* object_count,
                                          sai_object_key_t* object_list) const
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_sch_group_attribute(sai_object_id_t obj_port_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_port_id;

    snprintf(key_str, MAX_KEY_STR_LEN, "port 0x%0lx", obj_port_id);
    return sai_set_attribute(&key, key_str, sch_group_attribs, sch_group_vendor_attribs, attr);
}

static sai_status_t
get_sch_group_attribute(sai_object_id_t obj_port_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_port_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);

    snprintf(key_str, MAX_KEY_STR_LEN, "port 0x%0lx", obj_port_id);
    return sai_get_attributes(&key, key_str, sch_group_attribs, sch_group_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_sch_group(sai_object_id_t* out_sch_grp_id,
                 sai_object_id_t obj_switch_id,
                 uint32_t attr_count,
                 const sai_attribute_t* attr_list)
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_sch_group(sai_object_id_t obj_sch_grp_id)
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

const sai_scheduler_group_api_t sch_group_api
    = {create_sch_group, remove_sch_group, set_sch_group_attribute, get_sch_group_attribute};
}
}
