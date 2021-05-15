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

#include "sai_device.h"
#include "sai_db.h"
#include "sai_logger.h"
#include "sai_utils.h"

using namespace silicon_one;
using namespace silicon_one::sai;

sai_status_t
sai_get_maximum_attribute_count(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t* count)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_get_object_count(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t* count)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_per_obj_info[object_type]) {
        return sdev->m_per_obj_info[object_type]->get_object_count(sdev, count);
    } else {
        // Upper layer expects us to implement this for all object types
        // For now, return count=0 for objects with no implementation
        *count = 0;
        return SAI_STATUS_SUCCESS;
    }
}

sai_status_t
sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t* object_count, sai_object_key_t* object_list)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto ext_info = sdev->m_per_obj_info[object_type];
    if (ext_info) {
        return ext_info->get_object_keys(sdev, object_count, object_list);
    } else {
        // Upper layer expects us to implement this for all object types
        // For now, return empty object list for objects with no implementation
        *object_count = 0;
        return SAI_STATUS_SUCCESS;
    }
}

sai_status_t
sai_bulk_get_attribute(sai_object_id_t switch_id,
                       sai_object_type_t object_type,
                       uint32_t object_count,
                       const sai_object_key_t* object_key,
                       uint32_t* attr_count,
                       sai_attribute_t** attr_list,
                       sai_status_t* object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_query_attribute_capability(sai_object_id_t switch_id,
                               sai_object_type_t object_type,
                               sai_attr_id_t attr_id,
                               sai_attr_capability_t* attr_capability)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();
    sai_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", switch_id);

    if (!attr_capability) {
        sai_log_error(SAI_API_SWITCH, "NULL value attr_capability");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    attr_capability->create_implemented = false;
    attr_capability->set_implemented = false;
    attr_capability->get_implemented = false;

    const sai_attribute_entry_t* attrib_entry = obj_type_attr_info_get(object_type);

    if (attrib_entry == nullptr) {
        sai_log_error(SAI_API_SWITCH, "Could not find attribute_entry array for type %d", object_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    while (attrib_entry->id != END_FUNCTIONALITY_ATTRIBS_ID) {
        if (attrib_entry->id == attr_id) {
            break;
        }
        attrib_entry++;
    }

    if (attrib_entry->id == END_FUNCTIONALITY_ATTRIBS_ID) {
        sai_log_error(SAI_API_SWITCH, "Could not find attribute_entry line for type %d attr_id %d", object_type, attr_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    attr_capability->create_implemented = attrib_entry->valid_for_create;
    attr_capability->set_implemented = attrib_entry->valid_for_set;
    attr_capability->get_implemented = attrib_entry->valid_for_get;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_query_attribute_enum_values_capability(sai_object_id_t switch_id,
                                           sai_object_type_t object_type,
                                           sai_attr_id_t attr_id,
                                           sai_s32_list_t* enum_values_capability)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();
    sai_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", switch_id);

    if (object_type == SAI_OBJECT_TYPE_DEBUG_COUNTER) {
        return sdev->m_debug_counter_handler->query_attribute_enum_values_capability(attr_id, enum_values_capability);
    }

    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_object_type_get_availability(_In_ sai_object_id_t switch_id,
                                 _In_ sai_object_type_t object_type,
                                 _In_ uint32_t attr_count,
                                 _In_ const sai_attribute_t* attr_list,
                                 _Out_ uint64_t* count)
{
    return SAI_STATUS_NOT_SUPPORTED;
}

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
sai_status_t
sai_query_stats_capability(_In_ sai_object_id_t switch_id,
                           _In_ sai_object_type_t object_type,
                           _Inout_ sai_stat_capability_list_t* stats_capability)
{
    return SAI_STATUS_NOT_SUPPORTED;
}
#endif
