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

#include "api/system/la_device.h"
#include "sai_device.h"
#include "la_sai_object.h"
#include "sai_stats_shadow.h"

namespace silicon_one
{
namespace sai
{

static sai_status_t buffer_profile_attr_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t buffer_profile_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static lsai_stats_shadow<la_device::la_cgm_watermarks> cgm_watermarks_shadow;
static lsai_stats_shadow<la_uint64_t> curr_occ_bytes_shadow;

static sai_uint32_t
get_egress_dynamic_buffer_pool_size(lsai_object obj)
{
    auto sdev = obj.get_device();

    if (sdev->m_hw_device_type == hw_device_type_e::PACIFIC) {
        return (MAX_SAI_EGRESS_BUFFER_POOL_SIZE_PA);
    }
    if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        return (MAX_SAI_EGRESS_BUFFER_POOL_SIZE_GB);
    }
    return 0;
}

static sai_status_t
buffer_pool_attr_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_buf_pool(key->key.object_id);
    if (la_buf_pool.type != SAI_OBJECT_TYPE_BUFFER_POOL) {
        sai_log_error(SAI_API_BUFFER, "Invalid buffer pool for get attribute 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sdev = la_buf_pool.get_device();

    switch ((int64_t)arg) {
    case SAI_BUFFER_POOL_ATTR_SHARED_SIZE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_SHARED_SIZE, *value, get_egress_dynamic_buffer_pool_size(la_buf_pool));
        break;
    case SAI_BUFFER_POOL_ATTR_TYPE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_TYPE, *value, SAI_BUFFER_POOL_TYPE_EGRESS);
        break;
    case SAI_BUFFER_POOL_ATTR_SIZE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_SIZE, *value, get_egress_dynamic_buffer_pool_size(la_buf_pool));
        break;
    case SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, *value, SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC);
        break;
    case SAI_BUFFER_POOL_ATTR_TAM:
        value->objlist.count = 0;
        break;
    case SAI_BUFFER_POOL_ATTR_XOFF_SIZE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_XOFF_SIZE, *value, 0);
        break;
    case SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID:
        set_attr_value(SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID, *value, SAI_NULL_OBJECT_ID);
        break;
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
buffer_pool_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_SUCCESS;
}

// clang format-off
static const sai_attribute_entry_t buffer_pool_attribs[]
    = {{SAI_BUFFER_POOL_ATTR_SHARED_SIZE, false, false, true, true, "Buffer pool shared size", SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_POOL_ATTR_TYPE, true, true, true, true, "Buffer pool type", SAI_ATTR_VAL_TYPE_U8},
       {SAI_BUFFER_POOL_ATTR_SIZE, true, true, true, true, "Buffer pool size", SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, false, true, true, true, "Buffer pool threshold mode", SAI_ATTR_VAL_TYPE_U8},
       {SAI_BUFFER_POOL_ATTR_TAM, false, true, true, true, "Buffer pool TAM id", SAI_ATTR_VAL_TYPE_OID},
       {SAI_BUFFER_POOL_ATTR_XOFF_SIZE, false, true, true, true, "Buffer pool shared headroom pool size", SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID, false, true, true, true, "Buffer pool WRED profile id", SAI_ATTR_VAL_TYPE_OID},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t buffer_pool_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_BUFFER_POOL_ATTR_SHARED_SIZE,
     {false, false, true, true}, /* implemented */
     {false, false, true, true}, /* supported */
     buffer_pool_attr_get,
     (void*)SAI_BUFFER_POOL_ATTR_SHARED_SIZE,
     buffer_pool_attr_set,
     (void*)SAI_BUFFER_POOL_ATTR_SHARED_SIZE},

    {SAI_BUFFER_POOL_ATTR_TYPE,
     {false, false, true, true}, /* implemented */
     {false, false, true, true}, /* supported */
     buffer_pool_attr_get,
     (void*)SAI_BUFFER_POOL_ATTR_TYPE,
     buffer_pool_attr_set,
     (void*)SAI_BUFFER_POOL_ATTR_TYPE},

    {SAI_BUFFER_POOL_ATTR_SIZE,
     {false, false, true, true}, /* implemented */
     {false, false, true, true}, /* supported */
     buffer_pool_attr_get,
     (void*)SAI_BUFFER_POOL_ATTR_SIZE,
     buffer_pool_attr_set,
     (void*)SAI_BUFFER_POOL_ATTR_SIZE},

    {SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE,
     {false, false, true, true}, /* implemented */
     {false, false, true, true}, /* supported */
     buffer_pool_attr_get,
     (void*)SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE,
     buffer_pool_attr_set,
     (void*)SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE},

    {SAI_BUFFER_POOL_ATTR_TAM,
     {false, false, true, true}, /* implemented */
     {false, false, true, true}, /* supported */
     buffer_pool_attr_get,
     (void*)SAI_BUFFER_POOL_ATTR_TAM,
     buffer_pool_attr_set,
     (void*)SAI_BUFFER_POOL_ATTR_TAM},

    {SAI_BUFFER_POOL_ATTR_XOFF_SIZE,
     {false, false, true, true}, /* implemented */
     {false, false, true, true}, /* supported */
     buffer_pool_attr_get,
     (void*)SAI_BUFFER_POOL_ATTR_XOFF_SIZE,
     buffer_pool_attr_set,
     (void*)SAI_BUFFER_POOL_ATTR_XOFF_SIZE},

    {SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID,
     {false, false, true, true}, /* implemented */
     {false, false, true, true}, /* supported */
     buffer_pool_attr_get,
     (void*)SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID,
     buffer_pool_attr_set,
     (void*)SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID}};

static const sai_attribute_entry_t buffer_profile_attribs[]
    = {{SAI_BUFFER_PROFILE_ATTR_POOL_ID, false, false, true, true, "Buffer profile pool id", SAI_ATTR_VAL_TYPE_OID},
       {SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE,
        true,
        true,
        true,
        true,
        "Buffer profile reserved buffer size",
        SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, true, true, true, true, "Buffer profile threshold mode", SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH,
        false,
        true,
        true,
        true,
        "Buffer profile shared dynamic threshold",
        SAI_ATTR_VAL_TYPE_U8},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t buffer_profile_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_BUFFER_PROFILE_ATTR_POOL_ID,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     buffer_profile_attr_get,
     (void*)SAI_BUFFER_PROFILE_ATTR_POOL_ID,
     buffer_profile_attr_set,
     (void*)SAI_BUFFER_PROFILE_ATTR_POOL_ID},

    {SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     buffer_profile_attr_get,
     (void*)SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE,
     buffer_profile_attr_set,
     (void*)SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE},

    {SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     buffer_profile_attr_get,
     (void*)SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE,
     buffer_profile_attr_set,
     (void*)SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE},

    {SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     buffer_profile_attr_get,
     (void*)SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH,
     buffer_profile_attr_set,
     (void*)SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH}};

// clang format-on

static sai_status_t
create_ingress_priority_group(_Out_ sai_object_id_t* ingress_priority_group_id,
                              _In_ sai_object_id_t switch_id,
                              _In_ uint32_t attr_count,
                              _In_ const sai_attribute_t* attr_list)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();
    lsai_object la_ppg(SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, sdev->m_switch_id, 0);
    *ingress_priority_group_id = la_ppg.object_id();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_ingress_priority_group(_In_ sai_object_id_t ingress_priority_group_id)
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id, _In_ const sai_attribute_t* attr)
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id,
                                     _In_ uint32_t attr_count,
                                     _Inout_ sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id,
                                 _In_ uint32_t number_of_counters,
                                 _In_ const sai_stat_id_t* counter_ids,
                                 _Out_ uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_ingress_priority_group_stats_ext(_In_ sai_object_id_t ingress_priority_group_id,
                                     _In_ uint32_t number_of_counters,
                                     _In_ const sai_stat_id_t* counter_ids,
                                     _In_ sai_stats_mode_t mode,
                                     _Out_ uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
clear_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id,
                                   _In_ uint32_t number_of_counters,
                                   _In_ const sai_stat_id_t* counter_ids)
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

static std::string
buffer_profile_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_buffer_profile_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
buffer_profile_attr_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_buf_profile(key->key.object_id);
    if (la_buf_profile.type != SAI_OBJECT_TYPE_BUFFER_PROFILE) {
        sai_log_error(SAI_API_BUFFER, "Invalid buffer profile for get attribute 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sdev = la_buf_profile.get_device();

    buffer_profile* buffer_prof = sdev->m_buffer_profiles.get_ptr(la_buf_profile.index);
    if (buffer_prof == nullptr) {
        sai_log_error(SAI_API_BUFFER, "Buffer profile 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    switch ((int64_t)arg) {
    case SAI_BUFFER_PROFILE_ATTR_POOL_ID:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_POOL_ID, *value, buffer_prof->buffer_pool_id);
        break;
    case SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, *value, buffer_prof->reserved_buffer_size);
        break;
    case SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, *value, buffer_prof->mode);
        break;
    case SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, *value, buffer_prof->dynamic_thresh);
        break;
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
buffer_profile_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_buf_profile(key->key.object_id);
    if (la_buf_profile.type != SAI_OBJECT_TYPE_BUFFER_PROFILE) {
        sai_log_error(SAI_API_BUFFER, "Invalid buffer profile for get attribute 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sdev = la_buf_profile.get_device();

    buffer_profile* buffer_prof = sdev->m_buffer_profiles.get_ptr(la_buf_profile.index);
    if (buffer_prof == nullptr) {
        sai_log_error(SAI_API_BUFFER, "Buffer profile 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    switch ((int64_t)arg) {
    case SAI_BUFFER_PROFILE_ATTR_POOL_ID:
        buffer_prof->buffer_pool_id = get_attr_value(SAI_BUFFER_PROFILE_ATTR_POOL_ID, *value);
        break;
    case SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE:
        buffer_prof->reserved_buffer_size = get_attr_value(SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, *value);
        break;
    case SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE:
        buffer_prof->mode = get_attr_value(SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, *value);
        break;
    case SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH:
        buffer_prof->dynamic_thresh = get_attr_value(SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, *value);
        break;
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_buffer_profile(_Out_ sai_object_id_t* buffer_profile_id,
                      _In_ sai_object_id_t switch_id,
                      _In_ uint32_t attr_count,
                      _In_ const sai_attribute_t* attr_list)
{

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_SWITCH, switch_id, &buffer_profile_to_string, "buffer profile", attrs);

    lsai_object la_sw(switch_id);
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    buffer_profile buffer_prof;
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_POOL_ID, attrs, buffer_prof.buffer_pool_id, true);

    buffer_prof.mode = SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC;
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, attrs, buffer_prof.mode, false);

    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, attrs, buffer_prof.reserved_buffer_size, true);

    if (buffer_prof.mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC) {
        get_attrs_value(SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, attrs, buffer_prof.dynamic_thresh, true);
    }

    uint32_t db_index = 0;
    sdev->m_buffer_profiles.allocate_id(db_index);
    lsai_object la_buffer_profile_base(SAI_OBJECT_TYPE_BUFFER_PROFILE, sdev->m_switch_id, db_index);

    *buffer_profile_id = la_buffer_profile_base.object_id();
    sdev->m_buffer_profiles.set(*buffer_profile_id, buffer_prof, la_buffer_profile_base);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_buffer_profile(_In_ sai_object_id_t buffer_profile_id)
{
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_BUFFER_PROFILE, buffer_profile_id, &buffer_profile_to_string, buffer_profile_id);

    auto status = sdev->m_buffer_profiles.remove(buffer_profile_id);
    sai_return_on_la_error(status);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = buffer_profile_id;

    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_BUFFER_PROFILE, buffer_profile_id, &buffer_profile_to_string, "attr", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "buffer profile 0x%lx", buffer_profile_id);
    return sai_set_attribute(&key, key_str, buffer_profile_attribs, buffer_profile_vendor_attribs, attr);
}

static sai_status_t
get_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = buffer_profile_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BUFFER,
                  SAI_OBJECT_TYPE_BUFFER_PROFILE,
                  buffer_profile_id,
                  &buffer_profile_to_string,
                  "buffer pool",
                  buffer_profile_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "buffer profile 0x%0lx", buffer_profile_id);
    return sai_get_attributes(&key, key_str, buffer_profile_attribs, buffer_profile_vendor_attribs, attr_count, attr_list);
}

static std::string
buffer_pool_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_buffer_pool_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
get_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id, _In_ uint32_t attr_count, _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = buffer_pool_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_BUFFER, SAI_OBJECT_TYPE_BUFFER_POOL, buffer_pool_id, &buffer_pool_to_string, "buffer pool", buffer_pool_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "buffer pool 0x%0lx", buffer_pool_id);
    return sai_get_attributes(&key, key_str, buffer_pool_attribs, buffer_pool_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_buffer_pool(_Out_ sai_object_id_t* buffer_pool_id,
                   _In_ sai_object_id_t switch_id,
                   _In_ uint32_t attr_count,
                   _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_SWITCH, switch_id, &buffer_pool_to_string, "buffer pool", attrs);

    lsai_object la_sw(switch_id);
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (sdev->m_buffer_pool_count == MAX_BUFFER_POOL_COUNT) {
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    sai_buffer_pool_type_t type{};
    {
        get_attrs_value(SAI_BUFFER_POOL_ATTR_TYPE, attrs, type, true);
    }
    switch (type) {
    case SAI_BUFFER_POOL_TYPE_EGRESS:
        break;
    default:
        return SAI_STATUS_NOT_SUPPORTED;
    }

    sai_buffer_pool_threshold_mode_t mode{};
    {
        get_attrs_value(SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, attrs, mode, true);
    }
    switch (mode) {
    case SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC:
        break;
    default:
        return SAI_STATUS_NOT_SUPPORTED;
    }

    sai_uint64_t size{};
    {
        get_attrs_value(SAI_BUFFER_POOL_ATTR_SIZE, attrs, size, true);
    }
    if (type == SAI_BUFFER_POOL_TYPE_EGRESS && mode == SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC
        && size == get_egress_dynamic_buffer_pool_size(la_sw)) {
        lsai_object la_buffer_pool_base(SAI_OBJECT_TYPE_BUFFER_POOL, sdev->m_switch_id, 0);
        *buffer_pool_id = la_buffer_pool_base.object_id() + sdev->m_buffer_pool_count;
        // We assume upper level create few buffer pools at startup, and do not delete and recreate
        sdev->m_buffer_pool_count += 1;
    } else {
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_buffer_pool(_In_ sai_object_id_t buffer_pool_id)
{
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_BUFFER_POOL, buffer_pool_id, &buffer_pool_to_string, buffer_pool_id);

    // Ignoring the given buffer_pool_id. Just deleting last one
    sdev->m_buffer_pool_count -= 1;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_buffer_pool_stats_ext(_In_ sai_object_id_t buffer_pool_id,
                          _In_ uint32_t number_of_counters,
                          _In_ const sai_stat_id_t* counter_ids,
                          _In_ sai_stats_mode_t mode,
                          _Out_ uint64_t* counters)
{
    lsai_object la_buffer_pool(buffer_pool_id);
    auto sdev = la_buffer_pool.get_device();
    sai_start_api_counter(sdev);
    la_uint64_t free_buffer_count;
    la_uint64_t* free_buffer_count_ptr = &free_buffer_count;

    la_status status = LA_STATUS_SUCCESS;
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        case SAI_BUFFER_POOL_STAT_WATERMARK_BYTES: {
            la_device::la_cgm_watermarks* wmk_ptr = nullptr;

            status = cgm_watermarks_shadow.get_data(sdev, wmk_ptr, SAI_STATS_MODE_READ);
            if (status != LA_STATUS_SUCCESS) {
                la_device::la_cgm_watermarks wmk;

                status = sdev->m_dev->get_cgm_watermarks(wmk);
                if (status == LA_STATUS_SUCCESS) {
                    counters[i] = std::max(wmk.uc_wmk, wmk.mc_wmk) * BUFFER_POOL_ENTRY_SIZE;
                    cgm_watermarks_shadow.set_data(wmk, SAI_STATS_MODE_READ);
                } else {
                    sai_return_on_la_error(status, "Failed to get CGM watermarks, rc %s", status.message().c_str());
                }
            } else {
                counters[i] = std::max(wmk_ptr->uc_wmk, wmk_ptr->mc_wmk) * BUFFER_POOL_ENTRY_SIZE;
            }
            break;
        }
        case SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES:
            status = curr_occ_bytes_shadow.get_data(sdev, free_buffer_count_ptr, SAI_STATS_MODE_READ);
            if (status != LA_STATUS_SUCCESS) {
                status = sdev->m_dev->get_sms_total_free_buffer_summary(false, free_buffer_count);
                if (status == LA_STATUS_SUCCESS) {
                    curr_occ_bytes_shadow.set_data(free_buffer_count, SAI_STATS_MODE_READ);
                } else {
                    sai_return_on_la_error(
                        status, "Failed to get SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES, rc %s", status.message().c_str());
                }
            }
            counters[i] = get_egress_dynamic_buffer_pool_size(la_buffer_pool) - *free_buffer_count_ptr * BUFFER_POOL_ENTRY_SIZE;
            break;
        default:
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_buffer_pool_stats(_In_ sai_object_id_t buffer_pool_id,
                      _In_ uint32_t number_of_counters,
                      _In_ const sai_stat_id_t* counter_ids,
                      _Out_ uint64_t* counters)
{
    return get_buffer_pool_stats_ext(buffer_pool_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_buffer_pool_stats(_In_ sai_object_id_t pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t* counter_ids)
{
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_buffer_pool::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    *count = sdev->m_buffer_pool_count;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_buffer_pool::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                      uint32_t* object_count,
                                      sai_object_key_t* object_list) const
{
    if (*object_count < sdev->m_buffer_pool_count) {
        *object_count = sdev->m_buffer_pool_count;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    lsai_object la_buffer_pool_base(SAI_OBJECT_TYPE_BUFFER_POOL, sdev->m_switch_id, 0);

    for (uint32_t i = 0; i < sdev->m_buffer_pool_count; i++) {
        object_list[i].key.object_id = la_buffer_pool_base.object_id() + i;
    }
    *object_count = sdev->m_buffer_pool_count;

    return SAI_STATUS_SUCCESS;
}

const sai_buffer_api_t buffer_api = {
    create_buffer_pool,
    remove_buffer_pool,
    set_buffer_pool_attribute,
    get_buffer_pool_attribute,
    get_buffer_pool_stats,
    get_buffer_pool_stats_ext,
    clear_buffer_pool_stats,
    create_ingress_priority_group,
    remove_ingress_priority_group,
    set_ingress_priority_group_attribute,
    get_ingress_priority_group_attribute,
    get_ingress_priority_group_stats,
    get_ingress_priority_group_stats_ext,
    clear_ingress_priority_group_stats,
    create_buffer_profile,
    remove_buffer_profile,
    set_buffer_profile_attribute,
    get_buffer_profile_attribute,
};
}
}
