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

#include "sai_qos.h"

#include <set>

#include "common/gen_utils.h"

#include "sai_device.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

lasai_qos::lasai_qos(std::shared_ptr<lsai_device> sai_dev) : m_lsai_device(sai_dev)
{
}

//======================================================================
extern const sai_attribute_entry_t qos_map_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
    {SAI_QOS_MAP_ATTR_TYPE, true, true, false, true, "QOS map type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST, true, true, true, true, "QOS map value list", SAI_ATTR_VAL_TYPE_U32LIST},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t qos_map_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_QOS_MAP_ATTR_TYPE,
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     lasai_qos::sai_qos_map_attr_type_get,
     nullptr,
     nullptr,
     nullptr},
    {SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::sai_qos_map_attr_list_get,
     nullptr,
     lasai_qos::sai_qos_map_attr_list_set,
     nullptr}};

sai_status_t
lasai_qos::verify_limits(sai_qos_map_t& qos_entry)
{
    if (qos_entry.key.tc > MAX_QOS_TC_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "TC val %u too big. Max allowed is %u\n", qos_entry.key.tc, MAX_QOS_TC_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.key.dscp > MAX_QOS_DSCP_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "DSCP val %u too big. Max allowed is %u\n", qos_entry.key.dscp, MAX_QOS_DSCP_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.key.dot1p > MAX_QOS_DOT1P_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "DOT1P val %u too big. Max allowed is %u\n", qos_entry.key.dot1p, MAX_QOS_DOT1P_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.key.prio > MAX_QOS_PRIO_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "PRIO val %u too big. Max allowed is %u\n", qos_entry.key.prio, MAX_QOS_PRIO_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.key.pg > MAX_QOS_PG_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "PG val %u too big. Max allowed is %u\n", qos_entry.key.pg, MAX_QOS_PG_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.key.color > SAI_PACKET_COLOR_RED) {
        sai_log_error(SAI_API_QOS_MAP, "COLOR val %u too big. Max allowed is %u\n", qos_entry.key.color, SAI_PACKET_COLOR_RED);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.key.queue_index > MAX_QOS_QUEUE_INDEX_VAL) {
        sai_log_error(
            SAI_API_QOS_MAP, "QUEUE_INDEX val %u too big. Max allowed is %u\n", qos_entry.key.queue_index, MAX_QOS_QUEUE_INDEX_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.value.tc > MAX_QOS_TC_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "TC val %u too big. Max allowed is %u\n", qos_entry.value.tc, MAX_QOS_TC_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.value.dscp > MAX_QOS_DSCP_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "DSCP val %u too big. Max allowed is %u\n", qos_entry.value.dscp, MAX_QOS_DSCP_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.value.dot1p > MAX_QOS_DOT1P_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "DOT1P val %u too big. Max allowed is %u\n", qos_entry.value.dot1p, MAX_QOS_DOT1P_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.value.prio > MAX_QOS_PRIO_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "PRIO val %u too big. Max allowed is %u\n", qos_entry.value.prio, MAX_QOS_PRIO_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.value.pg > MAX_QOS_PG_VAL) {
        sai_log_error(SAI_API_QOS_MAP, "PG val %u too big. Max allowed is %u\n", qos_entry.value.pg, MAX_QOS_PG_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.value.color > SAI_PACKET_COLOR_RED) {
        sai_log_error(SAI_API_QOS_MAP, "COLOR val %u too big. Max allowed is %u\n", qos_entry.value.color, SAI_PACKET_COLOR_RED);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    if (qos_entry.value.queue_index > MAX_QOS_QUEUE_INDEX_VAL) {
        sai_log_error(SAI_API_QOS_MAP,
                      "QUEUE_INDEX val %u too big. Max allowed is %u\n",
                      qos_entry.value.queue_index,
                      MAX_QOS_QUEUE_INDEX_VAL);
        return SAI_STATUS_INVALID_ATTR_VALUE_MAX;
    }

    return SAI_STATUS_SUCCESS;
}

static std::string
qos_map_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_qos_map_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

/**
 * @brief Create a QOS MAP
 *
 * @param[out] qos_map_id QOS MAP Id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lasai_qos::create_qos_map(_Out_ sai_object_id_t* out_qos_map_id,
                          _In_ sai_object_id_t switch_id,
                          _In_ uint32_t attr_count,
                          _In_ const sai_attribute_t* attr_list)
{
    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_QOS_MAP, SAI_OBJECT_TYPE_SWITCH, switch_id, &qos_map_to_string, switch_id, attrs);

    sai_qos_map_type_t map_type;
    get_attrs_value(SAI_QOS_MAP_ATTR_TYPE, attrs, map_type, true);
    sai_qos_map_list_t map_list;
    get_attrs_value(SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST, attrs, map_list, true);
    if (attr_count > 2) {
        sai_log_error(SAI_API_QOS_MAP, "Got more than 2 attributes for create_qos_map (%d).", attr_count);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // verify values are in correct range
    for (uint32_t index = 0; index < map_list.count; index++) {
        sai_return_on_error(verify_limits(map_list.list[index]));
    }

    // if we got here, both mandatory attributes are present, and just them.
    // now it is time to allocate a new map
    uint32_t qos_map_index = 0;
    la_status status = sdev->m_qos_handler->m_qos_map_db.allocate_id(qos_map_index);
    sai_return_on_la_error(status, "Failed allocating QOS map ID");
    txn.on_fail([=]() { sdev->m_qos_handler->m_qos_map_db.release_id(qos_map_index); });

    lasai_qos_map qos_map(map_type, map_list.count);

    // no need to check the return status since map_list.count == qos_map.m_value_mapping.count
    fill_sai_list(map_list.list, &map_list.list[map_list.count], qos_map.m_value_mapping);

    lsai_object la_qos_map_id(SAI_OBJECT_TYPE_QOS_MAP, la_obj.index, qos_map_index);
    sdev->m_qos_handler->m_qos_map_db.set(qos_map_index, qos_map);
    *out_qos_map_id = la_qos_map_id.object_id();

    sai_log_info(SAI_API_QOS_MAP, "qos map 0x%lx created", *out_qos_map_id);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove an existing QOS MAP
 *
 * @param[in] qos_map_id QOS MAP Id
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lasai_qos::remove_qos_map(_In_ sai_object_id_t qos_map_id)
{
    // verify it exists
    lasai_qos_map qos_map{};

    sai_start_api(SAI_API_QOS_MAP, SAI_OBJECT_TYPE_QOS_MAP, qos_map_id, &qos_map_to_string, qos_map_id);

    la_status status = sdev->m_qos_handler->m_qos_map_db.get(la_obj.index, qos_map);
    sai_return_on_la_error(status);

    // verify it is not in use by the device!
    if (qos_map.m_reference_count > 0) {
        sai_log_error(SAI_API_QOS_MAP, "Failed to erase QOS map id %lx because map is in use by the device", qos_map_id);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    // OK to erase
    sdev->m_qos_handler->m_qos_map_db.remove(qos_map_id);

    sai_log_debug(SAI_API_QOS_MAP, "qos map 0x%lx removed", qos_map_id);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Set an attribute in a QOS MAP
 *
 * @param[in] qos_map_id QOS MAP Id
 * @param[in] attr An attribute to set
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lasai_qos::set_qos_map_attribute(_In_ sai_object_id_t qos_map_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = qos_map_id;
    sai_start_api(SAI_API_QOS_MAP, SAI_OBJECT_TYPE_QOS_MAP, qos_map_id, &qos_map_to_string, qos_map_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "qos map 0x%0lx", qos_map_id);

    return sai_set_attribute(&key, key_str, qos_map_attribs, qos_map_vendor_attribs, attr);
}

/**
 * @brief Get one or more attributes of a QOS MAP
 *
 * @param[in] qos_map_id QOS MAP Id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lasai_qos::get_qos_map_attribute(_In_ sai_object_id_t qos_map_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    sai_start_api(SAI_API_QOS_MAP, SAI_OBJECT_TYPE_QOS_MAP, qos_map_id, &qos_map_to_string, qos_map_id);

    key.key.object_id = qos_map_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "QOS Map ID 0x%0lx", qos_map_id);
    return sai_get_attributes(&key, key_str, qos_map_attribs, qos_map_vendor_attribs, attr_count, attr_list);
}

sai_status_t
lasai_qos::sai_qos_map_attr_type_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // verify it exists
    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    lasai_qos_map qos_map;
    sai_return_on_error(check_and_get_device_and_map_id(key->key.object_id, sdev, map_id, qos_map));

    set_attr_value(SAI_QOS_MAP_ATTR_TYPE, *value, (sai_qos_map_type_t)qos_map.m_map_type);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_qos::sai_qos_map_attr_list_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    lasai_qos_map qos_map;
    sai_return_on_error(check_and_get_device_and_map_id(key->key.object_id, sdev, map_id, qos_map));

    qos_map.m_value_mapping.count = value->qosmap.count;
    if (qos_map.m_value_mapping.count != 0) {
        qos_map.m_value_mapping.shared_list = std::shared_ptr<sai_qos_map_t>(new sai_qos_map_t[qos_map.m_value_mapping.count],
                                                                             std::default_delete<sai_qos_map_t[]>());
        qos_map.m_value_mapping.list = qos_map.m_value_mapping.shared_list.get();
    } else {
        qos_map.m_value_mapping.list = nullptr;
    }

    // verify values
    for (uint32_t index = 0; index < value->qosmap.count; index++) {
        sai_return_on_error(verify_limits(value->qosmap.list[index]));
    }

    // no need to check the return status since qos_map.count == value->qosmap.count
    fill_sai_list(value->qosmap.list, &value->qosmap.list[value->qosmap.count], qos_map.m_value_mapping);

    sdev->m_qos_handler->m_qos_map_db.set(map_id, qos_map);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_qos::sai_qos_map_attr_list_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // verify it exists
    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    lasai_qos_map qos_map;
    sai_return_on_error(check_and_get_device_and_map_id(key->key.object_id, sdev, map_id, qos_map));

    return fill_sai_list(qos_map.m_value_mapping.shared_list.get(),
                         qos_map.m_value_mapping.shared_list.get() + qos_map.m_value_mapping.count,
                         value->qosmap);
}

sai_status_t
lasai_qos::check_and_get_device_and_map_id(const sai_object_id_t& qos_map_id,
                                           std::shared_ptr<lsai_device>& out_sdev,
                                           uint32_t& out_map_index,
                                           lasai_qos_map& out_qos_map)
{
    lsai_object la_obj(qos_map_id);
    out_sdev = la_obj.get_device();
    if (la_obj.type != SAI_OBJECT_TYPE_QOS_MAP || out_sdev == nullptr || out_sdev->m_dev == nullptr) {
        sai_log_error(SAI_API_QOS_MAP, "Bad QOS map id %lu", qos_map_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    out_map_index = la_obj.index;
    la_status status = out_sdev->m_qos_handler->m_qos_map_db.get(out_map_index, out_qos_map);
    sai_return_on_la_error(status, "Failed to find QOS map id %lu", qos_map_id);

    return SAI_STATUS_SUCCESS;
}

la_status
lasai_qos::create_sdk_ingress_qos_profile(transaction& txn, unique_ptr<lasai_to_sdk_qos_ingress>& out_prof_info)
{
    la_ingress_qos_profile* new_sdk_profile;

    txn.status = m_lsai_device->m_dev->create_ingress_qos_profile(new_sdk_profile);
    la_return_on_error(txn.status, "Failed creating default ingress qos profile");
    txn.on_fail([=]() { m_lsai_device->m_dev->destroy(new_sdk_profile); });

    out_prof_info = make_unique<lasai_to_sdk_qos_ingress>();

    out_prof_info->m_sdk_profile = new_sdk_profile;

    return LA_STATUS_SUCCESS;
}

la_status
lasai_qos::configure_sdk_ingress_qos_profile(std::shared_ptr<lsai_device> sdev,
                                             const lasai_to_sdk_qos_ingress& prof_info,
                                             bool program_defaults)
{
    uint8_t pcpdei_to_tc[8][2];
    la_qos_color_e pcpdei_to_color[8][2];
    uint8_t dscp_to_tc[64];
    la_qos_color_e dscp_to_color[64];
    uint8_t mpls_to_tc[8];
    la_qos_color_e mpls_to_color[8];

    bool program_pcpdei_to_tc = false;
    bool program_pcpdei_to_color = false;
    bool program_dscp_to_tc = false;
    bool program_dscp_to_color = false;
    bool program_mpls_to_tc = false;
    bool program_mpls_to_color = false;

    if (program_defaults) {
        program_pcpdei_to_tc = true;
        program_pcpdei_to_color = true;
        program_dscp_to_tc = true;
        program_dscp_to_color = true;
        program_mpls_to_tc = true;
        program_mpls_to_color = true;
    }

    // Set default values
    for (size_t pcp = 0; pcp < 8; pcp++) {
        for (size_t dei = 0; dei < 2; dei++) {
            pcpdei_to_tc[pcp][dei] = 0;
            pcpdei_to_color[pcp][dei] = la_qos_color_e::GREEN;
        }
    }

    for (la_uint8_t val = 0; val < 64; val++) {
        dscp_to_tc[val] = 0;
        dscp_to_color[val] = la_qos_color_e::GREEN;
    }

    for (la_uint8_t val = 0; val < 8; val++) {
        mpls_to_tc[val] = 0;
        mpls_to_color[val] = la_qos_color_e::GREEN;
    }

    // override default values with values from user defined maps

    // PCP DEI to TC
    lasai_qos_map pcpdei_to_tc_map;
    la_status found = LA_STATUS_ENOTFOUND;
    if (prof_info.m_pcpdei_to_tc != SAI_QOS_NON_VALID_INDEX) {
        found = sdev->m_qos_handler->m_qos_map_db.get(prof_info.m_pcpdei_to_tc, pcpdei_to_tc_map);
    }
    if (found == LA_STATUS_SUCCESS) {
        program_pcpdei_to_tc = true;
        for (uint32_t index = 0; index < pcpdei_to_tc_map.m_value_mapping.count; index++) {
            uint8_t pcp = (pcpdei_to_tc_map.m_value_mapping.shared_list.get()[index].key.dot1p >> 3) & 0x7;
            uint8_t dei = pcpdei_to_tc_map.m_value_mapping.shared_list.get()[index].key.dot1p & 0x1;
            pcpdei_to_tc[pcp][dei] = pcpdei_to_tc_map.m_value_mapping.shared_list.get()[index].value.tc;
        }
    }

    // PCP DEI to color
    lasai_qos_map pcpdei_to_color_map;
    found = LA_STATUS_ENOTFOUND;
    if (prof_info.m_pcpdei_to_color != SAI_QOS_NON_VALID_INDEX) {
        found = sdev->m_qos_handler->m_qos_map_db.get(prof_info.m_pcpdei_to_color, pcpdei_to_color_map);
    }
    if (found == LA_STATUS_SUCCESS) {
        program_pcpdei_to_color = true;
        for (uint32_t index = 0; index < pcpdei_to_color_map.m_value_mapping.count; index++) {
            uint8_t pcp = (pcpdei_to_color_map.m_value_mapping.shared_list.get()[index].key.dot1p >> 3) & 0x7;
            uint8_t dei = pcpdei_to_color_map.m_value_mapping.shared_list.get()[index].key.dot1p & 0x1;
            pcpdei_to_color[pcp][dei]
                = sai_color_to_la_color(pcpdei_to_color_map.m_value_mapping.shared_list.get()[index].value.color);
        }
    }

    // DSCP to TC
    lasai_qos_map dscp_to_tc_map;
    found = LA_STATUS_ENOTFOUND;
    if (prof_info.m_dscp_to_tc != SAI_QOS_NON_VALID_INDEX) {
        found = sdev->m_qos_handler->m_qos_map_db.get(prof_info.m_dscp_to_tc, dscp_to_tc_map);
    }
    if (found == LA_STATUS_SUCCESS) {
        program_dscp_to_tc = true;
        for (uint32_t index = 0; index < dscp_to_tc_map.m_value_mapping.count; index++) {
            dscp_to_tc[dscp_to_tc_map.m_value_mapping.shared_list.get()[index].key.dscp]
                = dscp_to_tc_map.m_value_mapping.shared_list.get()[index].value.tc;
        }
    }

    // DSCP to color
    lasai_qos_map dscp_to_color_map;
    found = LA_STATUS_ENOTFOUND;
    if (prof_info.m_dscp_to_color != SAI_QOS_NON_VALID_INDEX) {
        found = sdev->m_qos_handler->m_qos_map_db.get(prof_info.m_dscp_to_color, dscp_to_color_map);
    }
    if (found == LA_STATUS_SUCCESS) {
        program_dscp_to_color = true;
        for (uint32_t index = 0; index < dscp_to_color_map.m_value_mapping.count; index++) {
            dscp_to_color[dscp_to_color_map.m_value_mapping.shared_list.get()[index].key.dscp]
                = sai_color_to_la_color(dscp_to_color_map.m_value_mapping.shared_list.get()[index].value.color);
        }
    }

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    // MPLS to tc
    lasai_qos_map mpls_to_tc_map;
    found = LA_STATUS_ENOTFOUND;
    if (prof_info.m_mpls_to_tc != SAI_QOS_NON_VALID_INDEX) {
        found = sdev->m_qos_handler->m_qos_map_db.get(prof_info.m_mpls_to_tc, mpls_to_tc_map);
    }
    if (found == LA_STATUS_SUCCESS) {
        program_mpls_to_tc = true;
        for (uint32_t index = 0; index < mpls_to_tc_map.m_value_mapping.count; index++) {
            mpls_to_tc[mpls_to_tc_map.m_value_mapping.shared_list.get()[index].key.mpls_exp]
                = mpls_to_tc_map.m_value_mapping.shared_list.get()[index].value.tc;
        }
    }

    // MPLS to color
    lasai_qos_map mpls_to_color_map;
    found = LA_STATUS_ENOTFOUND;
    if (prof_info.m_mpls_to_color != SAI_QOS_NON_VALID_INDEX) {
        found = sdev->m_qos_handler->m_qos_map_db.get(prof_info.m_mpls_to_color, mpls_to_color_map);
    }
    if (found == LA_STATUS_SUCCESS) {
        program_mpls_to_color = true;
        for (uint32_t index = 0; index < mpls_to_color_map.m_value_mapping.count; index++) {
            mpls_to_color[mpls_to_color_map.m_value_mapping.shared_list.get()[index].key.mpls_exp]
                = sai_color_to_la_color(mpls_to_color_map.m_value_mapping.shared_list.get()[index].value.color);
        }
    }
#endif

    // Set values to SDK

    // PCP-DEI mapping to PCP-DEI, TC, color
    for (size_t pcp = 0; pcp < 8; pcp++) {
        for (size_t dei = 0; dei < 2; dei++) {
            la_vlan_pcpdei pcpdei(pcp, dei);
            if (program_defaults) {
                prof_info.m_sdk_profile->set_qos_tag_mapping_pcpdei(pcpdei, pcpdei);
            }
            if (program_pcpdei_to_tc) {
                prof_info.m_sdk_profile->set_traffic_class_mapping(pcpdei, pcpdei_to_tc[pcp][dei]);
            }
            if (program_pcpdei_to_color) {
                prof_info.m_sdk_profile->set_color_mapping(pcpdei, pcpdei_to_color[pcp][dei]);
            }
        }
    }

    // DSCP mapping to DSCP, TC, color
    for (la_uint8_t val = 0; val < 64; val++) {
        la_ip_dscp dscp = {.value = val};
        if (program_defaults) {
            prof_info.m_sdk_profile->set_qos_tag_mapping_dscp(la_ip_version_e::IPV4, dscp, dscp);
            prof_info.m_sdk_profile->set_qos_tag_mapping_dscp(la_ip_version_e::IPV6, dscp, dscp);
        }
        if (program_dscp_to_tc) {
            prof_info.m_sdk_profile->set_traffic_class_mapping(la_ip_version_e::IPV4, dscp, dscp_to_tc[val]);
            prof_info.m_sdk_profile->set_traffic_class_mapping(la_ip_version_e::IPV6, dscp, dscp_to_tc[val]);
        }
        if (program_dscp_to_color) {
            prof_info.m_sdk_profile->set_color_mapping(la_ip_version_e::IPV4, dscp, dscp_to_color[val]);
            prof_info.m_sdk_profile->set_color_mapping(la_ip_version_e::IPV6, dscp, dscp_to_color[val]);
        }
    }

    // MPLS mapping to TC
    for (la_uint8_t val = 0; val < 8; val++) {
        la_mpls_tc tc = {.value = val};
        if (program_defaults) {
            prof_info.m_sdk_profile->set_qos_tag_mapping_mpls_tc(tc, tc);
        }
        if (program_mpls_to_tc) {
            prof_info.m_sdk_profile->set_traffic_class_mapping(tc, mpls_to_tc[val]);
        }
        if (program_mpls_to_color) {
            prof_info.m_sdk_profile->set_color_mapping(tc, mpls_to_color[val]);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_qos::create_sdk_egress_qos_profile(transaction& txn, unique_ptr<lasai_to_sdk_qos_egress>& out_prof_info)
{
    la_egress_qos_profile* new_sdk_profile;

    txn.status = m_lsai_device->m_dev->create_egress_qos_profile(la_egress_qos_marking_source_e::QOS_TAG, new_sdk_profile);
    la_return_on_error(txn.status, "Failed creating default egress qos profile");
    txn.on_fail([=]() { m_lsai_device->m_dev->destroy(new_sdk_profile); });

    out_prof_info = make_unique<lasai_to_sdk_qos_egress>();

    out_prof_info->m_sdk_profile = new_sdk_profile;

    return LA_STATUS_SUCCESS;
}

la_status
lasai_qos::configure_sdk_egress_qos_profile(const lasai_to_sdk_qos_egress& prof_info)
{
    auto encap_qos_values = la_egress_qos_profile::encapsulating_headers_qos_values();

    // PCP-DEI mapping
    for (size_t pcp = 0; pcp < 8; pcp++) {
        for (size_t dei = 0; dei < 2; dei++) {
            la_vlan_pcpdei pcpdei(pcp, dei);
            prof_info.m_sdk_profile->set_qos_tag_mapping_pcpdei(pcpdei, pcpdei, encap_qos_values);
        }
    }

    // DSCP mapping
    for (la_uint8_t val = 0; val < 64; val++) {
        la_ip_dscp dscp = {.value = val};
        prof_info.m_sdk_profile->set_qos_tag_mapping_dscp(dscp, dscp, encap_qos_values);
    }

    // MPLS TC mapping
    for (la_uint8_t val = 0; val < 8; val++) {
        la_mpls_tc tc = {.value = val};
        prof_info.m_sdk_profile->set_qos_tag_mapping_mpls_tc(tc, tc, encap_qos_values);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_qos::create_sdk_tc_profile(transaction& txn, unique_ptr<lasai_to_sdk_tc_profile>& out_prof_info)
{
    la_tc_profile* new_sdk_profile;

    txn.status = m_lsai_device->m_dev->create_tc_profile(new_sdk_profile);
    la_return_on_error(txn.status, "Failed creating default TC profile");
    txn.on_fail([=]() { m_lsai_device->m_dev->destroy(new_sdk_profile); });

    out_prof_info = make_unique<lasai_to_sdk_tc_profile>();

    out_prof_info->m_sdk_profile = new_sdk_profile;

    return LA_STATUS_SUCCESS;
}

la_status
lasai_qos::configure_sdk_tc_profile(std::shared_ptr<lsai_device> sdev, const lasai_to_sdk_tc_profile& prof_info)
{
    uint8_t tc_to_queue_offset[8];

    // init to default
    for (la_uint8_t val = 0; val < 8; val++) {
        tc_to_queue_offset[val] = val;
    }

    // put non default values according to prof_info
    lasai_qos_map tc_to_queue_offset_map;
    la_status found = sdev->m_qos_handler->m_qos_map_db.get(prof_info.m_tc_to_queue, tc_to_queue_offset_map);
    if (found == LA_STATUS_SUCCESS) {
        for (uint32_t index = 0; index < tc_to_queue_offset_map.m_value_mapping.count; index++) {
            tc_to_queue_offset[tc_to_queue_offset_map.m_value_mapping.shared_list.get()[index].key.tc]
                = tc_to_queue_offset_map.m_value_mapping.shared_list.get()[index].value.queue_index;
        }
    }

    // configure to SDK
    for (la_uint8_t val = 0; val < 8; val++) {
        prof_info.m_sdk_profile->set_mapping(val, tc_to_queue_offset[val]);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_qos::initialize_default_qos_profiles(transaction& txn, std::shared_ptr<lsai_device> sdev)
{
    lasai_qos_map default_dscp_to_color_map(SAI_QOS_MAP_TYPE_DSCP_TO_COLOR);
    lasai_qos_map default_dscp_to_tc_map(SAI_QOS_MAP_TYPE_DSCP_TO_TC);
    lasai_qos_map default_dot1p_to_color_map(SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR);
    lasai_qos_map default_dot1p_to_tc_map(SAI_QOS_MAP_TYPE_DOT1P_TO_TC);
    lasai_qos_map default_tc_to_queue_map(SAI_QOS_MAP_TYPE_TC_TO_QUEUE);
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    lasai_qos_map default_mpls_to_color_map(SAI_QOS_MAP_TYPE_MPLS_EXP_TO_COLOR);
    lasai_qos_map default_mpls_to_tc_map(SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC);
#endif

    // We want to keep them forever
    default_dscp_to_color_map.m_reference_count = 1;
    default_dscp_to_tc_map.m_reference_count = 1;
    default_dot1p_to_color_map.m_reference_count = 1;
    default_dot1p_to_tc_map.m_reference_count = 1;
    default_tc_to_queue_map.m_reference_count = 1;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    default_mpls_to_color_map.m_reference_count = 1;
    default_mpls_to_tc_map.m_reference_count = 1;
#endif

    uint32_t index;

    la_status status = create_sdk_ingress_qos_profile(txn, m_default_ingress_qos_profile);
    la_return_on_error(status, "Failed creating default ingress QOS profile");

    txn.status = m_qos_map_db.insert(default_dscp_to_color_map, index);
    txn.on_fail([=]() { m_qos_map_db.remove(index); });
    m_default_ingress_qos_profile->m_dscp_to_color = index;
    lsai_object la_qos_map_id(SAI_OBJECT_TYPE_QOS_MAP, sdev->m_switch_id, index);
    m_default_qos_maps[SAI_QOS_MAP_TYPE_DSCP_TO_COLOR] = la_qos_map_id.object_id();

    txn.status = m_qos_map_db.insert(default_dscp_to_tc_map, index);
    txn.on_fail([=]() { m_qos_map_db.remove(index); });
    m_default_ingress_qos_profile->m_dscp_to_tc = index;
    la_qos_map_id.index = index;
    m_default_qos_maps[SAI_QOS_MAP_TYPE_DSCP_TO_TC] = la_qos_map_id.object_id();

    txn.status = m_qos_map_db.insert(default_dot1p_to_color_map, index);
    txn.on_fail([=]() { m_qos_map_db.remove(index); });
    m_default_ingress_qos_profile->m_pcpdei_to_color = index;
    la_qos_map_id.index = index;
    m_default_qos_maps[SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR] = la_qos_map_id.object_id();

    txn.status = m_qos_map_db.insert(default_dot1p_to_tc_map, index);
    txn.on_fail([=]() { m_qos_map_db.remove(index); });
    m_default_ingress_qos_profile->m_pcpdei_to_tc = index;
    la_qos_map_id.index = index;
    m_default_qos_maps[SAI_QOS_MAP_TYPE_DOT1P_TO_TC] = la_qos_map_id.object_id();

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    txn.status = m_qos_map_db.insert(default_mpls_to_color_map, index);
    txn.on_fail([=]() { m_qos_map_db.remove(index); });
    m_default_ingress_qos_profile->m_mpls_to_color = index;
    la_qos_map_id.index = index;
    m_default_qos_maps[SAI_QOS_MAP_TYPE_MPLS_EXP_TO_COLOR] = la_qos_map_id.object_id();

    txn.status = m_qos_map_db.insert(default_mpls_to_tc_map, index);
    txn.on_fail([=]() { m_qos_map_db.remove(index); });
    m_default_ingress_qos_profile->m_mpls_to_tc = index;
    la_qos_map_id.index = index;
    m_default_qos_maps[SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC] = la_qos_map_id.object_id();
#endif

    status = configure_sdk_ingress_qos_profile(sdev, *m_default_ingress_qos_profile, true);
    la_return_on_error(status, "Failed configuring default ingress QOS profile");
    m_default_ingress_qos_profile->inc_ref_count();

    // SDK egress qos profile
    status = create_sdk_egress_qos_profile(txn, m_default_egress_qos_profile);
    la_return_on_error(status, "Failed creating default egress QOS profile");

    status = configure_sdk_egress_qos_profile(*m_default_egress_qos_profile);
    la_return_on_error(status, "Failed configuring default egress QOS profile");
    m_default_egress_qos_profile->inc_ref_count();

    // SDK TC profile
    status = create_sdk_tc_profile(txn, m_default_tc_profile);
    la_return_on_error(status, "Failed creating default TC profile");

    txn.status = m_qos_map_db.insert(default_tc_to_queue_map, index);
    txn.on_fail([=]() { m_qos_map_db.remove(index); });
    m_default_tc_profile->m_tc_to_queue = index;
    status = configure_sdk_tc_profile(sdev, *m_default_tc_profile);
    la_return_on_error(status, "Failed configuring default TC profile");
    la_qos_map_id.index = index;
    m_default_qos_maps[SAI_QOS_MAP_TYPE_TC_TO_QUEUE] = la_qos_map_id.object_id();

    m_default_tc_profile->inc_ref_count();

    // Ignore the default created objects in get_object_count/keys
    m_qos_map_db.set_ignore_in_get_num(m_default_qos_maps.size());

    return LA_STATUS_SUCCESS;
}

la_ingress_qos_profile*
lasai_qos::get_default_ingress_qos_profile() const
{
    return m_default_ingress_qos_profile->m_sdk_profile;
}

la_egress_qos_profile*
lasai_qos::get_default_egress_qos_profile() const
{
    return m_default_egress_qos_profile->m_sdk_profile;
}

la_tc_profile*
lasai_qos::get_default_tc_profile() const
{
    return m_default_tc_profile->m_sdk_profile;
}

sai_status_t
lasai_qos::check_switch_params_and_get_device_and_map_index(_In_ const sai_object_key_t* key,
                                                            _In_ const sai_attribute_value_t* value,
                                                            std::shared_ptr<lsai_device>& out_sdev,
                                                            uint32_t& out_map_id,
                                                            sai_qos_map_type_t map_type)
{
    // validate we got all params
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // verify valid device
    lsai_object la_sw(key->key.object_id);
    out_sdev = la_sw.get_device();
    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || out_sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t map_oid = value->oid;

    // verify a valid map ID been given
    if (map_oid == SAI_NULL_OBJECT_ID) {
        // SAI_NULL_OBJECT_ID means we need to use the default map for this type
        auto pos = out_sdev->m_qos_handler->m_default_qos_maps.find(map_type);
        if (pos == out_sdev->m_qos_handler->m_default_qos_maps.end()) {
            return SAI_STATUS_INVALID_PARAMETER;
        } else {
            lsai_object la_obj(pos->second);
            out_map_id = la_obj.index;
        }
    } else {
        std::shared_ptr<lsai_device> sdev_from_map_oid;
        lasai_qos_map qos_map;
        sai_return_on_error(check_and_get_device_and_map_id(map_oid, sdev_from_map_oid, out_map_id, qos_map));
        if (out_sdev != sdev_from_map_oid) {
            sai_log_error(SAI_API_QOS_MAP, "Device from switch and device from QOS Map are different.");
            return SAI_STATUS_INVALID_PARAMETER;
        }
        if (qos_map.m_map_type != map_type) {
            sai_log_error(SAI_API_QOS_MAP, "Trying to apply map type %d when map type %d is needed.", qos_map.m_map_type, map_type);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    return SAI_STATUS_SUCCESS;
}

la_qos_color_e
lasai_qos::sai_color_to_la_color(sai_packet_color_t sai_color)
{
    switch (sai_color) {
    case SAI_PACKET_COLOR_GREEN:
        return la_qos_color_e::GREEN;
    case SAI_PACKET_COLOR_YELLOW:
        return la_qos_color_e::YELLOW;
    case SAI_PACKET_COLOR_RED:
        return la_qos_color_e::RED;
    default:
        return la_qos_color_e::NONE;
    }
}

sai_status_t
lasai_qos::switch_attr_qos_map_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint32_t map_index = 0;
    sai_switch_attr_t attr_type = (sai_switch_attr_t)(uint64_t)arg;
    sai_qos_map_type_t map_type = SAI_QOS_MAP_TYPE_CUSTOM_RANGE_BASE;

    switch (attr_type) {
    case SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP:
        map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_dscp_to_color;
        map_type = SAI_QOS_MAP_TYPE_DSCP_TO_COLOR;
        break;
    case SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP:
        map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_dscp_to_tc;
        map_type = SAI_QOS_MAP_TYPE_DSCP_TO_TC;
        break;
    case SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP:
        map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_pcpdei_to_color;
        map_type = SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR;
        break;
    case SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP:
        map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_pcpdei_to_tc;
        map_type = SAI_QOS_MAP_TYPE_DOT1P_TO_TC;
        break;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    case SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_COLOR_MAP:
        map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_mpls_to_color;
        map_type = SAI_QOS_MAP_TYPE_MPLS_EXP_TO_COLOR;
        break;
    case SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP:
        map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_mpls_to_tc;
        map_type = SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC;
        break;
#endif
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object sai_obj(SAI_OBJECT_TYPE_QOS_MAP, sdev->m_switch_id, map_index);
    sai_object_id_t ret_obj_id = sai_obj.object_id();

    // If using one of the default maps, we return SAI_NULL_OBJECT_ID
    auto pos = sdev->m_qos_handler->m_default_qos_maps.find(map_type);
    if (pos != sdev->m_qos_handler->m_default_qos_maps.end() && pos->second == ret_obj_id) {
        ret_obj_id = SAI_NULL_OBJECT_ID;
    }

    set_attr_value(SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP, *value, ret_obj_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_qos::switch_attr_qos_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    std::shared_ptr<lsai_device> sdev;
    uint32_t new_map_index;
    uint32_t prev_map_index;
    sai_qos_map_type_t map_type = (sai_qos_map_type_t)(uint64_t)arg;

    sai_return_on_error(check_switch_params_and_get_device_and_map_index(key, value, sdev, new_map_index, map_type));

    lasai_to_sdk_qos_ingress prof_info;
    prof_info.m_dscp_to_color = SAI_QOS_NON_VALID_INDEX;
    prof_info.m_dscp_to_tc = SAI_QOS_NON_VALID_INDEX;
    prof_info.m_pcpdei_to_color = SAI_QOS_NON_VALID_INDEX;
    prof_info.m_pcpdei_to_tc = SAI_QOS_NON_VALID_INDEX;
    prof_info.m_mpls_to_color = SAI_QOS_NON_VALID_INDEX;
    prof_info.m_mpls_to_tc = SAI_QOS_NON_VALID_INDEX;
    prof_info.m_sdk_profile = sdev->m_qos_handler->m_default_ingress_qos_profile->m_sdk_profile;

    switch (map_type) {
    case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:
        prev_map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_dscp_to_color;
        sdev->m_qos_handler->m_default_ingress_qos_profile->m_dscp_to_color = new_map_index;
        prof_info.m_dscp_to_color = new_map_index;
        break;
    case SAI_QOS_MAP_TYPE_DSCP_TO_TC:
        prev_map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_dscp_to_tc;
        sdev->m_qos_handler->m_default_ingress_qos_profile->m_dscp_to_tc = new_map_index;
        prof_info.m_dscp_to_tc = new_map_index;
        break;
    case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:
        prev_map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_pcpdei_to_color;
        sdev->m_qos_handler->m_default_ingress_qos_profile->m_pcpdei_to_color = new_map_index;
        prof_info.m_pcpdei_to_color = new_map_index;
        break;
    case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:
        prev_map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_pcpdei_to_tc;
        sdev->m_qos_handler->m_default_ingress_qos_profile->m_pcpdei_to_tc = new_map_index;
        prof_info.m_pcpdei_to_tc = new_map_index;
        break;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    case SAI_QOS_MAP_TYPE_MPLS_EXP_TO_COLOR:
        prev_map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_mpls_to_color;
        sdev->m_qos_handler->m_default_ingress_qos_profile->m_mpls_to_color = new_map_index;
        prof_info.m_mpls_to_color = new_map_index;
        break;
    case SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC:
        prev_map_index = sdev->m_qos_handler->m_default_ingress_qos_profile->m_mpls_to_tc;
        sdev->m_qos_handler->m_default_ingress_qos_profile->m_mpls_to_tc = new_map_index;
        prof_info.m_mpls_to_tc = new_map_index;
        break;
#endif
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (new_map_index == prev_map_index) { // nothing to change
        return SAI_STATUS_SUCCESS;
    }

    transaction txn;
    configure_sdk_ingress_qos_profile(sdev, prof_info, false);

    // We already checked that new map exists, and prev one must exist
    lasai_qos_map* new_map = sdev->m_qos_handler->m_qos_map_db.get_ptr(new_map_index);
    new_map->m_reference_count++;

    lasai_qos_map* prev_map = sdev->m_qos_handler->m_qos_map_db.get_ptr(prev_map_index);
    prev_map->m_reference_count--;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_qos::switch_attr_tc_map_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint32_t map_index = 0;

    map_index = sdev->m_qos_handler->m_default_tc_profile->m_tc_to_queue;

    lsai_object sai_obj(SAI_OBJECT_TYPE_QOS_MAP, sdev->m_switch_id, map_index);
    sai_object_id_t ret_obj_id = sai_obj.object_id();

    // If using one of the default maps, we return SAI_NULL_OBJECT_ID
    auto pos = sdev->m_qos_handler->m_default_qos_maps.find(SAI_QOS_MAP_TYPE_TC_TO_QUEUE);
    if (pos != sdev->m_qos_handler->m_default_qos_maps.end() && pos->second == ret_obj_id) {
        ret_obj_id = SAI_NULL_OBJECT_ID;
    }

    set_attr_value(SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP, *value, ret_obj_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_qos::switch_attr_tc_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    std::shared_ptr<lsai_device> sdev;
    uint32_t new_map_index;
    uint32_t prev_map_index;

    sai_return_on_error(
        check_switch_params_and_get_device_and_map_index(key, value, sdev, new_map_index, SAI_QOS_MAP_TYPE_TC_TO_QUEUE));

    lasai_to_sdk_tc_profile prof_info;
    prof_info.m_tc_to_queue = SAI_QOS_NON_VALID_INDEX;
    prof_info.m_sdk_profile = sdev->m_qos_handler->m_default_tc_profile->m_sdk_profile;

    prev_map_index = sdev->m_qos_handler->m_default_tc_profile->m_tc_to_queue;
    sdev->m_qos_handler->m_default_tc_profile->m_tc_to_queue = new_map_index;
    prof_info.m_tc_to_queue = new_map_index;

    if (new_map_index == prev_map_index) { // nothing to change
        return SAI_STATUS_SUCCESS;
    }

    transaction txn;
    configure_sdk_tc_profile(sdev, prof_info);

    // We already checked that new map exists, and prev one must exist
    lasai_qos_map* new_map = sdev->m_qos_handler->m_qos_map_db.get_ptr(new_map_index);
    new_map->m_reference_count++;

    lasai_qos_map* prev_map = sdev->m_qos_handler->m_qos_map_db.get_ptr(prev_map_index);
    prev_map->m_reference_count--;

    return SAI_STATUS_SUCCESS;
}

void
lasai_qos::dump_json(json_t* parent_json) const
{
    uint32_t obj_count;
    json_t* all_qos_json = json_object();
    json_object_set_new(parent_json, "QOS maps", all_qos_json);

    m_qos_map_db.get_object_count(m_lsai_device, &obj_count);
    sai_object_key_t obj_list[obj_count];

    m_qos_map_db.get_object_keys(m_lsai_device, &obj_count, obj_list);
    for (uint32_t i = 0; i < obj_count; i++) {
        std::stringstream ss;
        ss << std::hex << "QOS map 0x" << obj_list[i].key.object_id;
        json_t* qos_map_json = json_object();
        json_object_set_new(all_qos_json, ss.str().c_str(), qos_map_json);

        lsai_object la_obj(obj_list[i].key.object_id);
        lasai_qos_map qos_map;
        m_qos_map_db.get(la_obj.index, qos_map);

        json_object_set_new(qos_map_json, "ref_count", json_integer(qos_map.m_reference_count));
        json_object_set_new(qos_map_json, "size", json_integer(qos_map.m_value_mapping.count));
        json_object_set_new(qos_map_json, "type", json_integer(qos_map.m_map_type));

        json_t* qos_map_entries_json = json_object();
        json_object_set_new(qos_map_json, "entries", qos_map_entries_json);
        for (uint32_t map_index = 0; map_index < qos_map.m_value_mapping.count; map_index++) {
            json_t* qos_map_one_entry_json = json_object();
            sai_qos_map_params_t& key = qos_map.m_value_mapping.shared_list.get()[map_index].key;
            sai_qos_map_params_t& value = qos_map.m_value_mapping.shared_list.get()[map_index].value;

            std::stringstream one_entry_ss;
            one_entry_ss << "entry " << map_index;
            json_object_set_new(qos_map_entries_json, one_entry_ss.str().c_str(), qos_map_one_entry_json);

            json_t* qos_map_key_json = json_object();
            json_object_set_new(qos_map_one_entry_json, "key", qos_map_key_json);
            json_object_set_new(qos_map_key_json, "tc", json_integer(key.tc));
            json_object_set_new(qos_map_key_json, "dscp", json_integer(key.dscp));
            json_object_set_new(qos_map_key_json, "dot1p", json_integer(key.dot1p));
            json_object_set_new(qos_map_key_json, "prio", json_integer(key.prio));
            json_object_set_new(qos_map_key_json, "pg", json_integer(key.pg));
            json_object_set_new(qos_map_key_json, "queue index", json_integer(key.queue_index));
            json_object_set_new(qos_map_key_json, "color", json_integer(key.color));

            json_t* qos_map_value_json = json_object();
            json_object_set_new(qos_map_one_entry_json, "value", qos_map_value_json);
            json_object_set_new(qos_map_value_json, "tc", json_integer(value.tc));
            json_object_set_new(qos_map_value_json, "dscp", json_integer(value.dscp));
            json_object_set_new(qos_map_value_json, "dot1p", json_integer(value.dot1p));
            json_object_set_new(qos_map_value_json, "prio", json_integer(value.prio));
            json_object_set_new(qos_map_value_json, "pg", json_integer(value.pg));
            json_object_set_new(qos_map_value_json, "queue index", json_integer(value.queue_index));
            json_object_set_new(qos_map_value_json, "color", json_integer(value.color));
        }
    }

    json_t* default_ingress_json = json_object();
    json_object_set_new(all_qos_json, "default ingress", default_ingress_json);

    std::stringstream temp_ss;
    temp_ss << std::hex << "0x" << m_default_ingress_qos_profile->m_dscp_to_color;
    json_object_set_new(default_ingress_json, "dscp to color", json_string(temp_ss.str().c_str()));

    std::stringstream temp_ss1;
    temp_ss1 << std::hex << "0x" << m_default_ingress_qos_profile->m_dscp_to_tc;
    json_object_set_new(default_ingress_json, "dscp to tc", json_string(temp_ss1.str().c_str()));

    std::stringstream temp_ss2;
    temp_ss2 << std::hex << "0x" << m_default_ingress_qos_profile->m_pcpdei_to_color;
    json_object_set_new(default_ingress_json, "pcpdei to color", json_string(temp_ss2.str().c_str()));

    std::stringstream temp_ss3;
    temp_ss3 << std::hex << "0x" << m_default_ingress_qos_profile->m_pcpdei_to_tc;
    json_object_set_new(default_ingress_json, "pcpdei to tc", json_string(temp_ss3.str().c_str()));

    std::stringstream temp_ss4;
    json_t* default_tc_json = json_object();
    json_object_set_new(all_qos_json, "default tc", default_tc_json);
    temp_ss4 << std::hex << "0x" << m_default_tc_profile->m_tc_to_queue;
    json_object_set_new(default_tc_json, "tc to queue", json_string(temp_ss4.str().c_str()));
}

void
lasai_qos::dump()
{
    printf("QOS_map database:\n");
    uint32_t obj_count;
    m_qos_map_db.get_object_count(m_lsai_device, &obj_count);
    sai_object_key_t obj_list[obj_count];

    m_qos_map_db.get_object_keys(m_lsai_device, &obj_count, obj_list);
    for (uint32_t i = 0; i < obj_count; i++) {
        printf("  object id %lx\n", obj_list[i].key.object_id);
        lsai_object la_obj(obj_list[i].key.object_id);
        lasai_qos_map qos_map;

        m_qos_map_db.get(la_obj.index, qos_map);
        printf("    ref count %d map type %d\n", qos_map.m_reference_count, qos_map.m_map_type);
        printf("    %d values in map:\n", qos_map.m_value_mapping.count);
        for (uint32_t map_index = 0; map_index < qos_map.m_value_mapping.count; map_index++) {
            sai_qos_map_params_t& key = qos_map.m_value_mapping.shared_list.get()[map_index].key;
            sai_qos_map_params_t& value = qos_map.m_value_mapping.shared_list.get()[map_index].value;
            printf("key: tc:%d, dscp:%d, dot1p:%d, prio:%d, pg:%d, queue_index:%d, color:%d\n",
                   key.tc,
                   key.dscp,
                   key.dot1p,
                   key.prio,
                   key.pg,
                   key.queue_index,
                   key.color);
            printf("value: tc:%d, dscp:%d, dot1p:%d, prio:%d, pg:%d, queue_index:%d, color:%d\n",
                   value.tc,
                   value.dscp,
                   value.dot1p,
                   value.prio,
                   value.pg,
                   value.queue_index,
                   value.color);
        }
    }

    printf("default QOS ingress\n");
    printf("  dscp to color %u dscp_to tc %u pcpdei to color %u pcpdei to tc %u sdk_profile %p\n",
           m_default_ingress_qos_profile->m_dscp_to_color,
           m_default_ingress_qos_profile->m_dscp_to_tc,
           m_default_ingress_qos_profile->m_pcpdei_to_color,
           m_default_ingress_qos_profile->m_pcpdei_to_tc,
           (void*)m_default_ingress_qos_profile->m_sdk_profile);
    printf("  m_reference_count %d\n", m_default_ingress_qos_profile->ref_count());
    printf("default QOS egress\n");
    printf("  sdk_profile %p\n", (void*)m_default_egress_qos_profile->m_sdk_profile);
    printf("  m_reference_count %d\n", m_default_ingress_qos_profile->ref_count());
    printf("default tc profile\n");
    printf("  tc to queue %u sdk_profile %p\n", m_default_tc_profile->m_tc_to_queue, (void*)m_default_tc_profile->m_sdk_profile);
    printf("  m_reference_count %d\n", m_default_ingress_qos_profile->ref_count());
}

/**
 * @brief QOS MAP methods table retrieved with sai_api_query()
 */
const sai_qos_map_api_t qos_map_api
    = {lasai_qos::create_qos_map, lasai_qos::remove_qos_map, lasai_qos::set_qos_map_attribute, lasai_qos::get_qos_map_attribute};
}
}
