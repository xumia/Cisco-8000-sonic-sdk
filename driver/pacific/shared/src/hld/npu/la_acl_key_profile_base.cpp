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

#include "la_acl_key_profile_base.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/device_tree.h"
#include "runtime_flexibility_resources.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

static const npl_fwd0_table_index_e fwd0_160_table_indexes[]
    = {NPL_RTF_DB1_160_FWD0_TABLE, NPL_RTF_DB2_160_FWD0_TABLE, NPL_RTF_DB3_160_FWD0_TABLE, NPL_RTF_DB4_160_FWD0_TABLE};

static const npl_fwd0_table_index_e fwd0_320_table_indexes[]
    = {NPL_RTF_DB1_320_FWD0_TABLE, NPL_RTF_DB2_320_FWD0_TABLE, NPL_RTF_DB3_320_FWD0_TABLE, NPL_RTF_DB4_320_FWD0_TABLE};

static const npl_fwd1_table_index_e fwd1_160_table_indexes[]
    = {NPL_RTF_DB1_160_FWD1_TABLE, NPL_RTF_DB2_160_FWD1_TABLE, NPL_RTF_DB3_160_FWD1_TABLE, NPL_RTF_DB4_160_FWD1_TABLE};

static const npl_network_rx_eth_rtf_macro_table_id_e eth_rtf_macro_table_ids[]
    = {NPL_NETWORK_RX_ETH_RTF_MACRO_TABLE_ID_INGRESS_RTF_ETH_DB1_160_F0_TABLE,
       NPL_NETWORK_RX_ETH_RTF_MACRO_TABLE_ID_INGRESS_RTF_ETH_DB2_160_F0_TABLE};

static const npl_network_rx_ipv4_rtf_macro_table_id_e ipv4_160_f0_rtf_macro_table_ids[]
    = {NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB1_160_F0_TABLE,
       NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB2_160_F0_TABLE,
       NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB3_160_F0_TABLE,
       NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB4_160_F0_TABLE};

static const npl_network_rx_ipv4_rtf_macro_table_id_e ipv4_320_f0_rtf_macro_table_ids[]
    = {NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB1_320_F0_TABLE,
       NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB2_320_F0_TABLE,
       NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB3_320_F0_TABLE,
       NPL_NETWORK_RX_IPV4_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV4_DB4_320_F0_TABLE};

static const npl_network_rx_ipv6_rtf_macro_table_id_e ipv6_160_f0_rtf_macro_table_ids[]
    = {NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB1_160_F0_TABLE,
       NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB2_160_F0_TABLE,
       NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB3_160_F0_TABLE,
       NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB4_160_F0_TABLE};

static const npl_network_rx_ipv6_rtf_macro_table_id_e ipv6_320_f0_rtf_macro_table_ids[]
    = {NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB1_320_F0_TABLE,
       NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB2_320_F0_TABLE,
       NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB3_320_F0_TABLE,
       NPL_NETWORK_RX_IPV6_RTF_MACRO_TABLE_ID_INGRESS_RTF_IPV6_DB4_320_F0_TABLE};

static const npl_tables_e eth_160_f0_table_e[]
    = {NPL_TABLES_INGRESS_RTF_ETH_DB1_160_F0_TABLE, NPL_TABLES_INGRESS_RTF_ETH_DB2_160_F0_TABLE};

static const npl_tables_e ipv4_160_f0_table_e[] = {NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F0_TABLE};

static const npl_tables_e ipv4_320_f0_table_e[] = {NPL_TABLES_INGRESS_RTF_IPV4_DB1_320_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV4_DB2_320_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV4_DB3_320_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV4_DB4_320_F0_TABLE};

static const npl_tables_e ipv6_160_f0_table_e[] = {NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F0_TABLE};

static const npl_tables_e ipv6_320_f0_table_e[] = {NPL_TABLES_INGRESS_RTF_IPV6_DB1_320_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV6_DB2_320_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV6_DB3_320_F0_TABLE,
                                                   NPL_TABLES_INGRESS_RTF_IPV6_DB4_320_F0_TABLE};

la_acl_key_profile_base::la_acl_key_profile_base(const la_device_impl_wptr& device)
    : m_device(device), m_key_size(key_size_e::SIZE_160), m_tcam_pool_id(0)
{
}

la_acl_key_profile_base::~la_acl_key_profile_base()
{
}

la_status
la_acl_key_profile_base::initialize(la_object_id_t oid,
                                    la_acl_key_type_e key_type,
                                    la_acl_direction_e dir,
                                    const la_acl_key_def_vec_t& key_def,
                                    la_acl_tcam_pool_id_t tcam_pool_id)
{
    m_oid = oid;
    m_key_type = key_type;
    m_dir = dir;
    m_tcam_pool_id = tcam_pool_id;
    m_acl_key = key_def;
    m_udk_table_id = INVALID_UDK_TABLE_ID;
    m_fwd0_table_index = NPL_RTF_DB1_160_FWD0_TABLE;
    m_fwd1_table_index = NPL_RTF_DB1_160_FWD1_TABLE;
    la_status status;

    if (key_type == la_acl_key_type_e::SGACL) {

        return LA_STATUS_SUCCESS;
    }

    status = validate_key_profile(key_type, dir, key_def, tcam_pool_id);
    return_on_error(status);

    auto acl_key_profiles = m_device->get_objects(object_type_e::ACL_KEY_PROFILE);
    m_key_size = key_size_e::SIZE_160;

    if (dir == la_acl_direction_e::EGRESS) {
        if (key_type == la_acl_key_type_e::IPV4) {
            m_key_size = key_size_e::SIZE_160;
        } else {
            m_key_size = key_size_e::SIZE_320;
        }
        return LA_STATUS_SUCCESS;
    }

    uint64_t table_id = 0;
    status = allocate_table_id(key_type, m_key_size, tcam_pool_id, table_id);
    if (status != LA_STATUS_SUCCESS) {
        m_key_size = key_size_e::SIZE_320;
        status = allocate_table_id(key_type, m_key_size, tcam_pool_id, table_id);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD,
                    "la_acl_key_profile_base::%s failed to allocate table id for %s key type, tcam pool id %d",
                    __func__,
                    silicon_one::to_string(key_type).c_str(),
                    tcam_pool_id);
            return status;
        }
    }

    status = update_all_table_ids(key_type, m_key_size, tcam_pool_id, table_id);
    return_on_error(status);

    status = place_udk_for_key_type(key_type);
    if (status != LA_STATUS_SUCCESS) {
        // If key size 160 fail, retry place_udk with key size 320..
        if (m_key_size == key_size_e::SIZE_160) {
            // release current table_id (for 160 bit) and try to allocate new table_id (for 320 bit)
            status = release_table_id(m_key_type, m_key_size, tcam_pool_id, table_id);
            m_key_size = key_size_e::SIZE_320;
            status = allocate_table_id(key_type, m_key_size, tcam_pool_id, table_id);
            return_on_error(status);
            status = update_all_table_ids(key_type, m_key_size, tcam_pool_id, table_id);
            return_on_error(status);
            status = place_udk_for_key_type(key_type);
        }
    }
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "la_acl_key_profile_base::%s failed to place udk for key type %s",
                __func__,
                silicon_one::to_string(key_type).c_str());
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::destroy()
{
    la_status status;
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }
    if (m_dir == la_acl_direction_e::INGRESS) {
        status = release_table_id(m_key_type, m_key_size, m_tcam_pool_id, m_allocated_table_id);
        return_on_error(status);
        status = place_udk_for_key_type(m_key_type);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_acl_key_profile_base::type() const
{
    return object_type_e::ACL_KEY_PROFILE;
}

const la_device*
la_acl_key_profile_base::get_device() const
{
    return m_device.get();
}

uint64_t
la_acl_key_profile_base::oid() const
{
    return m_oid;
}

std::string
la_acl_key_profile_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_acl_key_profile_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_status
la_acl_key_profile_base::get_key_type(la_acl_key_type_e& out_key) const
{
    start_api_getter_call("");
    out_key = m_key_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_key_definition(la_acl_key_def_vec_t& out_key_def_vec) const
{
    start_api_getter_call("");
    out_key_def_vec = m_acl_key;

    return LA_STATUS_SUCCESS;
}

la_acl_tcam_pool_id_t
la_acl_key_profile_base::get_key_tcam_pool_id() const
{
    start_api_getter_call("");
    return m_tcam_pool_id;
}

la_acl_direction_e
la_acl_key_profile_base::get_direction() const
{
    start_api_getter_call("");
    return m_dir;
}

// Implementation
la_acl_key_profile_base::key_size_e
la_acl_key_profile_base::get_key_size() const
{
    start_api_getter_call("");

    return m_key_size;
}

uint64_t
la_acl_key_profile_base::get_udk_table_id() const
{
    return m_udk_table_id;
}

const udk_translation_info_sptr&
la_acl_key_profile_base::get_translation_info()
{
    if (m_trans_info.empty()) {
        m_trans_info.emplace_back();
    }
    return (m_trans_info.back()); // temoprary patch - to be extended in order to support multiple tables
}

la_status
la_acl_key_profile_base::update_all_acl_key_profiles()
{
    la_status status;
    la_acl_key_type_e key_type;

    auto acl_key_profiles = m_device->get_objects(object_type_e::ACL_KEY_PROFILE);
    for (auto acl_key_profile : acl_key_profiles) {
        la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile);
        acl_key_profile_impl->get_key_type(key_type);
        if (key_type == la_acl_key_type_e::SGACL) {
            continue;
        }
        status = acl_key_profile_impl->trans_info_update();
        return_on_error(status);
        status = acl_key_profile_impl->microcode_update();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::microcode_update()
{
    if (m_dir != la_acl_direction_e::INGRESS) {
        return LA_STATUS_SUCCESS;
    }

    ll_device_sptr lld = m_device->get_ll_device_sptr();

    if (m_device->is_simulated_device()) {
        lld_memory_scptr mem{};
        if (m_device->m_ll_device->is_gibraltar()) {
            auto tree = m_device->m_ll_device->get_gibraltar_tree();
            mem = tree->sim_access->mem_address_place_udk;
        } else if (m_device->m_ll_device->is_pacific()) {
            auto tree = m_device->m_ll_device->get_pacific_tree();
            mem = tree->sim_access->mem_address_place_udk;
        } else {
            return LA_STATUS_EINVAL;
        }
        la_status status = lld->write_memory(*mem, 0, 1, m_microcode_writes.back().width, m_microcode_writes.back().data);
        return_on_error(status);
    } else {
        la_status status;
        auto nw_slices = get_slices(m_device, la_slice_mode_e::NETWORK);
        for (la_slice_id_t sid : nw_slices) {
            if (m_device->m_ll_device->is_gibraltar()) {
                auto tree = m_device->m_ll_device->get_gibraltar_tree();
                for (auto& fwd_npe : tree->slice[sid]->npu->rxpp_fwd->npe) {
                    for (auto curr_microcode_write : m_microcode_writes) {
                        size_t msb = (curr_microcode_write.offset + curr_microcode_write.width) - 1;
                        size_t lsb = (curr_microcode_write.offset);
                        bit_vector data_to_write(curr_microcode_write.get_width_in_bytes(),
                                                 (const uint8_t*)curr_microcode_write.data,
                                                 curr_microcode_write.width);

                        if (curr_microcode_write.name == "lookup_keys_construction_low_buckets") {
                            int8_t arr_index = (curr_microcode_write.array_index == -1) ? 0 : curr_microcode_write.array_index;
                            lld_memory_scptr mem = (*fwd_npe->lookup_keys_construction_low_buckets)[arr_index];
                            status = lld->read_modify_write_memory(*mem, curr_microcode_write.line, msb, lsb, data_to_write);
                            return_on_error(status);
                        } else if (curr_microcode_write.name == "lookup_keys_construction_macro") {
                            lld_memory_scptr mem = fwd_npe->lookup_keys_construction_macro;
                            status = lld->read_modify_write_memory(*mem, curr_microcode_write.line, msb, lsb, data_to_write);
                            return_on_error(status);
                        } else if (curr_microcode_write.name == "scoper_macro") {
                            lld_memory_scptr mem = fwd_npe->scoper_macro;
                            status = lld->read_modify_write_memory(*mem, curr_microcode_write.line, msb, lsb, data_to_write);
                            return_on_error(status);
                        }
                    }
                }
            } else if (m_device->m_ll_device->is_pacific()) {
                auto tree = m_device->m_ll_device->get_pacific_tree();
                for (auto& fwd_npe : tree->slice[sid]->npu->rxpp_fwd->npe) {
                    for (auto curr_microcode_write : m_microcode_writes) {
                        size_t msb = (curr_microcode_write.offset + curr_microcode_write.width) - 1;
                        size_t lsb = (curr_microcode_write.offset);
                        bit_vector data_to_write(curr_microcode_write.get_width_in_bytes(),
                                                 (const uint8_t*)curr_microcode_write.data,
                                                 curr_microcode_write.width);

                        if (curr_microcode_write.name == "lookup_keys_construction_low_buckets") {
                            int8_t arr_index = (curr_microcode_write.array_index == -1) ? 0 : curr_microcode_write.array_index;
                            lld_memory_scptr mem = (*fwd_npe->lookup_keys_construction_low_buckets)[arr_index];
                            status = lld->read_modify_write_memory(*mem, curr_microcode_write.line, msb, lsb, data_to_write);
                            return_on_error(status);
                        } else if (curr_microcode_write.name == "lookup_keys_construction_macro") {
                            lld_memory_scptr mem = fwd_npe->lookup_keys_construction_macro;
                            status = lld->read_modify_write_memory(*mem, curr_microcode_write.line, msb, lsb, data_to_write);
                            return_on_error(status);
                        } else if (curr_microcode_write.name == "scoper_macro") {
                            lld_memory_scptr mem = fwd_npe->scoper_macro;
                            status = lld->read_modify_write_memory(*mem, curr_microcode_write.line, msb, lsb, data_to_write);
                            return_on_error(status);
                        }
                    }
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_fwd0_table_index(npl_fwd0_table_index_e& out_table_index) const
{
    out_table_index = m_fwd0_table_index;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_fwd1_table_index(npl_fwd1_table_index_e& out_table_index) const
{
    out_table_index = m_fwd1_table_index;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_eth_rtf_macro_table_id(npl_network_rx_eth_rtf_macro_table_id_e& out_table_id) const
{
    out_table_id = m_eth_rtf_macro_table_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_ipv4_rtf_macro_table_id(npl_network_rx_ipv4_rtf_macro_table_id_e& out_table_id) const
{
    out_table_id = m_ipv4_rtf_macro_table_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_ipv6_rtf_macro_table_id(npl_network_rx_ipv6_rtf_macro_table_id_e& out_table_id) const
{
    out_table_id = m_ipv6_rtf_macro_table_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_npl_table_id(npl_tables_e& out_npl_table) const
{
    out_npl_table = m_npl_table_e;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::get_allocated_table_id(uint64_t& out_table_id) const
{
    out_table_id = m_allocated_table_id;

    return LA_STATUS_SUCCESS;
}

// Helper functions

la_status
la_acl_key_profile_base::prepare_place_udk_data(la_acl_key_type_e key_type,
                                                std::vector<udk_table_id_and_components>& udk_table_id_and_components,
                                                std::vector<udk_translation_info>& trans_info)
{
    la_status status;
    auto acl_key_profiles = m_device->get_objects(object_type_e::ACL_KEY_PROFILE);
    for (auto acl_key_profile : acl_key_profiles) {
        la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile);
        if ((key_type == acl_key_profile_impl->m_key_type) && (acl_key_profile_impl->m_udk_table_id != INVALID_UDK_TABLE_ID)) {
            udk_table_id_and_components.emplace_back();
            udk_table_id_and_components.back().udk_table_id = acl_key_profile_impl->m_udk_table_id;
            trans_info.emplace_back();
            if (key_type == la_acl_key_type_e::ETHERNET) {
                status = fill_ethernet_udk_components(udk_table_id_and_components.back().udk_components,
                                                      acl_key_profile_impl->m_acl_key);
                return_on_error(status);
            } else if (key_type == la_acl_key_type_e::IPV4) {
                status = fill_v4_udk_components(udk_table_id_and_components.back().udk_components, acl_key_profile_impl->m_acl_key);
                return_on_error(status);
            } else if (key_type == la_acl_key_type_e::IPV6) {
                status = fill_v6_udk_components(udk_table_id_and_components.back().udk_components, acl_key_profile_impl->m_acl_key);
                return_on_error(status);
            } else {
                return LA_STATUS_EINVAL;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::place_udk_for_key_type(la_acl_key_type_e key_type)
{
    la_status status;
    auto acl_key_profiles = m_device->get_objects(object_type_e::ACL_KEY_PROFILE);
    auto result = get_compiler_udk_resources("network");
    udk_resources resources;
    switch (key_type) {
    case la_acl_key_type_e::ETHERNET:
        resources = result[NPL_NETWORK_RX_ETH_RTF_MACRO];
        break;
    case la_acl_key_type_e::IPV4:
        resources = result[NPL_NETWORK_RX_IPV4_RTF_MACRO];
        break;
    case la_acl_key_type_e::IPV6:
        resources = result[NPL_NETWORK_RX_IPV6_RTF_MACRO];
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    std::vector<udk_table_id_and_components> udk_table_id_and_components;
    std::vector<udk_translation_info> trans_info;
    std::vector<microcode_write> microcode_writes;
    status = prepare_place_udk_data(key_type, udk_table_id_and_components, trans_info);
    return_on_error(status);

    if (udk_table_id_and_components.size() == 0) {
        return LA_STATUS_SUCCESS;
    }

    // m_device->m_udk_library->set_verbose(true);
    place_udk_res res = m_device->m_udk_library->place_udk(resources, udk_table_id_and_components, microcode_writes, trans_info);
    if (res != place_udk_res::PLACE_UDK_RES_OK) {
        // If key size 160 fail, retry place_udk with key size 320
        if (m_key_size == key_size_e::SIZE_160) {
            // release current table_id (for 160 bit) and try to allocate new table_id (for 320 bit)
            status = release_table_id(m_key_type, m_key_size, m_tcam_pool_id, m_allocated_table_id);
            return_on_error(status);
            m_key_size = key_size_e::SIZE_320;
            status = allocate_table_id(key_type, m_key_size, m_tcam_pool_id, m_allocated_table_id);
            return_on_error(status);
            status = update_all_table_ids(key_type, m_key_size, m_tcam_pool_id, m_allocated_table_id);
            return_on_error(status);
            udk_table_id_and_components.clear();
            trans_info.clear();

            status = prepare_place_udk_data(key_type, udk_table_id_and_components, trans_info);
            return_on_error(status);
            res = m_device->m_udk_library->place_udk(resources, udk_table_id_and_components, microcode_writes, trans_info);
        }
    }
    if (res != place_udk_res::PLACE_UDK_RES_OK) {
        switch (res) {
        case place_udk_res::PLACE_UDK_RES_ENO_PLACEMENT:
            return LA_STATUS_ERESOURCE;
        case place_udk_res::PLACE_UDK_RES_EWRONG_ARGS:
            return LA_STATUS_EINVAL;
        case place_udk_res::PLACE_UDK_RES_EWRONG_KEY_SIZE:
            return LA_STATUS_EINVAL;
        case place_udk_res::PLACE_UDK_RES_ENOTIMPLEMENTED:
            return LA_STATUS_ENOTIMPLEMENTED;
        case place_udk_res::PLACE_UDK_RES_EUNKNOWN:
            return LA_STATUS_EUNKNOWN;
        default:
            return LA_STATUS_EINVAL;
        }
    }
    uint32_t i = 0;
    for (auto acl_key_profile : acl_key_profiles) {
        la_acl_key_profile_base* acl_key_profile_impl = static_cast<la_acl_key_profile_base*>(acl_key_profile);
        if ((key_type == acl_key_profile_impl->m_key_type) && (acl_key_profile_impl->m_udk_table_id != INVALID_UDK_TABLE_ID)) {
            acl_key_profile_impl->m_microcode_writes.clear();
            acl_key_profile_impl->m_microcode_writes = microcode_writes;
            acl_key_profile_impl->m_trans_info.clear();
            // acl_key_profile_impl->m_trans_info.push_back(trans_info[i]);
            acl_key_profile_impl->m_trans_info.push_back(
                std::shared_ptr<udk_translation_info>(new udk_translation_info(trans_info[i])));
            i++;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::trans_info_update()
{
    if (m_dir != la_acl_direction_e::INGRESS) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    auto trans_info = get_translation_info();
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        switch (m_npl_table_e) {
        case NPL_TABLES_INGRESS_RTF_ETH_DB1_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_eth_db1_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_ETH_DB2_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_eth_db2_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB1_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db1_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB2_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db2_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB3_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db3_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB4_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db4_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB1_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db1_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB2_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db2_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB3_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db3_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV4_DB4_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv4_db4_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB1_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db1_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB2_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db2_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB3_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db3_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB4_160_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db4_160_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB1_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db1_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB2_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db2_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB3_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db3_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        case NPL_TABLES_INGRESS_RTF_IPV6_DB4_320_F0_TABLE: {
            const auto& udk_table(m_device->m_tables.ingress_rtf_ipv6_db4_320_f0_table[slice]);
            status = udk_table->set_trans_info(trans_info.get());
            return_on_error(status);
        } break;
        default:
            break;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::validate_key_profile(la_acl_key_type_e key_type,
                                              la_acl_direction_e dir,
                                              const la_acl_key_def_vec_t& key_def,
                                              la_acl_tcam_pool_id_t tcam_pool_id) const
{
    if (tcam_pool_id == 1) {
        log_err(HLD, "la_acl_key_profile_base::%s tcam pool id 1 is not supported", __func__);
        return LA_STATUS_EINVAL;
    }

    if (key_type == la_acl_key_type_e::ETHERNET) {
        for (auto field_def : key_def) {
            if (std::find(LA_ACL_KEY_ETHERNET_FIELDS.begin(), LA_ACL_KEY_ETHERNET_FIELDS.end(), field_def.type)
                == LA_ACL_KEY_ETHERNET_FIELDS.end()) {
                log_err(HLD,
                        "la_acl_key_profile_base::%s Invalid field type %s for ethernet key profile",
                        __func__,
                        silicon_one::to_string(field_def.type).c_str());
                return LA_STATUS_EINVAL;
            }
        }
    } else if (key_type == la_acl_key_type_e::IPV4) {
        for (auto field_def : key_def) {
            if (std::find(LA_ACL_KEY_IPV4_AND_ETH_FIELDS.begin(), LA_ACL_KEY_IPV4_AND_ETH_FIELDS.end(), field_def.type)
                == LA_ACL_KEY_IPV4_AND_ETH_FIELDS.end()) {
                log_err(HLD,
                        "la_acl_key_profile_base::%s Invalid field type %s for ipv4 key profile",
                        __func__,
                        silicon_one::to_string(field_def.type).c_str());
                return LA_STATUS_EINVAL;
            }
        }
    } else if (key_type == la_acl_key_type_e::IPV6) {
        for (auto field_def : key_def) {
            if (std::find(LA_ACL_KEY_IPV6_AND_ETH_FIELDS.begin(), LA_ACL_KEY_IPV6_AND_ETH_FIELDS.end(), field_def.type)
                == LA_ACL_KEY_IPV6_AND_ETH_FIELDS.end()) {
                log_err(HLD,
                        "la_acl_key_profile_base::%s Invalid field type %s for ipv6 key profile",
                        __func__,
                        silicon_one::to_string(field_def.type).c_str());
                return LA_STATUS_EINVAL;
            }
        }
    }

    bool src_bincode = false;
    bool dst_bincode = false;
    for (auto field_def : key_def) {
        switch (field_def.type) {
        case la_acl_field_type_e::SRC_PCL_BINCODE:
            src_bincode = true;
            break;
        case la_acl_field_type_e::DST_PCL_BINCODE:
            dst_bincode = true;
            break;
        default:
            break;
        }
    }
    if ((src_bincode && !dst_bincode) || (!src_bincode && dst_bincode)) {
        log_err(HLD, "la_acl_key_profile_base::%s must include both SRC_PCL_BINCODE and DST_PCL_BINCODE", __func__);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::allocate_table_id(la_acl_key_type_e key_type,
                                           key_size_e key_size,
                                           la_acl_tcam_pool_id_t tcam_pool_id,
                                           uint64_t& out_table_id)
{
    if (m_dir != la_acl_direction_e::INGRESS) {
        log_err(HLD, "la_acl_key_profile_base::%s ERROR, only INGRESS direction is supported", __func__);
        return LA_STATUS_EINVAL;
    }

    bool is_success;

    if ((key_type == la_acl_key_type_e::ETHERNET) && (key_size == key_size_e::SIZE_160) && (tcam_pool_id == 0)) {
        is_success = m_device->m_index_generators.rtf_eth_f0_160_table_id.allocate(out_table_id);
    } else if ((key_type == la_acl_key_type_e::IPV4) && (key_size == key_size_e::SIZE_160) && (tcam_pool_id == 0)) {
        is_success = m_device->m_index_generators.rtf_ipv4_f0_160_table_id.allocate(out_table_id);
    } else if ((key_type == la_acl_key_type_e::IPV4) && (key_size == key_size_e::SIZE_320) && (tcam_pool_id == 0)) {
        is_success = m_device->m_index_generators.rtf_ipv4_f0_320_table_id.allocate(out_table_id);
    } else if ((key_type == la_acl_key_type_e::IPV6) && (key_size == key_size_e::SIZE_160) && (tcam_pool_id == 0)) {
        is_success = m_device->m_index_generators.rtf_ipv6_f0_160_table_id.allocate(out_table_id);
    } else if ((key_type == la_acl_key_type_e::IPV6) && (key_size == key_size_e::SIZE_320) && (tcam_pool_id == 0)) {
        is_success = m_device->m_index_generators.rtf_ipv6_f0_320_table_id.allocate(out_table_id);
    } else {
        return LA_STATUS_EINVAL;
    }

    if (!is_success) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::release_table_id(la_acl_key_type_e key_type,
                                          key_size_e key_size,
                                          la_acl_tcam_pool_id_t tcam_pool_id,
                                          uint64_t table_id)
{
    if (m_dir != la_acl_direction_e::INGRESS) {
        log_err(HLD, "la_acl_key_profile_base::%s ERROR, only INGRESS direction is supported", __func__);
        return LA_STATUS_EINVAL;
    }

    if ((key_type == la_acl_key_type_e::ETHERNET) && (key_size == key_size_e::SIZE_160) && (tcam_pool_id == 0)) {
        m_device->m_index_generators.rtf_eth_f0_160_table_id.release(table_id);
    } else if ((key_type == la_acl_key_type_e::IPV4) && (key_size == key_size_e::SIZE_160) && (tcam_pool_id == 0)) {
        m_device->m_index_generators.rtf_ipv4_f0_160_table_id.release(table_id);
    } else if ((key_type == la_acl_key_type_e::IPV4) && (key_size == key_size_e::SIZE_320) && (tcam_pool_id == 0)) {
        m_device->m_index_generators.rtf_ipv4_f0_320_table_id.release(table_id);
    } else if ((key_type == la_acl_key_type_e::IPV6) && (key_size == key_size_e::SIZE_160) && (tcam_pool_id == 0)) {
        m_device->m_index_generators.rtf_ipv6_f0_160_table_id.release(table_id);
    } else if ((key_type == la_acl_key_type_e::IPV6) && (key_size == key_size_e::SIZE_320) && (tcam_pool_id == 0)) {
        m_device->m_index_generators.rtf_ipv6_f0_320_table_id.release(table_id);
    } else {
        return LA_STATUS_EINVAL;
    }

    m_udk_table_id = INVALID_UDK_TABLE_ID;
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_key_profile_base::update_all_table_ids(la_acl_key_type_e key_type,
                                              key_size_e key_size,
                                              la_acl_tcam_pool_id_t tcam_pool_id,
                                              uint64_t table_id)
{
    // Update m_fwd0_table_index or m_fwd1_table_index
    if (tcam_pool_id == 0) {
        if (key_size == key_size_e::SIZE_160) {
            m_fwd0_table_index = fwd0_160_table_indexes[table_id];
        } else {
            m_fwd0_table_index = fwd0_320_table_indexes[table_id];
        }
    } else if (tcam_pool_id == 1) {
        if (key_size == key_size_e::SIZE_160) {
            m_fwd1_table_index = fwd1_160_table_indexes[table_id];
        } else {
            return LA_STATUS_EINVAL;
        }
    } else {
        return LA_STATUS_EINVAL;
    }

    // Update m_npl_table_e and (m_eth_rtf_macro_table_id or m_ipv4_rtf_macro_table_id or m_ipv6_rtf_macro_table_id)
    if (key_type == la_acl_key_type_e::ETHERNET) {
        if ((key_size == key_size_e::SIZE_160) && (tcam_pool_id == 0) && (table_id < 2)) {
            m_eth_rtf_macro_table_id = eth_rtf_macro_table_ids[table_id];
            m_udk_table_id = m_eth_rtf_macro_table_id;
            m_npl_table_e = eth_160_f0_table_e[table_id];
        } else {
            return LA_STATUS_EINVAL;
        }
    } else if (key_type == la_acl_key_type_e::IPV4) {
        if (tcam_pool_id == 0) {
            if (key_size == key_size_e::SIZE_160) {
                m_ipv4_rtf_macro_table_id = ipv4_160_f0_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv4_rtf_macro_table_id;
                m_npl_table_e = ipv4_160_f0_table_e[table_id];
            } else {
                m_ipv4_rtf_macro_table_id = ipv4_320_f0_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv4_rtf_macro_table_id;
                m_npl_table_e = ipv4_320_f0_table_e[table_id];
            }
#if 0
        } else if (tcam_pool_id == 1) {
            if (key_size == key_size_e::SIZE_160) {
                m_ipv4_rtf_macro_table_id = ipv4_160_f1_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv4_rtf_macro_table_id;
                m_npl_table_e = ipv4_160_f1_table_e[table_id];
            } else {
                m_ipv4_rtf_macro_table_id = ipv4_320_f2_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv4_rtf_macro_table_id;
                m_npl_table_e = ipv4_320_f1_table_e[table_id];
            }
#endif
        } else {
            return LA_STATUS_EINVAL;
        }
    } else if (key_type == la_acl_key_type_e::IPV6) {
        if (tcam_pool_id == 0) {
            if (key_size == key_size_e::SIZE_160) {
                m_ipv6_rtf_macro_table_id = ipv6_160_f0_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv6_rtf_macro_table_id;
                m_npl_table_e = ipv6_160_f0_table_e[table_id];
            } else {
                m_ipv6_rtf_macro_table_id = ipv6_320_f0_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv6_rtf_macro_table_id;
                m_npl_table_e = ipv6_320_f0_table_e[table_id];
            }
#if 0
        } else if (tcam_pool_id == 1) {
            if (key_size == key_size_e::SIZE_160) {
                m_ipv6_rtf_macro_table_id = ipv6_160_f1_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv6_rtf_macro_table_id;
                m_npl_table_e = ipv6_160_f1_table_e[table_id];
            } else {
                m_ipv6_rtf_macro_table_id = ipv6_320_f1_rtf_macro_table_ids[table_id];
                m_udk_table_id = m_ipv6_rtf_macro_table_id;
                m_npl_table_e = ipv6_320_f1_table_e[table_id];
            }
#endif
        } else {
            return LA_STATUS_EINVAL;
        }
    } else {
        return LA_STATUS_EINVAL;
    }

    m_allocated_table_id = table_id;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
