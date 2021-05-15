// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "hw_tables/cem.h"
#include "common/bit_utils.h"
#include "common/bit_vector.h"
#include "common/dassert.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"

#include <chrono>
#include <thread>

#include <sys/stat.h>

namespace silicon_one
{
using namespace std::chrono;

enum {
    CEM_ARC_STATUS_BIT_INDEX = 14,        // 14 bit in valid_reg register in cdb->top symbolize CPU command
    CEM_ARC_CPU_REGISTER_WIDTH_BYTES = 4, // Each ARC regsiter is 32 bit / 4 bytes.

    CEM_ARC_STATUS_REG_VAL = (1 << CEM_ARC_STATUS_BIT_INDEX), // 14 bit in valid_reg register in cdb->top symbolize CPU command
    CEM_ARC_STATUS_REG_MASK = CEM_ARC_STATUS_REG_VAL,

    CEM_NUM_EM_ENTRIES_PER_BANK = 1 << 11, // 2k entries per bank.
    CEM_NUM_EM_ENTRIES_PER_CAM = 32,

    // The length of the hashed key is 78 bit, the 11 msb bits are used for the address in the bank.
    HASHER_KEY_WIDTH = 78,
    BANK_ADDRESS_LENGTH = 11,
    // The verifier bits are the hashed key without the address in the bank, i.e. [66:0]
    VERIFIER_RANGE_MSB = HASHER_KEY_WIDTH - BANK_ADDRESS_LENGTH - 1,
    VERIFIER_RANGE_LSB = 0,
    // Before hashing the key, we XOR its two parts, the first part is the 78 (HASHER_KEY_WIDTH) msb bits, while the second part
    // is the rest of the key. The XOR is performed with second part aligned to left, i.e. we shift it by 14 bits to left.
    PRE_HASH_KEY_MSB_PART_MSB = 141,
    PRE_HASH_KEY_MSB_PART_LSB = PRE_HASH_KEY_MSB_PART_MSB - HASHER_KEY_WIDTH + 1,
    PRE_HASH_KEY_LSB_PART_MSB = PRE_HASH_KEY_MSB_PART_LSB - 1,
    PRE_HASH_KEY_LSB_PART_LSB = 0,
    PRE_HASH_KEY_LSB_SHIFT_LENGTH = HASHER_KEY_WIDTH - (PRE_HASH_KEY_LSB_PART_MSB - PRE_HASH_KEY_LSB_PART_LSB + 1),
};

static const la_status arc_status_to_la_status[ARC_CPU_COMMAND_STATUS_LAST] = {
        [ARC_CPU_COMMAND_STATUS_SUCCESS] = LA_STATUS_SUCCESS,
        [ARC_CPU_COMMAND_STATUS_EUNKNOWN] = LA_STATUS_EUNKNOWN,
        [ARC_CPU_COMMAND_STATUS_ERESOURCE] = LA_STATUS_ERESOURCE,
        [ARC_CPU_COMMAND_STATUS_ELIMIT] = LA_STATUS_ERESOURCE,
        [ARC_CPU_COMMAND_STATUS_EEXIST] = LA_STATUS_EEXIST,
        [ARC_CPU_COMMAND_STATUS_ENOTFOUND] = LA_STATUS_ENOTFOUND,
        [ARC_CPU_COMMAND_STATUS_EINVAL] = LA_STATUS_EINVAL,
        [ARC_CPU_COMMAND_STATUS_ENOTIMPLEMENTED] = LA_STATUS_ENOTIMPLEMENTED,
};

static const char* arc_status_to_str[ARC_CPU_COMMAND_STATUS_LAST] = {
        [ARC_CPU_COMMAND_STATUS_SUCCESS] = "SUCCESS",
        [ARC_CPU_COMMAND_STATUS_EUNKNOWN] = "UNKNOWN",
        [ARC_CPU_COMMAND_STATUS_ERESOURCE] = "RESOURCE",
        [ARC_CPU_COMMAND_STATUS_ELIMIT] = "LIMIT",
        [ARC_CPU_COMMAND_STATUS_EEXIST] = "EXISTS",
        [ARC_CPU_COMMAND_STATUS_ENOTFOUND] = "NOTFOUND",
        [ARC_CPU_COMMAND_STATUS_EINVAL] = "INVAL",
        [ARC_CPU_COMMAND_STATUS_ENOTIMPLEMENTED] = "ENOTIMPLEMENTED",
};

static const char* arc_feature_to_str[ARC_CPU_FEATURE_TYPE_LAST + 1] = {
        [ARC_CPU_FEATURE_TYPE_NONE] = "UNUSED",
        [ARC_CPU_FEATURE_TYPE_LEARN_MODE] = "MAC learning mode",
        [ARC_CPU_FEATURE_TYPE_AGE_MODE] = "MAC aging mode",
        [ARC_CPU_FEATURE_TYPE_AGE_NOTIFICATION] = "MAC age notificaiton",
        [ARC_CPU_FEATURE_TYPE_AGE_INTERVAL] = "MAC age scanning interval",
};

// Set once ARC reaches timeout
bool timeout_occured = false;

cem::cem(const ll_device_sptr& device)
    : m_ll_device(device),
      m_wide_keys_to_storage_data(),
      m_hashed_keys_msb_to_cores_bitmap(),
      m_core_to_cam_keys(std::vector<std::vector<bit_vector> >(NUM_EM_CORES)),
      m_resource_monitor(nullptr),
      m_usage(0),
      m_cem_parameters(cem_parameters::get_params(device->get_device_revision()))
{
    // We need hashers for even banks only.
    for (size_t bank_index = 0; bank_index < m_cem_parameters.num_banks; bank_index += 2) {
        em::hasher_params hasher_params;
        generate_default_hasher_params(HASHER_KEY_WIDTH, bank_index, hasher_params);
        em_hasher hasher(HASHER_KEY_WIDTH, hasher_params);
        m_hashers.push_back(hasher);
    }

    if (m_ll_device->is_gibraltar()) {
        const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();
        m_cdb_top_storage = std::vector<cdb_top_storage>(1);
        initialize_cdb_top_references(tree->cdb->top, 0);
        m_cdb_top_storage[0].em_key_width = tree->cdb->top->em_key_width;
    } else if (m_ll_device->is_pacific()) {
        const pacific_tree* tree = m_ll_device->get_pacific_tree();
        m_cdb_top_storage = std::vector<cdb_top_storage>(1);
        initialize_cdb_top_references(tree->cdb->top, 0);
        m_cdb_top_storage[0].em_key_width = tree->cdb->top->em_key_width;
    } else {
        // new device - add it
        dassert_crit(false);
    }
    dassert_crit(m_cdb_top_storage.size() > 0);
}

cem::~cem()
{
}

template <class _Lambda>
la_status
cem::for_each_cdb(_Lambda lambda)
{
    std::vector<la_status> stats;
    for (auto cdb : m_cdb_top_storage) {
        la_status stat = lambda(cdb);
        for (la_status prev_stat : stats) {
            if (stat != prev_stat) {
                log_err(TABLES, "cem::%s: all stats should be equal", __func__);
                return LA_STATUS_EUNKNOWN;
            }
        }
        return_on_error(stat);
        stats.push_back(stat);
    }
    return stats[0];
}

la_status
cem::init_arc(const std::string& iccm_file, const std::string& dccm_file)
{
    la_status status = for_each_cdb([&](cdb_top_storage cdb) { return init_arc(iccm_file, dccm_file, cdb); });
    return_on_error(status);

    status = set_key_size_map_value();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
cem::init_arc(const std::string& iccm_file, const std::string& dccm_file, cdb_top_storage& cdb)
{
    la_status status = LA_STATUS_SUCCESS;
    if (m_ll_device->is_gibraltar()) {
        gibraltar::cdb_top_arc_control_registers_register arc_control_registers_val = {.u8 = {0}};
        arc_control_registers_val.fields.run_req = 0;
        // Stop ARC
        status = m_ll_device->write_register(*cdb.arc_control_registers, arc_control_registers_val);
    } else {
        cdb_top_arc_control_registers_register arc_control_registers_val = {.u8 = {0}};
        arc_control_registers_val.fields.run_req = 0;
        // Stop ARC
        status = m_ll_device->write_register(*cdb.arc_control_registers, arc_control_registers_val);
    }
    return_on_error(status);

    // ICCM
    size_t iccm_mem_entries = cdb.cem_iccm->get_desc()->entries;
    status = load_arc_microcode(true /* is_iccm */, iccm_mem_entries, iccm_file, cdb);
    return_on_error(status);

    // DCCM
    size_t dccm_mem_entries = cdb.cem_dccm->get_desc()->entries;
    status = load_arc_microcode(false /* is_iccm */, dccm_mem_entries, dccm_file, cdb);
    return_on_error(status);

    // Disable interrupts towards ARC
    // 17 - learn,
    // 18 - em_response,
    // 19 - aging,
    // 20 - bulk update,
    // 21 - cpu
    if (m_ll_device->is_gibraltar()) {
        gibraltar::cdb_top_arc_interrupt_masks_register irq_mask_val = {.u8 = {0}};
        irq_mask_val.fields.interrupt_mask = bit_utils::ones(irq_mask_val.fields.INTERRUPT_MASK_WIDTH); // 0x1f
        status = m_ll_device->write_register(*cdb.arc_interrupt_masks, irq_mask_val);
    } else {
        cdb_top_arc_interrupt_masks_register irq_mask_val = {.u8 = {0}};
        irq_mask_val.fields.interrupt_mask = bit_utils::ones(irq_mask_val.fields.INTERRUPT_MASK_WIDTH); // 0x1f
        status = m_ll_device->write_register(*cdb.arc_interrupt_masks, irq_mask_val);
    }
    return_on_error(status);

    status = reset_arc_counters(cdb);
    return_on_error(status);

    // Prep CPU REGISTERS
    size_t entries = sizeof(arc_cpu_command) / CEM_ARC_CPU_REGISTER_WIDTH_BYTES;
    arc_cpu_command command;
    memset(&command, 0, sizeof(arc_cpu_command));
    // Write data first (CPU register 1 --- 7)
    for (uint32_t reg_index = 1; reg_index < entries; ++reg_index) {
        status = m_ll_device->write_register(*(*cdb.access_reg)[reg_index + m_cem_parameters.cem_arc_cpu_register_start_addr],
                                             CEM_ARC_CPU_REGISTER_WIDTH_BYTES,
                                             ((uint32_t*)&command) + reg_index);
        return_on_error(status);
    }

    // Write command last (CPU register 0)
    command.state = ARC_CPU_FSM_STATE_CPU;
    command.command = ARC_CPU_COMMAND_NONE;
    command.status = ARC_CPU_COMMAND_STATUS_NONE;
    status = m_ll_device->write_register(*(*cdb.access_reg)[m_cem_parameters.cem_arc_cpu_register_start_addr],
                                         CEM_ARC_CPU_REGISTER_WIDTH_BYTES,
                                         ((uint32_t*)&command));
    return_on_error(status);

    // Start ARC
    if (m_ll_device->is_gibraltar()) {
        gibraltar::cdb_top_arc_control_registers_register arc_control_registers_val = {.u8 = {0}};
        arc_control_registers_val.fields.run_req = 1;
        status = m_ll_device->write_register(*cdb.arc_control_registers, arc_control_registers_val);
    } else {
        cdb_top_arc_control_registers_register arc_control_registers_val = {.u8 = {0}};
        arc_control_registers_val.fields.run_req = 1;
        status = m_ll_device->write_register(*cdb.arc_control_registers, arc_control_registers_val);
    }
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
cem::set_switch_mac_limit(la_uint32_t switch_id, la_uint64_t current_max_mac, la_uint64_t new_max_mac)
{
    log_debug(TABLES, "cem::set_switch_mac_limit(relay_id: %d, curr: %lld, new: %lld)", switch_id, current_max_mac, new_max_mac);

    arc_cpu_command max_mac_command;
    memset(&max_mac_command, 0, sizeof(arc_cpu_command));

    max_mac_command.params.obj_params.object_id = switch_id;

    // If current and new_max are max_macs, ARC need to initialize the counter
    if (new_max_mac == MAX_MAC_PER_SWITCH_NO_LIMIT_VALUE && current_max_mac == MAX_MAC_PER_SWITCH_NO_LIMIT_VALUE) {
        max_mac_command.command = ARC_CPU_COMMAND_SWITCH_INIT_MAC;
        max_mac_command.params.obj_params.object_data = new_max_mac;
    } else {
        max_mac_command.command = ARC_CPU_COMMAND_SWITCH_MAX_MAC;
        max_mac_command.params.obj_params.object_data = (int32_t)new_max_mac - current_max_mac;
    }

    la_status status = dispatch_arc_command(&max_mac_command);

    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
cem::lookup(const bit_vector& key, bit_vector& out_value_bv, cem_location& out_location)
{
    log_debug(TABLES, "cem::lookup key: %s", key.to_string().c_str());
    la_status status = LA_STATUS_SUCCESS;
    out_location.valid = false;

    arc_cpu_command cmd = init_table_command_params(key, out_value_bv);

    // Read key/value
    cmd.command = ARC_CPU_COMMAND_LOOKUP_KEY;
    status = dispatch_arc_command(&cmd, m_cdb_top_storage[0]);
    return_on_error(status);

    arc_cpu_command resp;
    status = read_arc_response(resp, m_cdb_top_storage[0]);
    return_on_error(status);

    out_value_bv = bit_vector(
        MAX_TABLE_PAYLOAD_LEN_IN_BYTES, (uint8_t*)resp.params.table_params.payload, MAX_TABLE_PAYLOAD_LEN_IN_BYTES * 8);

    // Read location
    cmd.command = ARC_CPU_COMMAND_LAST_LOOKUP_LOCATION;
    status = dispatch_arc_command(&cmd, m_cdb_top_storage[0]);
    return_on_error(status);

    status = read_arc_response(resp, m_cdb_top_storage[0]);
    return_on_error(status);

    out_location.valid = true;
    out_location.em_core_idx = resp.params.location_params.core;
    out_location.em_bank_idx = resp.params.location_params.bank;
    out_location.em_index = resp.params.location_params.index;
    out_location.key_size = resp.params.location_params.key_size;

    return LA_STATUS_SUCCESS;
}

la_status
cem::read(const cem_location& location, bit_vector& out_key_bv, bit_vector& out_value_bv)
{
    log_debug(TABLES, "cem::read(core=%lu, bank=%lu, index=%lu)", location.em_core_idx, location.em_bank_idx, location.em_index);
    la_status status = LA_STATUS_SUCCESS;

    arc_cpu_command cmd{};
    cmd.params.location_params.core = location.em_core_idx;
    cmd.params.location_params.bank = location.em_bank_idx;
    cmd.params.location_params.index = location.em_index;
    cmd.command = ARC_CPU_COMMAND_READ_ENTRY;

    status = dispatch_arc_command(&cmd, m_cdb_top_storage[0]);
    return_on_error(status);

    arc_cpu_command resp;
    status = read_arc_response(resp, m_cdb_top_storage[0]);
    return_on_error(status);

    out_key_bv = bit_vector(MAX_TABLE_KEY_LEN_IN_BYTES, (uint8_t*)resp.params.table_params.key, MAX_TABLE_KEY_LEN_IN_BYTES * 8);
    out_value_bv = bit_vector(
        MAX_TABLE_PAYLOAD_LEN_IN_BYTES, (uint8_t*)resp.params.table_params.payload, MAX_TABLE_PAYLOAD_LEN_IN_BYTES * 8);

    return LA_STATUS_SUCCESS;
}

la_status
cem::read_age(const bit_vector& key, const bit_vector& value, cem_age_info& out_age_info)
{
    log_debug(TABLES, "cem::read_age key: %s", key.to_string().c_str());
    la_status status = LA_STATUS_SUCCESS;

    arc_cpu_command cmd = init_table_command_params(key, value);
    cmd.command = ARC_CPU_COMMAND_AGE_READ_ENTRY;
    status = dispatch_arc_command(&cmd, m_cdb_top_storage[0]);
    return_on_error(status);

    arc_cpu_command resp;
    status = read_arc_response(resp, m_cdb_top_storage[0]);
    return_on_error(status);

    out_age_info.age_owner = resp.params.table_age_params.age_owner;
    out_age_info.age_value = resp.params.table_age_params.age;

    return LA_STATUS_SUCCESS;
}

la_status
cem::set_table_single_entry(const bit_vector& key, const bit_vector& value)
{
    arc_cpu_command cmd = init_table_command_params(key, value);
    cmd.command = ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY;

    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);

    return status;
}

la_status
cem::insert_table_single_entry(const bit_vector& key, const bit_vector& value)
{
    log_debug(TABLES, "cem::%s: key: %s payload: %s", __func__, key.to_string().c_str(), value.to_string().c_str());
    la_status status = set_table_single_entry(key, value);
    return_on_error(status);

    return status;
}

la_status
cem::update_table_single_entry(const bit_vector& key, const bit_vector& value)
{
    log_debug(TABLES, "cem::%s: key: %s payload: %s", __func__, key.to_string().c_str(), value.to_string().c_str());

    la_status status = set_table_single_entry(key, value);
    return_on_error(status);

    return status;
}

la_status
cem::erase_table_single_entry(const bit_vector& key)
{
    log_debug(TABLES, "cem::erase_table_single_entry key: %s", key.to_string().c_str());

    arc_cpu_command cmd = init_table_command_params(key, bit_vector());
    cmd.command = ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY;

    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);
    if (m_ll_device->is_pacific() && cmd.params.location_params.bank != ARC_CAM_BANK_IDX) {
        m_erase_bitset |= (1 << cmd.params.location_params.core);
    }
    return status;
}

la_status
cem::set_table_double_entry(const bit_vector& key, const bit_vector& value)
{
    // HW issue: Wide keys are stored in two consequtive banks,
    // the first is even bank and we store there the msb half of the hashed key, and the second is an odd bank which contains
    // the lsb. When a lookup for wide key happens, HW will search in even banks, if it hits the msb part of the key,
    // it will search the lsb part in the bank after it, if it misses, it will return miss without continuing the lookup
    // in the next banks. This may cause a false-miss in case two keys have the msb half after hashing in one bank.
    // WA: when we insert a new double entry, we pass to the ARC a bitmap that indicates the allowed cores,
    // those are all the cores that don't contain any key that may collide with the new key.
    // To be able to compute this bitmap, we need to remember the core each key was inserted to.
    wide_key_storage_data storage_data;
    populate_wide_key_hashed_values(key, storage_data);

    arc_cpu_command cmd = init_table_command_params(key, value);
    cmd.command = ARC_CPU_COMMAND_INSERT_TABLE_DOUBLE_ENTRY;

    uint32_t cores = get_allowed_cores_bitmap_of_key(storage_data);

    cmd.candidate_cores_bitmap = cores;

    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);

    add_wide_key_to_shadow(key, cmd, storage_data);

    return status;
}

la_status
cem::insert_table_double_entry(const bit_vector& key, const bit_vector& value)
{
    log_debug(TABLES, "cem::%s: key: %s payload: %s", __func__, key.to_string().c_str(), value.to_string().c_str());
    la_status status = set_table_double_entry(key, value);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
cem::update_table_double_entry(const bit_vector& key, const bit_vector& value)
{
    log_debug(TABLES, "cem::%s: key: %s payload: %s", __func__, key.to_string().c_str(), value.to_string().c_str());

    la_status status = set_table_double_entry(key, value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
cem::erase_table_double_entry(const bit_vector& key)
{
    log_debug(TABLES, "cem::erase_table_double_entry key: %s", key.to_string().c_str());

    arc_cpu_command cmd = init_table_command_params(key, bit_vector());
    cmd.command = ARC_CPU_COMMAND_ERASE_TABLE_DOUBLE_ENTRY;

    la_status status = dispatch_arc_command(&cmd);

    return_on_error(status);

    bool key_had_shadow = erase_wide_key_from_shadow(key, cmd.params.location_params.core);

    if (key_had_shadow) {
        m_erase_bitset |= (1 << cmd.params.location_params.core);
    }

    return LA_STATUS_SUCCESS;
}

arc_cpu_command
cem::init_table_command_params(const bit_vector& key, const bit_vector& value)
{
    arc_cpu_command ret;
    memset(&ret, 0, sizeof(arc_cpu_command));

    memcpy(ret.params.table_params.key, key.byte_array(), key.get_width_in_bytes());
    if (!value.is_null()) {
        memcpy(ret.params.table_params.payload, value.byte_array(), value.get_width_in_bytes());
    }

    return ret;
}

bit_vector
cem::generate_key_for_hasher(const bit_vector& key) const
{
    // Before hashing the key, we XOR its two halfs, the msb part is the 78 msb bits i.e. [141:64],
    // the lsb part is of length 64 and its value is the rest of the key [63:0].
    // When we XOR the two parts, we align the lsb part to the left, i.e. we shift it to left by 14.
    bit_vector msb_part = key.bits(PRE_HASH_KEY_MSB_PART_MSB, PRE_HASH_KEY_MSB_PART_LSB);
    bit_vector lsb_part = key.bits(PRE_HASH_KEY_LSB_PART_MSB, PRE_HASH_KEY_LSB_PART_LSB);
    lsb_part = lsb_part << PRE_HASH_KEY_LSB_SHIFT_LENGTH;
    return msb_part ^ lsb_part;
}

void
cem::populate_wide_key_hashed_values(const bit_vector& key, wide_key_storage_data& storage_data) const
{
    bit_vector key_to_hash = generate_key_for_hasher(key);
    storage_data.hashed_values.resize(m_cem_parameters.num_even_banks);

    for (size_t hasher_index = 0; hasher_index < m_cem_parameters.num_even_banks; hasher_index++) {
        hashed_key hk = m_hashers[hasher_index].encrypt(key_to_hash);
        // We need the MSB half only.
        hk = hk.bits(VERIFIER_RANGE_MSB, VERIFIER_RANGE_LSB);
        storage_data.hashed_values[hasher_index] = hk;
    }
}

uint32_t
cem::get_allowed_cores_bitmap_of_key(const wide_key_storage_data& storage_data) const
{
    cores_bitmap cores;

    if (!m_ll_device->is_pacific()) {
        // WA needed in Pacific only
        cores = 0;
    } else {
        for (size_t hasher_index = 0; hasher_index < m_cem_parameters.num_even_banks; hasher_index++) {
            hashed_key hk = storage_data.hashed_values[hasher_index];
            auto it = m_hashed_keys_msb_to_cores_bitmap.find(hk);
            if (it != m_hashed_keys_msb_to_cores_bitmap.end()) { // this hashed value exists
                cores |= it->second;
            }
        }
    }
    // We collected the colliding cores, so we flip the bitmap to get allowed cores turned on.
    cores.flip();
    return (uint32_t)cores.to_ulong();
}

void
cem::add_wide_key_to_shadow(const bit_vector& key, const arc_cpu_command arc_command, wide_key_storage_data& storage_data)
{
    if (!m_ll_device->is_pacific()) {
        // WA needed in Pacific only
        return;
    }

    if (arc_command.params.location_params.bank == ARC_CAM_BANK_IDX) {
        std::vector<bit_vector>& cam_keys = m_core_to_cam_keys[arc_command.params.location_params.core];
        if (std::find(cam_keys.begin(), cam_keys.end(), key) == cam_keys.end()) {
            cam_keys.push_back(key);
        }
        // the key was inserted to cam, update core and return. Nothing to do with hashed keys.
        storage_data.core = INVALID_CORE_OR_CAM;
        m_wide_keys_to_storage_data[key] = storage_data;
        return;
    }

    // set the core of this storage data.
    storage_data.core = arc_command.params.location_params.core;
    // Update m_hashed_keys_msb_to_cores_bitmap.
    cores_bitmap added_core;
    added_core.set(storage_data.core, 1);
    for (size_t hasher_index = 0; hasher_index < m_cem_parameters.num_even_banks; hasher_index++) {
        hashed_key hk = storage_data.hashed_values[hasher_index];
        auto it = m_hashed_keys_msb_to_cores_bitmap.find(hk);
        if (it != m_hashed_keys_msb_to_cores_bitmap.end()) { // this hashed value exists
            it->second |= added_core;                        // turn on the bit of the current core.
        } else {
            m_hashed_keys_msb_to_cores_bitmap[hk] = added_core;
        }
    }
    m_wide_keys_to_storage_data[key] = storage_data;
}

la_status
cem::set_key_size_map_value()
{
    arc_cpu_command cmd;
    memset(&cmd, 0, sizeof(arc_cpu_command));
    bit_vector key_size_map_value;
    m_ll_device->read_register(*m_cdb_top_storage[0].em_key_width, key_size_map_value);
    cmd.params.location_params.key_size = static_cast<uint32_t>(key_size_map_value.get_value());
    cmd.command = ARC_CPU_COMMAND_SET_KEY_SIZE_MAP_VALUE;
    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);
    return status;
}

la_status
cem::evacuation_routine()
{
    la_status status = LA_STATUS_SUCCESS;
    std::vector<bit_vector>& cam_keys = m_core_to_cam_keys[m_curr_evacuation_core];
    bit_vector& key = cam_keys[m_evacuation_index];
    auto it = m_wide_keys_to_storage_data.find(key);
    dassert_crit(it != m_wide_keys_to_storage_data.end());
    wide_key_storage_data& storage_data = it->second;
    uint32_t allowed_cores_bitmap = get_allowed_cores_bitmap_of_key(storage_data);
    uint32_t curr_core_bitmap = (1 << m_curr_evacuation_core);
    if (allowed_cores_bitmap & curr_core_bitmap) {
        arc_cpu_command cmd = init_table_command_params(key, bit_vector());
        cmd.candidate_cores_bitmap = curr_core_bitmap;
        cmd.command = ARC_CPU_COMMAND_EVACUATE_TABLE_DOUBLE_ENTRY;
        status = dispatch_arc_command(&cmd);
        if (status == LA_STATUS_SUCCESS) { // succesful evacuation
            cmd.params.location_params.core = m_curr_evacuation_core;
            add_wide_key_to_shadow(key, cmd, m_wide_keys_to_storage_data[key]);
            cam_keys.erase(cam_keys.begin() + m_evacuation_index);
            return status;
        } else if (status == LA_STATUS_ERESOURCE) {
            // successful functionallity, but unsuccesful evacuation
            status = LA_STATUS_SUCCESS;
        }
    }
    m_evacuation_index++;
    return status;
}

la_status
cem::evacuate()
{
    log_debug(TABLES, "cem::%s", __func__);
    la_status status = LA_STATUS_SUCCESS;
    if (m_evacuation_index < m_core_to_cam_keys[m_curr_evacuation_core].size()) {
        status = evacuation_routine();
        return_on_error(status);
        return status;
    }
    // check all cores until the first erased-core
    while (m_erase_bitset) {
        m_curr_evacuation_core = (m_curr_evacuation_core + 1) % NUM_EM_CORES;
        uint32_t curr_core_bit = (1 << m_curr_evacuation_core);
        if (m_erase_bitset & curr_core_bit) {
            log_debug(TABLES, "%s: core: %lu", __func__, m_curr_evacuation_core);
            m_erase_bitset &= ~curr_core_bit;
            m_evacuation_index = 0;
            break;
        }
    }
    return status;
}

bool
cem::erase_wide_key_from_shadow(const bit_vector& key, uint32_t core)
{
    if (!m_ll_device->is_pacific()) {
        // WA needed in Pacific only
        return false;
    }

    auto it = m_wide_keys_to_storage_data.find(key);
    dassert_crit(it != m_wide_keys_to_storage_data.end());
    wide_key_storage_data storage_data = it->second;
    m_wide_keys_to_storage_data.erase(key);
    if (storage_data.core == INVALID_CORE_OR_CAM) {
        std::vector<bit_vector>& cam_keys = m_core_to_cam_keys[core];
        auto delete_it = std::find(cam_keys.begin(), cam_keys.end(), key);
        dassert_crit(delete_it != cam_keys.end());
        if (core == m_curr_evacuation_core && m_evacuation_index > uint32_t(delete_it - cam_keys.begin())) {
            m_evacuation_index--;
        }
        cam_keys.erase(delete_it);
        // This key was added to CAM, so nothing to do more than deleting it from m_wide_keys_to_storage_data.
        return false;
    }

    // Update m_hashed_keys_msb_to_cores_bitmap.
    for (size_t hasher_index = 0; hasher_index < m_cem_parameters.num_even_banks; hasher_index++) {
        hashed_key hk = storage_data.hashed_values[hasher_index];
        auto it = m_hashed_keys_msb_to_cores_bitmap.find(hk);
        dassert_crit(it != m_hashed_keys_msb_to_cores_bitmap.end()); // The hashed key must be there.
        it->second.set(storage_data.core, 0);                        // turn off the bit of the matching core.
    }
    return true;
}

la_status
cem::read_status_register_loop(bit_vector& out_message, cdb_top_storage& cdb) const
{
    la_status status;
    size_t max_read_attempts = 10;
    size_t read_attempts_per_itr;
    if (m_ll_device->is_simulated_device()) {
        read_attempts_per_itr = 1;
    } else {
        read_attempts_per_itr = STATUS_REGISTER_READ_ATTEMPTS;
    }
    bit_vector first_message(0);
    bit_vector current_message(0);
    bool iteration_success = false;

    for (size_t itr = 0; itr < max_read_attempts && !iteration_success; ++itr) {
        iteration_success = true;
        status = m_ll_device->read_register(*(*cdb.access_reg)[m_cem_parameters.cem_arc_cpu_register_start_addr], first_message);
        return_on_error(status);

        for (size_t i = 1; i < read_attempts_per_itr; ++i) {
            status
                = m_ll_device->read_register(*(*cdb.access_reg)[m_cem_parameters.cem_arc_cpu_register_start_addr], current_message);
            return_on_error(status);
            if (current_message.get_value() != first_message.get_value()) {
                iteration_success = false;
                break;
            }
        }
    }

    if (!iteration_success) {
        log_crit(TABLES, "%s: Too much fickleness while reading ARC status register", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    out_message = first_message;
    return LA_STATUS_SUCCESS;
}

la_status
cem::dispatch_arc_command(arc_cpu_command* command)
{
    std::vector<arc_cpu_command> cmds;
    la_status stat = for_each_cdb([&](cdb_top_storage& cdb) {
        cmds.push_back(*command);
        return dispatch_arc_command(&cmds.back(), cdb);
    });
    return_on_error(stat);
    dassert_crit(cmds.size() > 0);
    // Assuming the cmds are equal
    *command = cmds.back();
    return stat;
}

la_status
cem::dispatch_arc_command(arc_cpu_command* command, cdb_top_storage& cdb) const
{
    // NOTE cdb->top->valid_reg errata in pacific
    // This register has multiple writers and the priority is designed with
    // the following order, CPU, HW and ARC.
    // Because of this order, there are risks for ARC halt.
    //
    // Workaround: avoid using valid_reg between CPU and ARC. Use access_reg[36]
    // for command and status communications.

    la_status stat;

    size_t entries = sizeof(arc_cpu_command) / CEM_ARC_CPU_REGISTER_WIDTH_BYTES;

    if (timeout_occured) {
        log_err(RA, "%s: cem in error state because of timeout. not dispatching further commands", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    // Write data first (CPU register 1 --- 7)
    for (uint32_t reg_index = 1; reg_index < entries; ++reg_index) {
        stat = m_ll_device->write_register(*(*cdb.access_reg)[reg_index + m_cem_parameters.cem_arc_cpu_register_start_addr],
                                           CEM_ARC_CPU_REGISTER_WIDTH_BYTES,
                                           ((uint32_t*)command) + reg_index);
        return_on_error(stat);
    }

    // Write command last (CPU register 0)
    command->state = ARC_CPU_FSM_STATE_ARC;
    command->status = ARC_CPU_COMMAND_STATUS_NONE;
    stat = m_ll_device->write_register(*(*cdb.access_reg)[m_cem_parameters.cem_arc_cpu_register_start_addr],
                                       CEM_ARC_CPU_REGISTER_WIDTH_BYTES,
                                       ((uint32_t*)command));
    return_on_error(stat);

    stat = wait_response(command, cdb);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
cem::read_arc_response(arc_cpu_command& resp, cdb_top_storage& cdb) const
{
    size_t entries = sizeof(arc_cpu_command) / CEM_ARC_CPU_REGISTER_WIDTH_BYTES;

    for (size_t idx = 1; idx < entries; ++idx) {
        size_t reg_idx = idx + m_cem_parameters.cem_arc_cpu_register_start_addr;
        bit_vector ret_bv;
        la_status stat = m_ll_device->read_register(*(*cdb.access_reg)[reg_idx], ret_bv);
        return_on_error(stat);

        resp.params.flat[idx - 1] = ret_bv.get_value();
    }

    return LA_STATUS_SUCCESS;
}

la_status
cem::wait_response(arc_cpu_command* out_arc_command, cdb_top_storage& cdb) const
{
    // NOTE cdb->top->valid_reg errata in pacific
    // This register has multiple writers and the priority is designed with
    // the following order, CPU, HW and ARC.
    // Because of this order, there are risks for ARC halt.
    //
    // Workaround: avoid using valid_reg between CPU and ARC. Use access_reg[36]
    // for command and status communications.

    la_status stat;
    uint64_t message_val;
    bit_vector message(0);

    arc_cpu_fsm_state_e arc_state;
    arc_cpu_command_e arc_command_enum;
    arc_cpu_command_status_e arc_status_enum;
    auto arc_poll_start_time = std::chrono::steady_clock::now();
    arc_cpu_status arc_status;

    bool bubble_requested = false;
    transaction txn;

    if (out_arc_command->command > ARC_CPU_COMMAND_NONE) {
        poll_arc_done(ARC_CPU_FSM_STATE_CPU, cdb);
    }

    do {
        std::this_thread::yield();
        // after ARC completed request status is written to the first register
        stat = read_status_register_loop(message, cdb);
        return_on_error(stat);

        message_val = message.get_value();
        arc_status = *(reinterpret_cast<arc_cpu_status*>(&message_val));
        arc_command_enum = arc_status.command;
        arc_state = arc_status.state;

        if (!bubble_requested && arc_status.status == ARC_CPU_COMMAND_STATUS_REQUEST_BUBBLE) {
            log_warning(TABLES, "%s: bubble requested", __func__);
            m_ll_device->change_traffic_rate(true);

            txn.on_exit([=] {
                log_warning(TABLES, "wait_response: restore traffic");
                m_ll_device->change_traffic_rate(false);
            });

            bubble_requested = true;
            continue; // to ensure at least another iteration
        }

        auto arc_poll_duration = std::chrono::steady_clock::now() - arc_poll_start_time;
        if (arc_poll_duration > LA_ARC_RESPONSE_INTERVAL && arc_command_enum > ARC_CPU_COMMAND_NONE) {
            // Waited long enough, break the loop
            // re-check response register after halting the ARC processor
            bit_vector stop_arc(2);
            m_ll_device->write_register(*cdb.arc_control_registers, stop_arc);
            stat = read_status_register_loop(message, cdb);
            bit_vector start_arc(1);
            m_ll_device->write_register(*cdb.arc_control_registers, start_arc);
            return_on_error(stat);
            message_val = message.get_value();
            arc_status = *(reinterpret_cast<arc_cpu_status*>(&message_val));
            arc_command_enum = arc_status.command;
            arc_state = arc_status.state;
            uint64_t* storage_64 = (uint64_t*)out_arc_command;
            if (arc_state == ARC_CPU_FSM_STATE_CPU) {
                // recovered from the cem stuck issue
                log_crit(TABLES,
                         "%s: recoverd from timeout, arc_command = 0x%s, response register = 0x%s",
                         __func__,
                         bit_vector(storage_64, 8 * CEM_ARC_CPU_REGISTER_WIDTH_BYTES * 8).to_string().c_str(),
                         message.to_string().c_str());
                break;
            }

            log_crit(TABLES,
                     "%s: timeout while waiting ARC response, arc_command = 0x%s, response register = 0x%s",
                     __func__,
                     bit_vector(storage_64, 8 * CEM_ARC_CPU_REGISTER_WIDTH_BYTES * 8).to_string().c_str(),
                     message.to_string().c_str());
            stat = LA_STATUS_EUNKNOWN;
            timeout_occured = true;
            return stat;
        }
    } while (arc_command_enum > ARC_CPU_COMMAND_NONE && arc_state != ARC_CPU_FSM_STATE_CPU);

    arc_status_enum = arc_status.status;
    out_arc_command->params.location_params.core = arc_status.core;
    out_arc_command->params.location_params.bank = arc_status.inserted_to_cam ? (size_t)ARC_CAM_BANK_IDX : 0;

    la_status ret_status = arc_status_to_la_status[arc_status_enum];

    if (ret_status == LA_STATUS_SUCCESS || ret_status == LA_STATUS_EEXIST || ret_status == LA_STATUS_ENOTFOUND) {
        // These are valid statuses, no need to warn
        return ret_status;
    }

    const char* ret_status_str = arc_status_to_str[arc_status_enum];
    log_warning(TABLES, "%s: status=%s, return_code=%s", __func__, ret_status_str, message.to_string().c_str());

    return ret_status;
}

la_status
cem::reset_arc_counters(cdb_top_storage& cdb)
{
    log_debug(RA, "cem::reset_arc_counters()");
    la_status status = LA_STATUS_SUCCESS;

    // There are 2 x 2^12 limit counters that we should not initialize.
    // The rest is occupacy counters that we should initialize;
    static const size_t ARC_LIMIT_COUNTERS_NUM = (1 << 12) * 2;

    lld_memory_scptr counters_mem(cdb.counters);
    const lld_memory_desc_t* counters_mem_desc = counters_mem->get_desc();

    // TODO: for testing, initialize also limit counters
    for (size_t mem_line = 0; mem_line < ARC_LIMIT_COUNTERS_NUM; ++mem_line) {
        bit_vector init_bv(0x7ffff, counters_mem_desc->width_bits);
        status = m_ll_device->write_memory(*counters_mem, mem_line, init_bv);
        return_on_error(status);
    }

    for (size_t mem_line = ARC_LIMIT_COUNTERS_NUM; mem_line < counters_mem_desc->entries; ++mem_line) {
        bit_vector zero_bv(0, counters_mem_desc->width_bits);
        status = m_ll_device->write_memory(*counters_mem, mem_line, zero_bv);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
cem::load_arc_microcode(bool is_iccm, size_t mem_entries, const std::string& filename, cdb_top_storage& cdb)
{
    std::string mem_type = (is_iccm) ? "iccm" : "dccm";
    log_debug(RA, "cem::load_arc_microcode(%s), %s", mem_type.c_str(), filename.c_str());

    if (!m_ll_device->is_block_available(cdb.arc_mem_start->get_block()->get_block_id())) {
        log_debug(RA, "Not available on the device, skipping");
        return LA_STATUS_SUCCESS;
    }

    struct stat file_stat;
    int rc = stat(filename.c_str(), &file_stat);
    if (rc) {
        log_err(RA, "Failed to stat microcode file=%s, %s", filename.c_str(), strerror(errno));
        return LA_STATUS_EUNKNOWN;
    }
    size_t file_size = (size_t)file_stat.st_size;
    size_t buffer_size = mem_entries * sizeof(uint32_t);
    if (file_size > buffer_size) {
        log_err(RA,
                "Microcode file=%s, size=%ld is too big to fit in %s, size=%ld.",
                filename.c_str(),
                file_size,
                mem_type.c_str(),
                buffer_size);
        return LA_STATUS_ESIZE;
    }

    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        log_err(RA, "Failed to open microcode file %s, errno=%d.", filename.c_str(), errno);
        return LA_STATUS_ENOTFOUND;
    }

    log_debug(RA, "Reading CEM ARC microcode %s from %s.", mem_type.c_str(), filename.c_str());

    std::vector<uint32_t> buffer(mem_entries);
    size_t n = fread(buffer.data(), 1 /* element size */, file_size /* count of elements */, fp);
    fclose(fp);

    if (n != file_size) {
        log_err(RA, "Failed reading a microcode file %s.", filename.c_str());
        return LA_STATUS_ENOTFOUND;
    }

    // Write DWORDs one-by-one to cem_iccm or cem_dccm
    for (size_t line = 0; line < mem_entries; ++line) {
        // Data
        la_status status = LA_STATUS_SUCCESS;
        if (m_ll_device->is_gibraltar()) {
            gibraltar::cdb_top_arc_mem_ccm_data_register data_val = {.fields = {.ccm_data = buffer[line]}};
            status = m_ll_device->write_register(*cdb.arc_mem_ccm_data, data_val);
        } else {
            cdb_top_arc_mem_ccm_data_register data_val = {.fields = {.ccm_data = buffer[line]}};
            status = m_ll_device->write_register(*cdb.arc_mem_ccm_data, data_val);
        }
        return_on_error(status);

        // Address
        if (m_ll_device->is_gibraltar()) {
            gibraltar::cdb_top_arc_mem_regs_register addr_val = {.fields = {.ccm_wr = 1, // read or write
                                                                            .access_iccm = is_iccm,
                                                                            .ccm_addr = line}};
            status = m_ll_device->write_register(*cdb.arc_mem_regs, addr_val);
        } else {
            cdb_top_arc_mem_regs_register addr_val = {.fields = {.ccm_wr = 1, // read or write
                                                                 .access_iccm = is_iccm,
                                                                 .ccm_addr = line}};
            status = m_ll_device->write_register(*cdb.arc_mem_regs, addr_val);
        }
        return_on_error(status);

        // Start & Poll
        if (m_ll_device->is_gibraltar()) {
            gibraltar::cdb_top_arc_mem_start_register start_val = {.fields = {.start = 1}};
            status = m_ll_device->write_register(*cdb.arc_mem_start, start_val);
        } else {
            cdb_top_arc_mem_start_register start_val = {.fields = {.start = 1}};
            status = m_ll_device->write_register(*cdb.arc_mem_start, start_val);
        }
        return_on_error(status);

        bit_vector done_val(1, 1 /*width*/);
        while (done_val.bit(0)) {
            status = m_ll_device->read_register(*cdb.arc_mem_start, done_val);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
cem::set_mac_aging_interval(uint32_t interval)
{
    uint8_t current_tlv_index = 0;
    arc_cpu_command cmd;
    memset(&cmd, 0, sizeof(arc_cpu_command));

    cmd.command = ARC_CPU_COMMAND_SET_FEATURES;
    // ARC needs to know MAC learning mode
    cmd.params.feature_params.type_values[current_tlv_index].type = ARC_CPU_FEATURE_TYPE_AGE_INTERVAL;
    cmd.params.feature_params.type_values[current_tlv_index].value = interval & ARC_CPU_FEATURE_VALUE_MASK;
    current_tlv_index++;

    la_status status = dispatch_arc_command(&cmd);

    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
cem::set_soft_reset_mode(bool enabled)
{
    return for_each_cdb([&](cdb_top_storage& cdb) {
        la_status status = LA_STATUS_SUCCESS;

        // Halt/resume ARC
        if (m_ll_device->is_gibraltar()) {
            gibraltar::cdb_top_arc_control_registers_register arc_control_registers_val = {.u8 = {0}};
            arc_control_registers_val.fields.halt_req = enabled ? 1 : 0;
            arc_control_registers_val.fields.run_req = enabled ? 0 : 1;
            status = m_ll_device->write_register(*cdb.arc_control_registers, arc_control_registers_val);
        } else {
            cdb_top_arc_control_registers_register arc_control_registers_val = {.u8 = {0}};
            arc_control_registers_val.fields.halt_req = enabled ? 1 : 0;
            arc_control_registers_val.fields.run_req = enabled ? 0 : 1;
            status = m_ll_device->write_register(*cdb.arc_control_registers, arc_control_registers_val);
        }

        return status;

    });
}

void
cem::poll_arc_done(arc_cpu_fsm_state_e expected_state, cdb_top_storage& cdb) const
{
    size_t addr = (*cdb.access_reg)[m_cem_parameters.cem_arc_cpu_register_start_addr]->get_absolute_address();
    size_t width = (*cdb.access_reg)[m_cem_parameters.cem_arc_cpu_register_start_addr]->get_desc()->width_in_bits;
    bit_vector expected_val((int)expected_state, width);
    bit_vector mask((1 << 4) - 1, width);
    log_debug(
        SIM, "command::poll_no_response %016zx 2 %s %s 200", addr, expected_val.to_string().c_str(), mask.to_string().c_str());
}

size_t
cem::max_size() const
{
    constexpr size_t MAX_USAGE = 100;
    return MAX_USAGE;
}

la_status
cem::get_physical_usage(entry_type_e table_type, size_t num_of_table_logical_entries, size_t& out_physical_usage) const
{
    bool double_entry = table_type == entry_type_e::DOUBLE_ENTRY;
    log_debug(TABLES,
              "cem::get_physical_usage(table_type: %s, #entries: %lu)",
              (double_entry ? "DOUBLE_ENTRY" : "SINGLE_ENTRY"),
              num_of_table_logical_entries);
    size_t max_entries_per_core = m_cem_parameters.banks_configuration.count_ones() * CEM_NUM_EM_ENTRIES_PER_BANK;
    size_t total_entries = max_entries_per_core * NUM_EM_CORES;
    size_t entry_size = double_entry ? 2 : 1;
    out_physical_usage = (100 * entry_size * num_of_table_logical_entries) / total_entries;
    return LA_STATUS_SUCCESS;
}

la_status
cem::get_available_entries(entry_type_e table_type, size_t& out_available_entries)
{
    bool double_entry = table_type == entry_type_e::DOUBLE_ENTRY;
    log_debug(TABLES, "cem::get_available_entries(table_type: %s)", (double_entry ? "DOUBLE_ENTRY" : "SINGLE_ENTRY"));
    arc_cpu_command cmd;
    memset(&cmd, 0, sizeof(arc_cpu_command));
    cmd.command = ARC_CPU_COMMAND_GET_UTILIZATION_STATE;

    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);

    arc_cpu_command resp;
    status = read_arc_response(resp, m_cdb_top_storage[0]);
    return_on_error(status);

    size_t max_entries_per_core = m_cem_parameters.banks_configuration.count_ones() * CEM_NUM_EM_ENTRIES_PER_BANK;
    size_t used_entries = resp.params.utilization_params.total_sram_utilization;
    size_t available_entries = max_entries_per_core * NUM_EM_CORES - used_entries;
    out_available_entries = double_entry ? available_entries / 2 : available_entries;
    return status;
}

la_status
cem::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    m_resource_monitor = monitor;

    return LA_STATUS_SUCCESS;
}

la_status
cem::get_resource_monitor(resource_monitor_sptr& out_monitor) const
{
    out_monitor = m_resource_monitor;

    return LA_STATUS_SUCCESS;
}

la_status
cem::update_size()
{
    arc_cpu_command cmd;
    memset(&cmd, 0, sizeof(arc_cpu_command));
    cmd.command = ARC_CPU_COMMAND_GET_UTILIZATION_STATE;

    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);

    arc_cpu_command resp;
    status = read_arc_response(resp, m_cdb_top_storage[0]);
    return_on_error(status);

    constexpr size_t CAM_DIVISOR_PENALTY = 9;

    size_t max_entries_per_core = m_cem_parameters.banks_configuration.count_ones() * CEM_NUM_EM_ENTRIES_PER_BANK;
    m_usage = (resp.params.utilization_params.sram_utilization * 100) / max_entries_per_core;

    size_t cam_usage = (resp.params.utilization_params.cam_utilization * 100) / (CEM_NUM_EM_ENTRIES_PER_CAM - CAM_DIVISOR_PENALTY);
    cam_usage = cam_usage < 100 ? cam_usage : 100;

    m_usage = cam_usage > m_usage ? cam_usage : m_usage;

    if (m_resource_monitor != nullptr) {
        m_resource_monitor->update_size(m_usage);
    }

    return LA_STATUS_SUCCESS;
}

size_t
cem::size() const
{
    return m_usage;
}

const cem::cem_parameters
cem::cem_parameters::get_params(la_device_revision_e device_revision)
{
    if (is_pacific(device_revision)) {
        constexpr size_t NUM_BANKS = 16;
        constexpr size_t NUM_OF_EM_BANKS = 8;

        bit_vector banks_configuration = bit_vector::ones_range(
            NUM_BANKS - 1 /*msb*/, NUM_BANKS - NUM_OF_EM_BANKS /*lsb*/, NUM_BANKS /*width_bits*/); // 0xff00

        const cem::cem_parameters PACIFIC_CEM_PARAMS = {
            .num_banks = NUM_BANKS,
            .num_even_banks = NUM_BANKS / 2,
            .banks_configuration = banks_configuration,
            .cem_arc_cpu_register_start_addr = 44 - 8 // ARC has 44 registers for internal usage, last 8 for cpu-arc communication
        };
        return PACIFIC_CEM_PARAMS;
    };

    if (is_gibraltar(device_revision)) {
        constexpr size_t NUM_BANKS = 28;
        constexpr size_t NUM_OF_EM_BANKS = 19;

        bit_vector banks_configuration = bit_vector::ones_range(
            NUM_BANKS - 1 /*msb*/, NUM_BANKS - NUM_OF_EM_BANKS /*lsb*/, NUM_BANKS /*width_bits*/); // 0xffffe00

        const cem::cem_parameters GIBRALTAR_CEM_PARAMS = {
            .num_banks = NUM_BANKS,
            .num_even_banks = NUM_BANKS / 2,
            .banks_configuration = banks_configuration,
            .cem_arc_cpu_register_start_addr = 47 - 9 // ARC has 47 registers for internal usage, last 9 for cpu-arc communication
                                                      // TODO - add a const of 47 and substract ARC_CPU_COMMAND_REG_LEN
        };
        return GIBRALTAR_CEM_PARAMS;
    };

    dassert_crit(false, "Unknown device_revision %d", to_utype(device_revision));

    const cem::cem_parameters ERROR_CEM_PARAMS{};
    return ERROR_CEM_PARAMS;
}

la_status
cem::get_arc_features()
{
    arc_cpu_command cmd;
    memset(&cmd, 0, sizeof(arc_cpu_command));

    cmd.command = ARC_CPU_COMMAND_GET_FEATURES;

    la_status status = dispatch_arc_command(&cmd, m_cdb_top_storage[0]);
    if (status != LA_STATUS_SUCCESS) {
        log_err(TABLES, "Failed to sent feature request to ARC");
        return LA_STATUS_EUNKNOWN;
    }

    arc_cpu_command resp;
    status = read_arc_response(resp, m_cdb_top_storage[0]);
    if (status != LA_STATUS_SUCCESS) {
        log_err(TABLES, "Failed to get feature response from ARC");
        return LA_STATUS_EUNKNOWN;
    }

    for (size_t index = 0; index < ARC_CPU_FEATURE_MAX_TLV_COUNT; ++index) {
        arc_cpu_feature_e current_type = resp.params.feature_params.type_values[index].type;
        if (current_type >= ARC_CPU_FEATURE_TYPE_FIRST && current_type <= ARC_CPU_FEATURE_TYPE_LAST) {
            uint32_t current_value = resp.params.feature_params.type_values[index].value;
            const char* ret_type_str = arc_feature_to_str[current_type];
            log_debug(TABLES, "ARC feature TLV index: %lu, type: %s, value: %u", index, ret_type_str, current_value);
        } else {
            log_debug(TABLES, "Available ARC feature TLV index: %lu", index);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
cem::set_arc_local_mac_learning_features()
{
    uint8_t current_tlv_index = 0;
    arc_cpu_command cmd;
    memset(&cmd, 0, sizeof(arc_cpu_command));

    cmd.command = ARC_CPU_COMMAND_SET_FEATURES;
    // ARC needs to know MAC learning mode
    cmd.params.feature_params.type_values[current_tlv_index].type = ARC_CPU_FEATURE_TYPE_LEARN_MODE;
    cmd.params.feature_params.type_values[current_tlv_index].value = ARC_CPU_FEATURE_VALUE_LEARN_MODE_LOCAL;
    current_tlv_index++;
    // Let ARC deletes MAC entries during aging scanning rounds
    cmd.params.feature_params.type_values[current_tlv_index].type = ARC_CPU_FEATURE_TYPE_AGE_MODE;
    cmd.params.feature_params.type_values[current_tlv_index].value = ARC_CPU_FEATURE_VALUE_AGE_MODE_DELETE_ENTRY;
    current_tlv_index++;
    // Disable age notification for local leanring mode
    cmd.params.feature_params.type_values[current_tlv_index].type = ARC_CPU_FEATURE_TYPE_AGE_NOTIFICATION;
    cmd.params.feature_params.type_values[current_tlv_index].value = ARC_CPU_FEATURE_VALUE_AGE_NOTIFICATION_OFF;
    current_tlv_index++;

    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
cem::set_arc_system_mac_learning_features()
{
    uint8_t current_tlv_index = 0;
    arc_cpu_command cmd;
    memset(&cmd, 0, sizeof(arc_cpu_command));

    cmd.command = ARC_CPU_COMMAND_SET_FEATURES;
    // ARC needs to know MAC learning mode
    cmd.params.feature_params.type_values[current_tlv_index].type = ARC_CPU_FEATURE_TYPE_LEARN_MODE;
    cmd.params.feature_params.type_values[current_tlv_index].value = ARC_CPU_FEATURE_VALUE_LEARN_MODE_SYSTEM;
    current_tlv_index++;
    // Let ARC keep MAC entries during aging scanning rounds
    cmd.params.feature_params.type_values[current_tlv_index].type = ARC_CPU_FEATURE_TYPE_AGE_MODE;
    cmd.params.feature_params.type_values[current_tlv_index].value = ARC_CPU_FEATURE_VALUE_AGE_MODE_KEEP_ENTRY;
    current_tlv_index++;
    // Age notification is available for system learning mode only
    cmd.params.feature_params.type_values[current_tlv_index].type = ARC_CPU_FEATURE_TYPE_AGE_NOTIFICATION;
    cmd.params.feature_params.type_values[current_tlv_index].value = ARC_CPU_FEATURE_VALUE_AGE_NOTIFICATION_ON;
    current_tlv_index++;

    la_status status = dispatch_arc_command(&cmd);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
