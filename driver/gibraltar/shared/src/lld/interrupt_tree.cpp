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

#include "lld/interrupt_tree.h"
#include "common/bit_utils.h"
#include "common/common_strings.h"
#include "common/file_utils.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_strings.h"
#include "lld/lld_utils.h"
#include "parse_context.h"

#include <fstream>
#include <jansson.h>
#include <sstream>
#include <vector>

//
// Interrupts wiring.
//
// - Master Interrupt is always at addr 0 and is non-maskable.
//
// - Internal interrupt registers are always coupled with mask registers.
//   There are 2 cases:
//      1. non-mem_protect interrupt, status and mask regs are the same width, simple bit-to-bit correspondance.
//      2. mem_protect interrupt has 3 bits: parity, ecc2b, ecc1b
//         There is no single mem_protect mask, but instead, we have three mask registers - one for each bit.
//         The three mask registers are parity_err_mask, ecc_2b_err_mask, ecc_1b_err_mask
//         The number of bits in each mask corresponds to the number of memories which are parity or ECC protected.
//
//         Example: npu_txpp_data/txpp_mem.lbr
//          This block has 9 ECC-protected memories and 2 parity-protected memories.
//          And the registers are:
//              - masks
//                  * ecc_1b_err_mask: width=9bits (1 bit per ECC memory)
//                  * ecc_2b_err_mask: width=9bits (1 bit per ECC memory)
//                  * parity_err_mask: width=2bits (1 bit per parity memory)
//              - initiate, when set an access to memory will generate an error and trigger an interrupt
//                  * ecc_1b_err_initiate: width=9bits (1 bit per ECC memory)
//                  * ecc_2b_err_initiate: width=9bits (1 bit per ECC memory)
//                  * parity_err_initiate: width=2bits (1 bit per parity memory)
//              - counters
//                  * ecc_1b_err_debug.counter: 16bit (the counter accumulates ECC 1b errors, cleared-on-read)
//                  * ecc_2b_err_debug.counter: 16bit (the counter accumulates ECC 2b errors, cleared-on-read)
//                  * parity_err_debug.counter: 16bit (the counter accumulates parity errors, cleared-on-read)
//              - mem_protect_err_status: width=11bit (1 bit per memory, ECC+parity combined)
//                  The bits are unordered (!!!), but the names of the bits match to the names of ecc/parity mask bits.
//              - select/read/reset
//                  * ser_error_debug_configuration.erroneous_memory_selector - select a memory for read info
//                  * ser_error_debug_configuration.reset_memory_errors - toggle 0-1-0 to clear errors
//                  * selected_ser_error_info
//                      read (after select) - mem_err_addr, mem_err_type (0 = ecc_1b, 1 = ecc_2b, 2 = parity)
//
//              See code below for more info.
//
//
//  More notes on mem_protect
//
//
//      CSS
//    ||      .-------------------.  .-----------------.  .------------------.  ||
//    ||      | MSI root & mask   |  | Pin             |  | Arc0,1,2,3       |  ||
//    ||      |-------------------|  |-----------------|  |------------------|  ||
//    ||      | ... 3 | 2 | 1 | 0 |  | ... | 2 | 1 | 0 |  |  ... | 2 | 1 | 0 |  ||
//    ||      '-----x---x---x---x-'  '-------x---x---x-'  '--------x---x---x-'  ||
//    ||            |   |   |    \                                              ||
//    ||  cause1 <--+   |   |     \______                                       ||
//    ||  cause0 <------+   |            |                                      ||
//    ||                    |            |                                      ||
//    ||   .----------------v--.      .--v----------------.                     ||
//    ||   | msi block1 & mask |      | msi block0 & mask |                     ||
//    ||   |-------------------|      |-------------------|                     ||
//    ||   | ...   | 2 | 1 | 0 |      | ...   | 2 | 1 | 0 |                     ||
//    ||   '---------x---x---x-'      '---------x---x---x-'                     ||
//                          |
//                          |
//      Block A             |
//    ||        .-----------v----------------.                                                                         ||
//    ||        | master interrupt (no mask) |                                                                         ||
//    ||        |----------------------------|                                                                         ||
//    ||        |          ...   | 2 | 1 | 0 |                                                                         ||
//    ||        '------------------x---x---x-'                                                                         ||
//    ||                          /    |    \                                                                          ||
//    ||                         /     |     \________                                                                 ||
//    ||       .----------------/------v-.            \                                                                ||
//    ||    .------------------v-. reg 1 |          .--v-----------------------.                                       ||
//    ||    |    interrupt reg 2 |-------|          | mem protect interrupt    |                                       ||
//    ||    |--------------------|mask 1 |          |--------------------------|                                       ||
//    ||    |   interrupt mask 2 |-------|          | parity | ecc_2b | ecc_1b |                                       ||
//    ||    |--------------------| 1 | 0 |          '--x------------x--------x-'                                       ||
//    ||    | ...| 3 | 2 | 1 | 0 |-------'            /              \        \___________                             ||
//    ||    '------x---x---x---x-'                   /                \                   |                            ||
//    ||           |   |   |   |         .----------v--.            .--v----------.  .----v-------.                    ||
//    ||  cause2 <-+   |   |   v         | parity mask |            | ecc2b mask  |  | ecc1b mask |                    ||
//    ||  cause1 <-----+   |   |         |-------------|            |-------------|  |------------|                    ||
//    ||  cause0 <---------+   v         |   m4 |  m3  |            | m2 | m1 | m0|  |m2 | m1 | m0|                    ||
//    ||                       |         '---x-------x-'            '--x----x---x-'  '-x---x----x-'                    ||
//    ||                       v             |       |                 |    |   |      |   |    |                      ||
//    ||                       |             |       |                 |    |   +------(---(----+--------+             ||
//    ||                       v             |       |                 |    |          |   |             |             ||
//    ||                       |             |       |                 |    +----------(---+             |             ||
//    ||                       v             |       |                 |               (   |             |             ||
//    ||                       |             |       |                 +---------------+   |             |             ||
//    ||                       v             |       |                 |                   |             |             ||
//    ||                       |  .----------v--.  .-v-----------.  .--v----------.  .-----v-------.  .--v----------.  ||
//    ||                       v  | memory4     |  | memory3     |  | memory2     |  | memory1     |  | memory0     |  ||
//    ||                       |  |  parity-    |  |  parity-    |  |  ECC-       |  |  ECC-       |  |  ECC-       |  ||
//    ||                       v  |   protected |  |   protected |  |   protected |  |   protected |  |   protected |  ||
//    ||                       |  '-------------'  '-------------'  '-------------'  '-------------'  '-------------'  ||
//    ||                       v                                                                                       ||
//    ||                       |                                                                                       ||
//    ||                       v          Memory subsystem status registers:                                           ||
//    ||                       |                  mem_protect_err_status - one bit per memory (m4,m3,m2,m1,m0)         ||
//    ||                       v                  ecc_1b_err_counter - 16bit counter                                   ||
//    ||                       |                  ecc_2b_err_counter - 16bit counter                                   ||
//    ||                       v                  parity_err_counter - 16bit counter                                   ||
//    ||                       |                                                                                       ||
//    ||                       v                                                                                       ||
//                             v
//                             |
//      Block B                v
//    ||             +---------v----------+                                     ||
//    ||             | master interrupt   |                                     ||
//    ||             |--------------------|                                     ||
//    ||             | ...| 3 | 2 | 1 | 0 |                                     ||
//    ||             +------x---x---x---x-+                                     ||
//    ||                    |   |   |    \                                      ||
//    ||                    v   v   v     v                                     ||
//    ||                   ... ... ...   mem protect                            ||
//
//

using namespace std;

namespace silicon_one
{

static const char DEFAULT_BASE_OUTPUT_DIR[] = "out/noopt-debug";

static const char BASE_OUTPUT_DIR_ENVVAR[] = "BASE_OUTPUT_DIR";

static inline const char*
to_string(const parse_context& pos)
{
    static char buf[80];
    snprintf(buf, sizeof(buf), "{nodes=%ld, bits=%ld, registers=%ld}", pos.nodes, pos.bits, pos.registers);

    return buf;
}

static inline uint64_t
unpack_field(const bit_vector& bv, const interrupt_tree::register_field& field)
{
    return bit_utils::get_bits(bv.get_value(), field.msb, field.lsb);
}

static inline void
pack_field(bit_vector& bv, const interrupt_tree::register_field& field, uint64_t val)
{
    bv.set_bits(field.msb, field.lsb, val);
}

static interrupt_tree::bit_sptr parse_bit(json_t* j_root, size_t bit_i, parse_context& pos);
static interrupt_tree::node_sptr parse_node(json_t* j_root, parse_context& pos);
static lld_register_scptr parse_register(json_t* j_root, parse_context& pos);

static lld_register_scptr
parse_register(json_t* j_root, parse_context& pos)
{
    // get fields
    json_t* j_objtype = json_object_get(j_root, "objtype");
    json_t* j_block_id = json_object_get(j_root, "block_id");
    json_t* j_addr = json_object_get(j_root, "addr");
    json_t* j_name = json_object_get(j_root, "name");

    if (!j_objtype || !j_block_id || !j_addr || !j_name) {
        log_debug(INTERRUPT, "%s: ERROR - pos=%s, some of the REG fields are missing", __func__, to_string(pos));
        return nullptr;
    }

    // parse fields
    const char* objtype = json_string_value(j_objtype);
    int block_id = json_integer_value(j_block_id);
    int addr = json_integer_value(j_addr);
    const char* name = json_string_value(j_name);

    if (strcmp(objtype, "REG") != 0) {
        log_err(INTERRUPT, "%s: pos=%s, bad objtype=%s, should be REG", __func__, to_string(pos), objtype);
        return nullptr;
    }

    lld_register_scptr reg = pos.get_register_from_tree(block_id, addr);
    if (!reg) {
        log_err(INTERRUPT, "%s: pos=%s, register not found, block_id=%d, addr=%d", __func__, to_string(pos), block_id, addr);
        return nullptr;
    }
    if (reg->get_name() != string(name)) {
        log_err(INTERRUPT, "%s: pos=%s, register name mismatch, %s VS %s", __func__, to_string(pos), reg->get_name().c_str(), name);
        return nullptr;
    }

    pos.registers++;
    log_xdebug(INTERRUPT, "%s: pos=%s, register %s", __func__, to_string(pos), name);

    return reg;
}

string
interrupt_tree::to_string(const node_scptr& node)
{
    stringstream ss;

    ss << node->status->get_name() << ": bits=" << node->bits.size();
    return ss.str();
}

string
interrupt_tree::to_string(const bit_scptr& bit)
{
    stringstream ss;

    ss << "b" << bit->bit_i << ": name=" << bit->name << ", type=" << silicon_one::to_string(bit->type);
    return ss.str();
}

static interrupt_tree::bit_sptr
parse_bit(json_t* j_root, size_t bit_i, parse_context& pos)
{
    // get fields
    json_t* j_objtype = json_object_get(j_root, "objtype");
    json_t* j_name = json_object_get(j_root, "name");
    json_t* j_type = json_object_get(j_root, "type");
    json_t* j_sw_action = json_object_get(j_root, "sw_action");
    json_t* j_children = json_object_get(j_root, "children");
    json_t* j_is_masked = json_object_get(j_root, "is_masked");

    if (!j_objtype || !j_name || !j_type || !j_sw_action || !j_children || !j_is_masked) {
        log_err(INTERRUPT, "%s: ERROR - pos=%s, some of the BIT fields are missing", __func__, to_string(pos));
        return nullptr;
    }

    // parse fields
    const char* objtype = json_string_value(j_objtype);
    const char* name = json_string_value(j_name);
    size_t children_n = json_array_size(j_children); // 0 of not JSON_ARRAY or if array is empty

    if (!objtype || !name) {
        log_err(INTERRUPT, "%s: pos=%s, one of objtype|name is not a string", __func__, to_string(pos));
        return nullptr;
    }
    if (strcmp(objtype, "BIT") != 0) {
        log_err(INTERRUPT, "%s: pos=%s, bad objtype=%s, should be BIT", __func__, to_string(pos), objtype);
        return nullptr;
    }

    json_int_t type_int = json_integer_value(j_type);
    interrupt_type_e type = interrupt_type_e::LAST;
    if (!numeric_to_enum(type_int, type)) {
        log_err(INTERRUPT, "%s: pos=%s, bad interrupt bit type %d", __func__, to_string(pos), (int)type_int);
        return nullptr;
    }

    json_int_t sw_action_int = json_integer_value(j_sw_action);
    la_notification_action_e action = la_notification_action_e::LAST;
    if (!numeric_to_enum(sw_action_int, action)) {
        log_err(INTERRUPT, "%s: pos=%s, bad interrupt action %d", __func__, to_string(pos), (int)sw_action_int);
        return nullptr;
    }

    bool is_masked = json_boolean_value(j_is_masked);

    log_xdebug(INTERRUPT,
               "%s: pos=%s, name=%s, type=%s, action=%d, children_n=%ld",
               __func__,
               to_string(pos),
               name,
               silicon_one::to_string(type).c_str(),
               (int)action,
               children_n);

    if (!children_n && type == interrupt_type_e::SUMMARY) {
        log_debug(INTERRUPT, "%s: ERROR - pos=%s, %s is a SUMMARY and should have children", __func__, to_string(pos), name);
    } else if (children_n && type != interrupt_type_e::SUMMARY) {
        log_warning(INTERRUPT, "%s: pos=%s, %s is not a SUMMARY but has children", __func__, to_string(pos), name);
    }

    vector<interrupt_tree::node_sptr> children;
    size_t index;
    json_t* value;
    json_array_foreach(j_children, index, value)
    {
        log_xdebug(INTERRUPT, "%s: pos=%s, child %ld", __func__, to_string(pos), index);
        interrupt_tree::node_sptr n = parse_node(value, pos);
        if (!n) {
            log_err(INTERRUPT, "%s: pos=%s, failed parsing child node for bit %s", __func__, to_string(pos), name);
            return nullptr;
        }
        children.push_back(move(n));
    }

    pos.bits++;
    interrupt_tree::bit* b_ptr = new interrupt_tree::bit{.name = name,
                                                         .type = type,
                                                         .action = action,
                                                         .children = move(children),
                                                         .is_masked = is_masked,
                                                         .parent = nullptr, // to be assigned by parse_node()
                                                         .bit_i = bit_i};

    interrupt_tree::bit_sptr b(b_ptr);

    // Assign parent bit
    for (auto& node : b->children) {
        node->parent = b;
    }

    return interrupt_tree::bit_sptr(b);
}

static bool
parse_mem_protect_control(json_t* j_mem_protect_fields,
                          const lld_block_scptr& block,
                          struct interrupt_tree::node::mem_protect_s& mp)
{
    size_t ecc_1b_index = (size_t)la_mem_protect_error_e::ECC_1B;
    size_t ecc_2b_index = (size_t)la_mem_protect_error_e::ECC_2B;
    size_t parity_index = (size_t)la_mem_protect_error_e::PARITY;

    mp.masks[ecc_1b_index] = block->get_register(lld_register::ECC_1B_ERR_INTERRUPT_MASK);
    mp.masks[ecc_2b_index] = block->get_register(lld_register::ECC_2B_ERR_INTERRUPT_MASK);
    mp.masks[parity_index] = block->get_register(lld_register::PARITY_ERR_INTERRUPT_MASK);
    mp.mem_protect_err_status = block->get_register(lld_register::MEM_PROTECT_ERR_STATUS);
    mp.selected_ser_error_info = block->get_register(lld_register::SELECTED_SER_ERROR_INFO);
    mp.ser_error_debug_configuration = block->get_register(lld_register::SER_ERROR_DEBUG_CONFIGURATION);
    mp.err_debug[ecc_1b_index] = block->get_register(lld_register::ECC_1B_ERR_DEBUG);
    mp.err_debug[ecc_2b_index] = block->get_register(lld_register::ECC_2B_ERR_DEBUG);
    mp.err_debug[parity_index] = block->get_register(lld_register::PARITY_ERR_DEBUG);

    for (lld_memory_scptr mem : block->get_memories()) {
        lld_memory_protection_e prot = mem->get_desc()->protection;
        if (prot == lld_memory_protection_e::NONE) {
            continue;
        }

        if (prot == lld_memory_protection_e::ECC || prot == lld_memory_protection_e::EXT_ECC) {
            mp.ecc_protected_memories.push_back(mem);
        } else {
            mp.parity_protected_memories.push_back(mem);
        }
        mp.protected_memories.push_back(mem);
    }

    // It's ok to not have any protected memories.
    if (mp.protected_memories.empty()) {
        return true;
    }

    // Verify ECC+Parity members
    if (!mp.mem_protect_err_status || !mp.selected_ser_error_info || !mp.ser_error_debug_configuration) {
        log_err(INTERRUPT, "%s: %s, mandatory mem_protect registers are absent", __func__, block->get_name().c_str());
        return false;
    }
    if (mp.protected_memories.size() != mp.mem_protect_err_status->get_desc()->width_in_bits) {
        log_err(INTERRUPT, "%s: %s, unexpected number of protected memories", __func__, block->get_name().c_str());
        return false;
    }

    // Verify ECC members
    if (mp.ecc_protected_memories.size()) {
        if (!mp.masks[ecc_1b_index] || !mp.masks[ecc_2b_index] || !mp.err_debug[ecc_1b_index] || !mp.err_debug[ecc_2b_index]) {
            log_err(INTERRUPT, "%s: %s, ECC mem_potect registers are absent", __func__, block->get_name().c_str());
            return false;
        }
        if (mp.ecc_protected_memories.size() != mp.masks[ecc_1b_index]->get_desc()->width_in_bits) {
            log_err(INTERRUPT, "%s: %s, unexpected number of ECC protected memories", __func__, block->get_name().c_str());
            return false;
        }
    }

    // Verify Parity members
    if (mp.parity_protected_memories.size()) {
        if (!mp.masks[parity_index] || !mp.err_debug[parity_index]) {
            log_err(INTERRUPT, "%s: %s, Parity mem_protect registers are absent", __func__, block->get_name().c_str());
            return false;
        }
        if (mp.parity_protected_memories.size() != mp.masks[parity_index]->get_desc()->width_in_bits) {
            log_err(INTERRUPT, "%s: %s, unexpected number of Parity protected memories", __func__, block->get_name().c_str());
            return false;
        }
    }

    // Parse register fields
    size_t index;
    json_t* value;
    json_array_foreach(j_mem_protect_fields, index, value)
    {
        const char* field_name = json_string_value(json_object_get(value, "field_name"));
        size_t pos = (size_t)json_integer_value(json_object_get(value, "pos"));
        size_t width = (size_t)json_integer_value(json_object_get(value, "width"));

        interrupt_tree::register_field field = {.msb = pos + width - 1, .lsb = pos};

        if (strcmp(field_name, "erroneous_memory_selector") == 0) {
            mp.erroneous_memory_selector = field;
        } else if (strcmp(field_name, "reset_memory_errors") == 0) {
            mp.reset_memory_errors = field;
        } else if (strcmp(field_name, "mem_err_addr") == 0) {
            mp.mem_err_addr = field;
        } else if (strcmp(field_name, "mem_err_type") == 0) {
            mp.mem_err_type = field;
        } else {
            log_err(INTERRUPT, "%s: unexpected register field %s", __func__, field_name);
            return false;
        }
    }

    return true;
}

static interrupt_tree::node_sptr
parse_node(json_t* j_root, parse_context& pos)
{
    // get fields
    json_t* j_objtype = json_object_get(j_root, "objtype");
    json_t* j_status = json_object_get(j_root, "status");
    json_t* j_mask = json_object_get(j_root, "mask");
    json_t* j_mem_protect_fields = json_object_get(j_root, "mem_protect_fields");
    json_t* j_is_mask_active_low = json_object_get(j_root, "is_mask_active_low");
    json_t* j_bits = json_object_get(j_root, "bits");

    if (!j_objtype || !j_status || !j_mask || !j_is_mask_active_low || !j_bits) {
        log_err(INTERRUPT, "%s: pos=%s, some of the NODE fields are missing", __func__, to_string(pos));
        return nullptr;
    }

    // parse fields
    const char* objtype = json_string_value(j_objtype);
    lld_register_scptr reg_status = parse_register(j_status, pos);
    lld_register_scptr reg_mask;
    if (reg_status->get_block_id() != pos.sbif_block_id
        && (reg_status->get_desc()->addr == lld_register::MASTER_INTERRUPT
            || reg_status->get_desc()->addr == lld_register::MEM_PROTECT_INTERRUPT)) {
        reg_mask = nullptr;
    } else {
        if (!j_mask) {
            log_err(INTERRUPT, "%s: pos=%s, bad node, should have a mask register", __func__, to_string(pos));
            return nullptr;
        }
        reg_mask = parse_register(j_mask, pos);
    }
    bool is_mask_active_low = json_boolean_value(j_is_mask_active_low);
    size_t bits_n = json_object_size(j_bits);

    if (strcmp(objtype, "NODE") != 0) {
        log_err(INTERRUPT, "%s: pos=%s, bad objtype=%s, should be NODE", __func__, to_string(pos), objtype);
        return nullptr;
    }
    if (!reg_status) {
        log_err(INTERRUPT, "%s: pos=%s, status reg is missing", __func__, to_string(pos));
        return nullptr;
    }

    struct interrupt_tree::node::mem_protect_s mp;
    if (reg_status->get_desc()->addr == lld_register::MEM_PROTECT_INTERRUPT) {
        bool ok = parse_mem_protect_control(j_mem_protect_fields, reg_status->get_block(), mp);
        if (!ok) {
            return nullptr;
        }
    }

    log_xdebug(INTERRUPT, "%s: pos=%s, is_mask_active_low %d, bits_n %ld", __func__, to_string(pos), is_mask_active_low, bits_n);

    // Iterate through bits
    vector<interrupt_tree::bit_sptr> bits(bits_n);
    const char* err_str = nullptr;
    size_t bit_i = -1;
    const char* key;
    json_t* value;
    json_object_foreach(j_bits, key, value)
    {
        bit_i = strtol(key, NULL, 10);
        if (bit_i >= bits_n) {
            err_str = "out of range";
            break;
        }
        if (bits[bit_i]) {
            err_str = "already exists";
            break;
        }

        log_xdebug(INTERRUPT, "%s: pos=%s, bit_i=%ld", __func__, to_string(pos), bit_i);

        bits[bit_i] = parse_bit(value, bit_i, pos);
        if (!bits[bit_i]) {
            err_str = "failed parsing";
            break;
        }
    }
    if (err_str) {
        log_err(INTERRUPT, "%s: pos=%s, bit_i=%ld, %s", __func__, to_string(pos), bit_i, err_str);
        return nullptr;
    }

    interrupt_tree::node* n = new interrupt_tree::node{
        .status = reg_status,
        .mask = reg_mask,
        .is_mask_active_low = is_mask_active_low,
        .bits = move(bits),
        .parent = nullptr,
        .mem_protect = move(mp),
    };
    interrupt_tree::node_sptr n_sptr(n);

    // Assign parent node
    for (auto& bit : n->bits) {
        bit->parent = n_sptr;
    }

    // Add this node to the lookup map.
    // No need to check for collision here, because we compare the total count
    // of nodes VS size of map at the end of generation of the tree.
    uint64_t absolute_address = reg_status->get_absolute_address();
    pos.map_address_to_node[absolute_address] = n_sptr;
    pos.nodes++;

    // Store this node in the interrupt tree
    return n_sptr;
}

static bool
load_from_json(const char* json_file,
               parse_context& out_ctx,
               interrupt_tree::node_sptr& out_msi_root,
               vector<interrupt_tree::node_sptr>& out_non_wired_roots)
{
    json_error_t jerr;
    json_t* j_root = json_load_file(json_file, 0, &jerr);
    if (!j_root) {
        log_err(INTERRUPT, "Failed loading interrupt tree metadata, path %s, json_error %s", json_file, jerr.text);
        return false;
    }

    log_info(INTERRUPT,
             "Loading interrupt tree from %s: nodes %ld, unique %ld, registers %ld, bits %ld",
             json_file,
             out_ctx.nodes,
             out_ctx.map_address_to_node.size(),
             out_ctx.registers,
             out_ctx.bits);
    // The first level is a list of root nodes: [msi_root, non-wired-node-0, non-wired-node-1, ...]
    // interrupt_tree::node_sptr msi_root;
    // vector<interrupt_tree::node_sptr> roots(roots_n);
    size_t index;
    json_t* value;
    json_array_foreach(j_root, index, value)
    {
        interrupt_tree::node_sptr root = parse_node(value, out_ctx);
        if (!root) {
            log_err(INTERRUPT, "Failed parsing root at index=%ld", index);
            break;
        }
        if (index == 0) {
            out_msi_root = move(root);
        } else {
            out_non_wired_roots.push_back(move(root));
        }
    }

    size_t roots_n = json_array_size(j_root);
    json_decref(j_root);

    if (!out_msi_root) {
        return false;
    }
    if (out_non_wired_roots.size() + 1 != roots_n) {
        return false;
    }
    if (out_ctx.map_address_to_node.size() != out_ctx.nodes) {
        // Some nodes collided, check the json!
        log_err(INTERRUPT,
                "Bad number of interrupt nodes, from %s, nodes %ld, unique %ld, registers %ld, bits %ld",
                json_file,
                out_ctx.nodes,
                out_ctx.map_address_to_node.size(),
                out_ctx.registers,
                out_ctx.bits);
        return false;
    }

    log_info(INTERRUPT,
             "Loaded interrupt tree from %s: nodes %ld, unique %ld, registers %ld, bits %ld",
             json_file,
             out_ctx.nodes,
             out_ctx.map_address_to_node.size(),
             out_ctx.registers,
             out_ctx.bits);

    return true;
}

interrupt_tree::interrupt_tree(const ll_device_wptr& ll_device) : m_ll_device(ll_device)
{
    m_thresholds.mem_config[(int)la_mem_protect_error_e::ECC_1B] = (uint32_t)interrupt_default_threshold_e::MEM_CONFIG_ECC_1B;
    m_thresholds.mem_config[(int)la_mem_protect_error_e::ECC_2B] = (uint32_t)interrupt_default_threshold_e::MEM_CONFIG_ECC_2B;
    m_thresholds.mem_config[(int)la_mem_protect_error_e::PARITY] = (uint32_t)interrupt_default_threshold_e::MEM_CONFIG_PARITY;

    m_thresholds.mem_volatile[(int)la_mem_protect_error_e::ECC_1B] = (uint32_t)interrupt_default_threshold_e::MEM_VOLATILE_ECC_1B;
    m_thresholds.mem_volatile[(int)la_mem_protect_error_e::ECC_2B] = (uint32_t)interrupt_default_threshold_e::MEM_VOLATILE_ECC_2B;
    m_thresholds.mem_volatile[(int)la_mem_protect_error_e::PARITY] = (uint32_t)interrupt_default_threshold_e::MEM_VOLATILE_PARITY;

    m_thresholds.lpm_sram_ecc[(int)la_mem_protect_error_e::ECC_1B] = (uint32_t)interrupt_default_threshold_e::LPM_SRAM_ECC_1B;
    m_thresholds.lpm_sram_ecc[(int)la_mem_protect_error_e::ECC_2B] = (uint32_t)interrupt_default_threshold_e::LPM_SRAM_ECC_2B;
    m_thresholds.lpm_sram_ecc[(int)la_mem_protect_error_e::PARITY] = 0; // unused
}

void
interrupt_tree::set_thresholds(const interrupt_tree::thresholds& val)
{
    m_thresholds = val;
}

la_status
interrupt_tree::initialize()
{
    const char* base_outdir_env = getenv(BASE_OUTPUT_DIR_ENVVAR);
    string fname = base_outdir_env ? base_outdir_env : DEFAULT_BASE_OUTPUT_DIR;

    parse_context parse_ctx(m_ll_device.get());

    m_sbif_block_id = parse_ctx.sbif_block_id;

    fname += parse_ctx.json_fname;

    bool ok = load_from_json(fname.c_str(), parse_ctx, m_msi_root, m_non_wired_roots);
    if (!ok) {
        return LA_STATUS_EUNKNOWN;
    }
    m_map_address_to_node = move(parse_ctx.map_address_to_node);
    if (!is_valid()) {
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

bool
interrupt_tree::node::is_valid() const
{
    if (!status) {
        return false; // TODO: should be gone (or replaced with assert) when interrupt tree is fully modelled
    }
    if (status->get_desc()->width_in_bits != bits.size()) {
        log_err(INTERRUPT, "%s: reg width and bits counts do not match, %s", __func__, status->get_name().c_str());
        return false;
    }
    return true;
}

bool
interrupt_tree::bit::is_valid() const
{
    if (!parent) {
        log_err(INTERRUPT, "%s: %s, no parent", __func__, name.c_str());
        return false;
    }
    if (bit_i >= parent->bits.size()) {
        log_err(INTERRUPT, "%s: %s, bad bit_i=%ld", __func__, name.c_str(), bit_i);
        return false;
    }
    if (parent->bits[bit_i].get() != this) {
        log_err(INTERRUPT, "%s: %s, parent-to-bit reference does not match", __func__, name.c_str());
        return false;
    }
    return true;
}

bool
interrupt_tree::is_valid() const
{
    size_t errors = 0;
    auto node_cb = ([&](const node_scptr& node, size_t depth) {
        errors += !node->is_valid();
        // Continue traversing on all children bits, set all to '1'.
        return bit_vector::ones(node->status->get_desc()->width_in_bits);
    });
    auto bit_cb = ([&](const bit_scptr& bit, size_t depth) { errors += !bit->is_valid(); });

    traverse(node_cb, bit_cb);

    if (errors) {
        log_err(INTERRUPT, "%s: errors=%ld", __func__, errors);
        return false;
    }

    return true;
}

interrupt_tree::node_scptr
interrupt_tree::lookup_node(lld_register_scptr reg) const
{
    auto it = m_map_address_to_node.find(reg->get_absolute_address());
    if (it == m_map_address_to_node.end()) {
        return nullptr;
    }

    return it->second;
}

void
interrupt_tree::increment_interrupt_count(const interrupt_tree::bit_scptr& bit) const
{
    ++m_count_bits[bit];
}

void
interrupt_tree::increment_interrupt_count(const mem_protect_error& mem_error) const
{
    ++m_count_mem_errors[mem_error];
}

uint64_t
interrupt_tree::get_interrupt_count(const bit_scptr& bit)
{
    auto it = m_count_bits.find(bit);
    uint64_t val = (it == m_count_bits.end() ? 0 : it->second);

    return val;
}

uint64_t
interrupt_tree::get_interrupt_count(const mem_protect_error& mem_error)
{
    auto it = m_count_mem_errors.find(mem_error);
    uint64_t val = (it == m_count_mem_errors.end() ? 0 : it->second);

    return val;
}

void
interrupt_tree::reset_interrupt_counters()
{
    m_count_bits.clear();
    m_count_mem_errors.clear();
}

void
interrupt_tree::get_threshold_and_action(const bit_scptr& bit, la_notification_action_e& action_out, uint32_t& threshold_out)
{
    action_out = bit->action;

    // A single bit has a hard-coded threshold of '1' if action is defined for this bit.
    // Otherwise, the threshold is '0'.
    threshold_out = (bit->action == la_notification_action_e::NONE ? 0 : 1);
}

void
interrupt_tree::get_threshold_and_action(const mem_protect_error& mem_error,
                                         la_notification_action_e& action_out,
                                         uint32_t& threshold_out)
{
    dassert_crit((size_t)mem_error.error <= (size_t)la_mem_protect_error_e::LAST);

    bool is_volatile = mem_error.mem->get_desc()->is_volatile();
    threshold_out
        = (is_volatile ? m_thresholds.mem_volatile[(size_t)mem_error.error] : m_thresholds.mem_config[(size_t)mem_error.error]);

    // Threshold-crossing action for memories is always HARD_RESET, because SOFT_RESET retains the state of memories.
    uint64_t count = get_interrupt_count(mem_error);
    action_out = (count < threshold_out ? la_notification_action_e::NONE : la_notification_action_e::HARD_RESET);
}

void
interrupt_tree::get_threshold_and_action(const bit_scptr& bit,
                                         const lpm_sram_mem_protect& mem_error,
                                         la_notification_action_e& action_out,
                                         uint32_t& threshold_out)
{
    // LPM SRAM is organized in 8 cores, each core has 2 LPMs - a total of 16 LPMs.
    // Each of the LPMs has ecc1b and ecc2b interrupt bit.
    //
    // The interrupt count is per bit, hence, per LPM (one of 16) and per error type (ecc 1b or 2b).
    // Because the error entry is unknown, this is the finest resolution for the current ASIC.
    uint64_t count = get_interrupt_count(bit);
    threshold_out = m_thresholds.lpm_sram_ecc[(size_t)mem_error.error];
    action_out = (count < threshold_out ? la_notification_action_e::NONE : la_notification_action_e::HARD_RESET);
}

void
interrupt_tree::dump_tree(bool show_bits, bool show_values, const char* file_name) const
{
    std::ofstream out_file;
    if (file_name != nullptr) {
        out_file.open(file_name, std::ios::out);
        if (!out_file.is_open()) {
            log_err(INTERRUPT, "Failed to open file %s\n", file_name);
            return;
        }
    }

    auto node_cb = ([=, &out_file](const node_scptr& node, size_t depth) {
        string prefix(depth, '+');
        stringstream ss;

        ss << prefix << to_string(node);
        if (show_values) {
            bit_vector bv;
            m_ll_device->read_register(*node->status, bv);
            ss << ", status=" << bv.to_string();
            if (node->mask) {
                m_ll_device->read_register(*node->mask, bv);
                ss << ", mask=" << bv.to_string();
            } else {
                ss << ", mask=n/a";
            }
        }
        if (file_name == nullptr) {
            log_info(INTERRUPT, "%s\n", ss.str().c_str());
        } else {
            out_file << ss.str() << std::endl;
        }
        // Continue traversing on all children bits, set all to '1'.
        return bit_vector::ones(node->status->get_desc()->width_in_bits);
    });
    auto bit_cb = ([=, &out_file](const bit_scptr& bit, size_t depth) {
        if (show_bits) {
            string prefix(depth, '+');
            if (file_name == nullptr) {
                log_info(INTERRUPT, "%s %s\n", prefix.c_str(), to_string(bit).c_str());
            } else {
                out_file << prefix << " " << to_string(bit) << std::endl;
            }
        }
    });

    traverse(node_cb, bit_cb);
}

void
interrupt_tree::traverse(node_cb node_cb, bit_cb bit_cb) const
{
    traverse(m_msi_root, node_cb, bit_cb);

    for (auto& non_wired_root : m_non_wired_roots) {
        traverse(non_wired_root, node_cb, bit_cb);
    }
}

void
interrupt_tree::traverse(const node_scptr& root, node_cb node_cb, bit_cb bit_cb) const
{
    return do_traverse(root, 1, node_cb, bit_cb);
}

void
interrupt_tree::do_traverse(const node_scptr& node, size_t depth, node_cb node_cb, bit_cb bit_cb) const
{
    // node_cb() returns a mask that selects bits for further traversal
    bit_vector mask = node_cb(node, depth);
    if (mask.is_zero()) {
        return;
    }

    // Now iterate over all bits and process only those selected by mask
    for (size_t bit_i = 0; bit_i < node->bits.size(); ++bit_i) {
        if (mask.bit(bit_i)) {
            auto& bit = node->bits[bit_i];
            bit_cb(bit, depth);
            if (bit->type == interrupt_type_e::SUMMARY) {
                for (auto& child_node : bit->children) {
                    do_traverse(child_node, depth + 1, node_cb, bit_cb);
                }
            }
        }
    }
}

bit_vector
interrupt_tree::get_pending_interrupt_bits(const node_scptr& node) const
{
    bit_vector val;

    // Read interrupt status
    la_status rc = m_ll_device->read_register(*node->status, val);
    if (rc) {
        log_err(INTERRUPT, "%s: failed reading from %s", __func__, node->status->get_name().c_str());
        val = 0;
        return val;
    }
    if (val.is_zero()) {
        // no pending interrupts.
        return val;
    }

    // Interrupt status is non-zero, go on, check the mask
    if (!node->mask) {
        // Whatever is pending is unmaskable.
        // This applies to
        //  - Master Interrupt, indeed unmaskable
        //  - Mem Protect, maskable, but the masking is tricky, a TODO for now.
        log_xdebug(INTERRUPT, "%s: %s, pending bits=0x%s, mask n/a", __func__, to_string(node).c_str(), val.to_string().c_str());
        return val;
    }

    // Interrupt status is non-zero and there is a mask register.
    // Read interrupt mask and apply it to status.
    bit_vector mask_val;
    m_ll_device->read_register(*node->mask, mask_val);
    if (node->is_mask_active_low) {
        mask_val = ~mask_val;
    }

    // Apply the mask. If 'val' becomes 0 as a result, this means that the interrupt is pending but masked.
    bit_vector val_and_mask = val & mask_val;
    if (val_and_mask.is_zero()) {
        log_xdebug(INTERRUPT,
                   "%s: %s a pending interrupt 0x%s is masked by 0x%s",
                   __func__,
                   node->status->get_name().c_str(),
                   val.to_string().c_str(),
                   mask_val.to_string().c_str());
    } else {
        // Finally, all "set" bits in 'val' correspond to pending and not-masked interrupts.
        log_xdebug(INTERRUPT, "%s: %s, pending bits = 0x%s", __func__, to_string(node).c_str(), val.to_string().c_str());
    }

    return val_and_mask;
}

interrupt_tree::mem_protect_errors
interrupt_tree::collect_mem_protect_errors(const node_scptr& node) const
{
    const auto& mp = node->mem_protect;
    mem_protect_errors res;

    // Here we read mem_protect errors for a specific block, the one this 'node' belongs to.
    // The behavior is "clear-on-read".
    //  - mem_error counters are cleared-on-read automatically in sylicon.
    //  - mem_error reset is toggled 0-1-0 by host as the last step here.
    //
    // Steps:
    // 1. Disable masks
    // 2. Iterate over memories that have a pending error and read mem_error info.
    // 3. Read error counters (auto-cleared).
    //    This step is optional, since we retur
    // 4. Reset error state by toggling 0-1-0
    // 5. Restore masks

    // Step 0: Check if this node has protected memories
    if (mp.protected_memories.empty()) {
        return res;
    }

    // Step 1. Disable masks
    auto save = save_and_disable_mem_protect_masks(node);

    // Step 2. Iterate over memories that have a pending error and read mem_error info.

    // Read error status bits - one bit per instance of ECC/Parity-protected memory
    bit_vector bv(0);
    m_ll_device->read_register(*mp.mem_protect_err_status, bv);
    if (bv.is_zero()) {
        return res;
    }

    // Iterate through error status bits, add collected errors to 'res'
    for (size_t i = 0; i < mp.protected_memories.size(); ++i) {
        if (bv.bit(i)) {
            read_mem_protect_error(node, i, res);
        }
    }

    // Step 3. Read error counters (auto-cleared)
    //  We skip this step, since we return a vector of actual errors.

    // Step 4. Reset error state of all block's memories by toggling the reset bit 0-1-0

    bv = 0;
    bit_vector bv_reset(0, mp.ser_error_debug_configuration->get_desc()->width_in_bits);
    pack_field(bv_reset, mp.reset_memory_errors, 1);

    m_ll_device->write_register(*mp.ser_error_debug_configuration, bv);
    m_ll_device->write_register(*mp.ser_error_debug_configuration, bv_reset);
    m_ll_device->write_register(*mp.ser_error_debug_configuration, bv);

    // Step 5:
    restore_mem_protect_masks(node, save);

    return res;
}

interrupt_tree::cause_bits
interrupt_tree::collect_msi_interrupts() const
{
    return do_collect_interrupts(m_msi_root);
}

interrupt_tree::cause_bits
interrupt_tree::collect_non_wired_interrupts() const
{
    cause_bits all;

    for (const node_sptr& non_wired_root : m_non_wired_roots) {
        cause_bits causes = do_collect_interrupts(non_wired_root);
        all.insert(std::end(all), std::begin(causes), std::end(causes));
    }

    return all;
}

interrupt_tree::cause_bits
interrupt_tree::do_collect_interrupts(const interrupt_tree::node_scptr& root) const
{
    cause_bits causes;

    auto node_cb = ([&](const node_scptr& node, size_t depth) {
        bit_vector val = get_pending_interrupt_bits(node);
        if (val.is_zero()) {
            if (node->parent) {
                // Interrupt branch is chopped off here, the node is clear (contains no pending bits).
                // The parent is a SUMMARY bit and it is the leaf of the pending interrupt branch.
                // Add this SUMMARY bit to the list of causes.
                causes.push_back(node->parent.lock());
                log_debug(INTERRUPT,
                          "collect_interrupts: summary bit {%s} is pending but node is clear {%s}",
                          to_string(node->parent.lock()).c_str(),
                          to_string(node).c_str());
            } else {
                // no parent --> this is the root node, ignore
            }
        }

        return val;
    });
    auto bit_cb = ([&](const bit_scptr& bit, size_t depth) {
        if (bit->type != interrupt_type_e::SUMMARY) {
            // We found a pending "leaf" bit - this is the interrupt cause
            causes.push_back(bit);
            increment_interrupt_count(bit);
        }
    });

    traverse(root, node_cb, bit_cb);

    dump_cause_bits(causes);

    return causes;
}

void
interrupt_tree::clear()
{
    // Traverse the tree, collect pending leafs
    cause_bits bits = collect_msi_interrupts();
    cause_bits non_wired_bits = collect_non_wired_interrupts();
    bits.insert(std::end(bits), std::begin(non_wired_bits), std::end(non_wired_bits));
    if (bits.empty()) {
        log_debug(INTERRUPT, "%s: already clear", __func__);
        return;
    }

    set<node_wcptr> mem_protect_nodes;
    auto remove_condition = ([&](interrupt_tree::bit_scptr bit) {
        if (bit->type == interrupt_type_e::MEM_PROTECT) {
            mem_protect_nodes.insert(bit->parent);
            return true; // remove
        }

        return false; // do not remove
    });

    // Remove mem_protect bits and group them by nodes
    bits.erase(std::remove_if(bits.begin(), bits.end(), remove_condition), bits.end());

    log_debug(INTERRUPT, "%s: mem-protect=%ld, other=%ld", __func__, mem_protect_nodes.size(), bits.size());

    // Clear mem-protect errors by resetting SER registers then clear the interrupt.
    for (auto& node : mem_protect_nodes) {
        node_scptr node_s(node.lock());
        clear_mem_protect_errors_and_interrupts(node_s);
    }

    // Clear anything other than mem-protect by just clearing the interrupt.
    for (const auto& bit : bits) {
        clear_interrupt_cause(bit);
    }
}

// Convenience API - doesn't take interrupt_tree::node/bit arguments.
la_status
interrupt_tree::clear_interrupt(lld_register_scptr reg, const bit_vector& bits)
{
    node_scptr node = lookup_node(reg);
    if (!node) {
        log_err(INTERRUPT, "%s: %s, not an interrupt register", __func__, reg->get_name().c_str());
        return LA_STATUS_EINVAL;
    }
    if (bits.get_width() > reg->get_desc()->width_in_bits) {
        log_err(INTERRUPT,
                "%s: %s, value is too wide, value width=%ld, reg width=%d",
                __func__,
                reg->get_name().c_str(),
                bits.get_width(),
                reg->get_desc()->width_in_bits);
        return LA_STATUS_ESIZE;
    };

    clear_interrupt_cause(node, bits);

    return LA_STATUS_SUCCESS;
}

// Convenience API - doesn't take interrupt_tree::node/bit arguments.
la_status
interrupt_tree::clear_interrupt(lld_register_scptr reg, size_t bit_i)
{
    bit_vector bv;
    bv.set_bit(bit_i, true);
    return clear_interrupt(reg, bv);
}

// Convenience API - doesn't take interrupt_tree::node/bit arguments.
la_status
interrupt_tree::clear_interrupt(lld_memory_scptr mem)
{
    lld_register_scptr reg = mem->get_block()->get_register(lld_register::MEM_PROTECT_INTERRUPT);
    node_scptr node = lookup_node(reg);
    if (!node) {
        // nullptr means not modeled in the interrupt_tree
        log_err(INTERRUPT, "%s: %s is not modeled in the interrupt tree", __func__, mem->get_name().c_str());
        return LA_STATUS_EUNKNOWN;
    }

    clear_mem_protect_errors_and_interrupts(node);

    return LA_STATUS_SUCCESS;
}

void
interrupt_tree::clear_mem_protect_errors_and_interrupts(const node_scptr& node)
{
    // collect mem-protect errors (ignore the collected errors) and clear SER registers.
    collect_mem_protect_errors(node);

    // Clear all mem_protect interrupts at node level at once
    static constexpr uint64_t val = (1 << (uint64_t)la_mem_protect_error_e::ECC_1B)
                                    | (1 << (uint64_t)la_mem_protect_error_e::ECC_2B)
                                    | (1 << (uint64_t)la_mem_protect_error_e::PARITY);
    // clear mem-protect interrupt and summaries
    clear_interrupt_cause(node, bit_vector(val));
}

void
interrupt_tree::clear_interrupt_summary(const node_scptr& node) const
{
    if (node->parent) {
        clear_summary_bit(node->parent.lock());
    }
}

void
interrupt_tree::clear_interrupt_cause(const node_scptr& node, const bit_vector& val) const
{
    write_interrupt_register(node->status, val);

    clear_interrupt_summary(node);
}

void
interrupt_tree::clear_interrupt_cause(const bit_scptr& bit) const
{
    clear_interrupt_cause(bit->parent.lock(), bit_vector(1 << bit->bit_i));
}

void
interrupt_tree::clear_summary_bit(const bit_scptr& bit) const
{
    node_scptr node = bit->parent.lock();
    write_interrupt_register(node->status, bit_vector(1 << bit->bit_i));

    if (node->parent) {
        // Recurse to the upstream "summary" bit
        clear_summary_bit(node->parent.lock());
        return;
    }

    // We are done, reached the root node
}

void
interrupt_tree::write_interrupt_register(lld_register_scptr reg, const bit_vector& val) const
{
    if (reg->get_desc()->addr == lld_register::MASTER_INTERRUPT) {
        // Master Interrupt register is read-only
        return;
    }

    // An interrupt bit is cleared by writing "1" to it.
    // Writing a "0" has no effect.
    m_ll_device->write_register(*reg, val);
}

void
interrupt_tree::dampen_interrupt_cause(const bit_scptr& bit)
{
    lld_register_scptr reg = bit->parent->mask;
    if (!reg) {
        return;
    }
    if (bit->type == interrupt_type_e::SUMMARY) {
        return;
    }

    log_debug(INTERRUPT, "%s: reg=%s, bit_i=%s", __func__, reg->get_name().c_str(), to_string(bit).c_str());
    dampen_interrupt_mask(reg, bit->bit_i, bit->parent->is_mask_active_low);
}

vector<bit_vector>
interrupt_tree::save_and_disable_mem_protect_masks(const node_scptr& node) const
{
    size_t n = silicon_one::array_size(node->mem_protect.masks);
    vector<bit_vector> save(n);

    // Read and save the current values of masks
    // Write all-ones to disable masks
    for (size_t i = 0; i < n; ++i) {
        lld_register_scptr mask = node->mem_protect.masks[i];
        if (mask) {
            m_ll_device->read_register(*mask, save[i]);
            m_ll_device->write_register(*mask, bit_vector::ones(mask->get_desc()->width_in_bits));
        }
    }

    return save;
}

void
interrupt_tree::restore_mem_protect_masks(const node_scptr& node, const vector<bit_vector>& save) const
{
    // Restore to the previously saved value
    for (size_t i = 0; i < save.size(); ++i) {
        lld_register_scptr mask = node->mem_protect.masks[i];
        if (mask) {
            m_ll_device->write_register(*mask, save[i]);
        }
    }
}

la_status
interrupt_tree::get_memory_index_in_mask(const interrupt_tree::node_scptr& node, lld_memory_scptr mem, size_t& out_bit_i)
{
    lld_memory_protection_e protection = mem->get_desc()->protection;
    if (protection == lld_memory_protection_e::NONE) {
        return LA_STATUS_EINVAL;
    }

    const lld_block::lld_memory_vec_t* protected_memories;
    if (protection == lld_memory_protection_e::ECC || protection == lld_memory_protection_e::EXT_ECC) {
        protected_memories = &node->mem_protect.ecc_protected_memories;
    } else {
        protected_memories = &node->mem_protect.parity_protected_memories;
    }

    // Find index of mask bit that corresponds to this memory.
    size_t i;
    for (i = 0; i < protected_memories->size(); ++i) {
        if (mem->get_desc()->addr == (*protected_memories)[i]->get_desc()->addr) {
            out_bit_i = i;
            return LA_STATUS_SUCCESS;
        }
    }

    log_err(INTERRUPT, "no matching mask bit for mem=%s", mem->get_name().c_str());

    return LA_STATUS_ENOTFOUND;
}

void
interrupt_tree::dampen_mem_protect_error(const node_scptr& node, const mem_protect_error& e)
{
    // ensured by read_mem_protect_error()
    dassert_crit((uint64_t)e.error <= (uint64_t)la_mem_protect_error_e::LAST);

    // Step 1: find mask register and bit in register that correspond to this mem_protect error.

    // Mask register, must be ECC_1B_ERR_INTERRUPT_MASK, ECC_2B_ERR_INTERRUPT_MASK or PARITY_ERR_INTERRUPT_MASK
    lld_register_scptr mask_reg = node->mem_protect.masks[(size_t)e.error];
    if (!mask_reg) {
        log_err(INTERRUPT, "unexpected error type %ld for mem=%s", (size_t)e.error, e.mem->get_name().c_str());
        return;
    }

    size_t mask_bit = 0;
    la_status rc = get_memory_index_in_mask(node, e.mem, mask_bit);
    if (rc) {
        return;
    }

    // Step 2: mask off this specific mem_protect error - a bit in ECC_1B or ECC_2B or PARITY mask
    log_debug(INTERRUPT, "%s: err=%s for mem=%s", __func__, silicon_one::to_string(e.error).c_str(), e.mem->get_name().c_str());
    dampen_interrupt_mask(mask_reg, mask_bit, true /* is_mask_active_low */);
}

void
interrupt_tree::read_mem_protect_error(const node_scptr& node, size_t memory_index, mem_protect_errors& errors) const
{
    const auto& mp = node->mem_protect;

    // Select memory
    bit_vector bv(0);
    pack_field(bv, mp.erroneous_memory_selector, memory_index);
    m_ll_device->write_register(*mp.ser_error_debug_configuration, bv);

    // Read error info from selected memory
    bv = 0;
    m_ll_device->read_register(*mp.selected_ser_error_info, bv);

    // Check if value belongs to enum
    la_mem_protect_error_e err = (la_mem_protect_error_e)unpack_field(bv, mp.mem_err_type);
    if ((uint64_t)err > (uint64_t)la_mem_protect_error_e::LAST) {
        log_err(INTERRUPT, "%s: unexpected selected_ser_error_info val=%s", __func__, bv.to_string().c_str());
        return;
    }
    la_entry_addr_t err_addr = (la_entry_addr_t)unpack_field(bv, mp.mem_err_addr);

    mem_protect_error mem_error{.mem = mp.protected_memories[memory_index], .error = err, .entry = err_addr};
    errors.push_back(mem_error);
    increment_interrupt_count(mem_error);
}

void
interrupt_tree::dump_cause_bits(const cause_bits& cause_bits) const
{
    for (const auto& bit : cause_bits) {
        lld_register_scptr reg = bit->parent->status;
        log_debug(INTERRUPT, "%s: %s, %s", __func__, reg->get_name().c_str(), to_string(bit).c_str());
    }
}

void
interrupt_tree::dampen_interrupt_mask(lld_register_scptr reg, size_t bit_index, bool is_mask_active_low)
{
    // Read...
    bit_vector rval;
    m_ll_device->read_register(*reg, rval);

    if (rval.bit(bit_index) == is_mask_active_low) {
        // The interrupt bit is already masked off - should not happen!
        log_debug(INTERRUPT, "%s: %s[%ld] is already masked off", __func__, reg->get_name().c_str(), bit_index);
        return;
    }

    // Modify...
    bit_vector wval = rval;
    wval.set_bit(bit_index, is_mask_active_low);

    // Write
    m_ll_device->write_register(*reg, wval);

    if (m_dampened.find(reg) == m_dampened.end()) {
        dampen_mask_register_info info{.is_mask_active_low = is_mask_active_low,
                                       .initial_value = rval,
                                       .time_points
                                       = vector<time_point>(reg->get_desc()->width_in_bits, // vector size
                                                            time_point::min() // fill value, all bits are initially not touched
                                                            )};
        m_dampened[reg] = info;
    }

    m_dampened[reg].time_points[bit_index] = chrono::steady_clock::now();
}

la_status
interrupt_tree::reenable_dampened_interrupts(interrupt_tree::time_point older_than)
{
    size_t count_masked_off = 0, count_restored = 0;

    for (auto& it : m_dampened) {
        dampen_mask_register_info& info = it.second;
        bit_vector restore_value = info.initial_value;
        bool should_restore = false;

        for (size_t bit_i = 0; bit_i < info.time_points.size(); ++bit_i) {
            time_point& ts = info.time_points[bit_i];
            if (ts == time_point::min()) {
                // time_point is not set, the bit is not masked-off.
                continue;
            }

            // time_point is set ==> the bit is masked-off.
            if (ts >= older_than) {
                // If not masked off for long enough - leave as masked-off.
                restore_value.set_bit(bit_i, info.is_mask_active_low);
                ++count_masked_off;
            } else {
                // Masked off for long enough, restore.
                ts = time_point::min();
                should_restore = true;
                ++count_restored;
            }
        }

        if (should_restore) {
            lld_register_scptr reg_mask = it.first;
            log_debug(INTERRUPT, "%s: restore %s=%s", __func__, reg_mask->get_name().c_str(), restore_value.to_string().c_str());
            la_status rc = m_ll_device->write_register(*reg_mask, restore_value);
            if (rc) {
                return rc;
            }
        }
    }

    log_xdebug(INTERRUPT, "%s: restored %ld bits, still masked off %ld bits", __func__, count_restored, count_masked_off);

    return LA_STATUS_SUCCESS;
}

void
interrupt_tree::remove_from_dampening(lld_register_scptr mask_reg, const bit_vector& bits)
{
    if (m_dampened.find(mask_reg) == m_dampened.end()) {
        return;
    }

    log_debug(INTERRUPT, "%s: remove mask_reg=%s, bits=%s", __func__, mask_reg->get_name().c_str(), bits.to_string().c_str());

    size_t msb = std::min(bits.get_width(), (size_t)mask_reg->get_desc()->width_in_bits);

    for (size_t bit_i = 0; bit_i < msb; ++bit_i) {
        if (!bits.bit(bit_i)) {
            continue;
        }
        // Reset dampening timestamp, as if this bit was never dampened.
        m_dampened[mask_reg].time_points[bit_i] = time_point::min();
        // Set the initial value to masked-off.
        m_dampened[mask_reg].initial_value.set_bit(bit_i, true);
    }
}

la_status
interrupt_tree::get_interrupt_mask_register(lld_register_scptr reg, lld_register_scptr& out_mask_reg)
{
    const lld_register_desc_t* desc = reg->get_desc();

    if (reg->get_block_id() == m_sbif_block_id) {
        log_err(INTERRUPT, "%s: %s enable/disable for SBIF interrupt is not supported", __func__, reg->get_name().c_str());
        return LA_STATUS_EINVAL;
    }
    if (!reg->is_valid()) {
        log_err(INTERRUPT, "%s: %s is invalid", __func__, reg->get_name().c_str());
        return LA_STATUS_EINVAL;
    }
    if (desc->type == lld_register_type_e::INTERRUPT_MASK) {
        out_mask_reg = reg;
        return LA_STATUS_SUCCESS;
    }
    if (desc->type != lld_register_type_e::INTERRUPT) {
        log_err(INTERRUPT, "%s: %s is not an interrupt register", __func__, reg->get_name().c_str());
        return LA_STATUS_EINVAL;
    }
    if (desc->addr == lld_register::MASTER_INTERRUPT) {
        log_err(INTERRUPT, "%s: %s is non-maskable", __func__, reg->get_name().c_str());
        return LA_STATUS_EINVAL;
    }
    if (desc->addr == lld_register::MEM_PROTECT_INTERRUPT) {
        log_err(
            INTERRUPT, "%s: %s, mem-protect interrupt should be set/get per memory instance.", __func__, reg->get_name().c_str());
        return LA_STATUS_EINVAL;
    }

    // All interrupt registers that are not MASTER and not MEM_PROTECT have this layout:
    //
    //   interrupt            addr0[,addr1[,addr2...]]
    //   interrupt_mask       addr0+1[,addr1+1[,addr2+1...]]
    //   interrupt_test       addr0+2[,addr1+2[,addr2+2...]]
    lld_register_scptr mask_reg = reg->get_block()->get_register(desc->addr + desc->instances);
    if (!mask_reg || mask_reg->get_desc()->type != lld_register_type_e::INTERRUPT_MASK) {
        log_err(INTERRUPT, "%s: failed getting a mask register for %s", __func__, reg->get_name().c_str());
        return LA_STATUS_EUNKNOWN;
    }

    out_mask_reg = mask_reg;

    return LA_STATUS_SUCCESS;
}

la_status
interrupt_tree::set_interrupt_enabled(lld_register_scptr reg, size_t bit_i, bool enabled, bool clear)
{
    bit_vector bits;
    bits.set_bit(bit_i, true);

    return set_interrupt_enabled(reg, bits, enabled, clear);
}

la_status
interrupt_tree::set_interrupt_enabled(lld_register_scptr reg, const bit_vector& bits, bool enabled, bool clear)
{
    lld_register_scptr mask_reg = nullptr;
    la_status rc = get_interrupt_mask_register(reg, mask_reg);
    return_on_error(rc);

    rc = do_set_interrupt_enabled(reg, mask_reg, bits, enabled, clear);

    return rc;
}

la_status
interrupt_tree::do_set_interrupt_enabled(lld_register_scptr reg,
                                         lld_register_scptr mask_reg,
                                         const bit_vector& bits_in,
                                         bool enabled,
                                         bool clear)
{
    const lld_register_desc_t* desc = mask_reg->get_desc();
    if (bits_in.get_width() > desc->width_in_bits) {
        log_err(INTERRUPT,
                "%s: %s, bits=%s out of range, width_in_bits=%d",
                __func__,
                mask_reg->get_name().c_str(),
                bits_in.to_string().c_str(),
                desc->width_in_bits);
        return LA_STATUS_EOUTOFRANGE;
    }

    bit_vector bits = bits_in;
    bits.resize(desc->width_in_bits);

    // If setting to 'disabled' and the register is in the dampening pool, make sure the bit is not re-enabled by
    // reenable_dampened_interrupts()
    if (!enabled) {
        remove_from_dampening(mask_reg, bits);
    }

    // Update the mask for this interrupt register.
    // No need to update summaries, because they are initialized once at init().
    bit_vector bv;
    la_status rc = m_ll_device->read_register(*mask_reg, bv);
    return_on_error(rc);

    // Active low logic, 0 == enabled, 1 == disabled
    if (enabled) {
        bv = bv & (~bits);
    } else {
        bv = bv | bits;
    }

    if (reg && enabled && clear) {
        // clear before enable
        rc = m_ll_device->write_register(*reg, bits_in);
        return_on_error(rc);
    }
    // set mask - enable or disable
    rc = m_ll_device->write_register(*mask_reg, bv);
    return_on_error(rc);
    if (reg && !enabled && clear) {
        // clear after disable
        rc = m_ll_device->write_register(*reg, bits_in);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
interrupt_tree::get_interrupt_enabled(lld_register_scptr reg, size_t bit_i, bool& out_enabled)
{
    if (bit_i >= reg->get_desc()->width_in_bits) {
        log_err(INTERRUPT,
                "%s: %s, bit_i=%ld out of range, width_in_bits=%d",
                __func__,
                reg->get_name().c_str(),
                bit_i,
                reg->get_desc()->width_in_bits);
        return LA_STATUS_EOUTOFRANGE;
    }

    lld_register_scptr mask_reg = nullptr;
    la_status rc = get_interrupt_mask_register(reg, mask_reg);
    return_on_error(rc);

    // Check if the interrupt register is wired into HW interrupt tree.
    // If yes, check the mask register
    node_scptr node = lookup_node(reg);
    if (node) {
        // Wired
        bit_vector bv;
        rc = m_ll_device->read_register(*mask_reg, bv);
        return_on_error(rc);

        out_enabled = !bv.bit(bit_i);
    } else {
        // Not wired
        // TODO: re-write this case if we poll for non-wired interrupts.
        log_debug(INTERRUPT, "%s: %s is not wired to interrupt tree", __func__, reg->get_name().c_str());
        out_enabled = false;
    }

    return LA_STATUS_SUCCESS;
}

la_status
interrupt_tree::set_interrupt_enabled(lld_memory_scptr mem, bool enabled, bool clear)
{
    return get_or_set_interrupt_enabled(mem, false /* is_get */, clear, enabled);
}

la_status
interrupt_tree::get_interrupt_enabled(lld_memory_scptr mem, bool& out_enabled)
{
    return get_or_set_interrupt_enabled(mem, true /* is_get */, false /* clear_on_set */, out_enabled);
}

la_status
interrupt_tree::get_or_set_interrupt_enabled(lld_memory_scptr mem, bool is_get, bool clear_on_set, bool& in_out_enabled)
{
    lld_memory_protection_e protection = mem->get_desc()->protection;
    if (protection == lld_memory_protection_e::NONE) {
        log_err(INTERRUPT, "%s: %s is not a protected memory", __func__, mem->get_name().c_str());
        return LA_STATUS_EINVAL;
    }

    lld_register_scptr reg = mem->get_block()->get_register(lld_register::MEM_PROTECT_INTERRUPT);

    const interrupt_tree::node_scptr node = lookup_node(reg);
    // nullptr means not modeled in the interrupt tree
    if (!node) {
        log_debug(INTERRUPT, "%s: %s is not modeled in the interrupt tree", __func__, mem->get_name().c_str());
        if (is_get) {
            in_out_enabled = false;
        }
        return LA_STATUS_SUCCESS;
    }

    size_t bit_i;
    la_status rc = get_memory_index_in_mask(node, mem, bit_i);
    return_on_error(rc);

    lld_register_scptr masks[2] = {};
    if (protection == lld_memory_protection_e::ECC || protection == lld_memory_protection_e::EXT_ECC) {
        masks[0] = node->mem_protect.masks[(size_t)la_mem_protect_error_e::ECC_1B];
        masks[1] = node->mem_protect.masks[(size_t)la_mem_protect_error_e::ECC_2B];
    } else {
        masks[0] = node->mem_protect.masks[(size_t)la_mem_protect_error_e::PARITY];
    }

    // Before enable, clear mem-protect errors by resetting SER registers then clear the interrupt.
    if (!is_get && clear_on_set && in_out_enabled) {
        clear_mem_protect_errors_and_interrupts(node);
    }

    bit_vector bv;
    bool out_enabled = true;
    for (auto mask : masks) {
        if (!mask) {
            continue;
        }
        if (is_get) {
            // Check if ecc1b/2b or parity masks are enabled
            rc = m_ll_device->read_register(*mask, bv);
            return_on_error(rc);
            if (bv.bit(bit_i)) {
                out_enabled = false;
                break;
            }
        } else {
            // Enable ecc1b/2b or parity masks
            bit_vector bits;
            bits.set_bit(bit_i, true);

            rc = do_set_interrupt_enabled(nullptr, mask, bits, in_out_enabled, false /* clear */);
            return_on_error(rc);
        }
    }

    // After disable, clear mem-protect errors by resetting SER registers then clear the interrupt.
    if (!is_get && clear_on_set && !in_out_enabled) {
        clear_mem_protect_errors_and_interrupts(node);
    }

    if (is_get) {
        in_out_enabled = out_enabled;
    }

    return LA_STATUS_SUCCESS;
}

la_status
interrupt_tree::save_state(json_t* out_root) const
{
    std::map<interrupt_type_e, size_t> type_to_count;
    for (const auto it : m_count_bits) {
        type_to_count[it.first->type] += it.second;
    }

    json_t* interrpt_types = json_object();
    for (const auto it : type_to_count) {
        json_object_set_new(interrpt_types, silicon_one::to_string(it.first).c_str(), json_integer(it.second));
    }

    json_t* mem_protection = json_object();
    for (const auto it : m_count_mem_errors) {
        json_object_set_new(mem_protection, it.first.mem->get_short_name().c_str(), json_integer(it.second));
    }

    json_object_set_new(out_root, "interrpt_types", interrpt_types);
    json_object_set_new(out_root, "mem_protection", mem_protection);

    return LA_STATUS_SUCCESS;
}

la_status
interrupt_tree::save_state(std::string file_name) const
{
    json_t* root_node = json_object();
    la_status stat = save_state(root_node);
    return_on_error(stat);

    stat = file_utils::write_json_to_file(root_node, file_name);
    json_decref(root_node);

    return stat;
}

} // namespace silicon_one
