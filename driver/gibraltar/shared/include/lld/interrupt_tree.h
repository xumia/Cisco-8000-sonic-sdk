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

#ifndef __INTERRUPT_TREE_H__
#define __INTERRUPT_TREE_H__

#include "api/types/la_notification_types.h"
#include "common/allocator_wrapper.h"
#include "common/bit_vector.h"

#include "interrupt_types.h"
#include "lld/lld_block.h"
#include "lld/lld_fwd.h"

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <vector>

namespace silicon_one
{

class interrupt_tree
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    interrupt_tree(const ll_device_wptr& ll_device);
    la_status initialize();

    struct node;
    struct bit;

    // All tree elements (nodes and bits) are stored as unique_ptr (node stores vector of bit_sptr's and bit stores vector of
    // node_uptr's).
    // As a result, the tree is freed automatically.
    // A nice side effect is that 'node' and 'bit' are not copyable, because both contain unique_ptr's.
    using node_sptr = std::shared_ptr<node>;
    using node_scptr = std::shared_ptr<const node>;
    using node_wcptr = weak_ptr_unsafe<const node>;
    using bit_sptr = std::shared_ptr<bit>;
    using bit_scptr = std::shared_ptr<const bit>;
    using bit_wptr = weak_ptr_unsafe<bit>;
    using bit_wcptr = weak_ptr_unsafe<const bit>;

    // Interrupt causes are "leaf" bits of the interrupt tree
    using cause_bits = vector_alloc<bit_scptr>;

    static std::string to_string(const node_scptr& node);
    static std::string to_string(const bit_scptr& bit);

    struct mem_protect_error {
        lld_memory_scptr mem;
        la_mem_protect_error_e error;
        la_entry_addr_t entry;
    };
    using mem_protect_errors = vector_alloc<mem_protect_error>;

    // A "cause" bit has no children.
    // A "summary" bit is normally mapped 1:1 to a single next-level node.
    // Rarely, "summary" bit is mapped 1:N to multiple next-level nodes.
    struct bit {
        // Fields loaded from metadata
        std::string name;                ///< Name of this bit
        interrupt_type_e type;           ///< Summary or one of the interrupt causes.
        la_notification_action_e action; ///< Action request when count reaches the threshold.
        std::vector<node_sptr> children; ///< Unordered collection of next level nodes, empty if the bit is not a summary.
        bool is_masked;                  ///< Is this bit masked.

        // Useful extra info (not from metadata)
        node_wcptr parent; ///< Parent node
        size_t bit_i;      ///< Index of this bit in the register (zero-based)

        bool is_valid() const;
    };

    struct register_field {
        size_t msb;
        size_t lsb;
    };

    struct node {
        // Fields loaded from metadata
        lld_register_scptr status;  ///< Interrupt status register
        lld_register_scptr mask;    ///< Interrupt mask register
        bool is_mask_active_low;    ///< Usually false as the mask is usually active-high
        std::vector<bit_sptr> bits; ///< Interrupt "source" or "summary" bits. Vector index corresponds to bit index in HW.

        // Useful extra info (not from metadata)
        bit_wptr parent; ///< Parent summary bit

        // mem_protect registers and memories
        struct mem_protect_s {
            lld_register_scptr masks[(size_t)la_mem_protect_error_e::LAST + 1];     ///< ECC 1b/2b and Parity masks
            lld_register_scptr err_debug[(size_t)la_mem_protect_error_e::LAST + 1]; ///< ECC 1b/2b and Parity error counters

            lld_register_scptr mem_protect_err_status; ///< Error status, 1b per memory

            /// Memory select & reset register and its fields
            lld_register_scptr ser_error_debug_configuration;
            register_field erroneous_memory_selector;
            register_field reset_memory_errors;

            /// Selected memory info register and its fields
            lld_register_scptr selected_ser_error_info;
            register_field mem_err_addr;
            register_field mem_err_type;

            /// Vector of ECC and Parity protected memories
            /// Indices of memories in vector match indices of bits in mem_protect_err_status register.
            lld_block::lld_memory_vec_t protected_memories;

            /// Vector of ECC protected memories
            /// Indices of memories in vector match indices of bits in ecc_{1,2}_err_interrupt_register_mask register.
            lld_block::lld_memory_vec_t ecc_protected_memories;

            /// Vector of Parity protected memories
            /// Indices of memories in vector match indices of bits in ecc_{1,2}_err_interrupt_register_mask register.
            lld_block::lld_memory_vec_t parity_protected_memories;
        } mem_protect;

        bool is_valid() const;
    };

    // Visit node, called before bits are visited. Return a mask which selects bits for further recursion.
    using node_cb = std::function<bit_vector(const node_scptr& node, size_t depth)>;

    // Visit bit, called before bit's children nodes are visited
    using bit_cb = std::function<void(const bit_scptr& bit, size_t depth)>;

    // Traverse the interrupt tree starting from root node.
    // Call node_cb() and bit_cb() for nodes and bits respectively.
    // Both callbacks are called at the earliest possible point, i.e. before recursing deeper.
    // Descend from node to children 'bits' based on bitmask returned by node_cb.
    void traverse(const node_scptr& root, node_cb node_cb, bit_cb bit_cb) const;

    // Traverse all trees - msi root and non-wired roots.
    void traverse(node_cb node_cb, bit_cb bit_cb) const;

    bool is_valid() const;
    void dump_tree(bool show_bits, bool show_values, const char* file_name) const;
    void dump_cause_bits(const cause_bits& cause_bits) const;

    // Look up interrupt node by interrupt register
    node_scptr lookup_node(lld_register_scptr reg) const;

    // Clear all interrupts
    void clear();

    // Collect interrupt causes ("leaf" interrupt bits) starting from MSI root.
    cause_bits collect_msi_interrupts() const;

    // Collect interrupt causes ("leaf" interrupt bits) for non-wired interrupts.
    cause_bits collect_non_wired_interrupts() const;

    // Collect all mem_protect errors for a block this node belongs to. The behavior is clear-on-read.
    mem_protect_errors collect_mem_protect_errors(const node_scptr& node) const;

    // Clear a single interrupt cause bit by writing '1' to the corresponding bit in node's status register.
    void clear_interrupt_cause(const bit_scptr& cause_bit) const;

    // Clear one or more cause bits by writing 'val' to node's status register
    void clear_interrupt_cause(const node_scptr& node, const bit_vector& val) const;

    // Clear the branch of summary bits above this node
    void clear_interrupt_summary(const node_scptr& node) const;

    // Dampen interrupt cause, mask off for a limitted period of time.
    void dampen_interrupt_cause(const bit_scptr& bit);

    // Dampen a specific mem_protect error (the combination of memory instance + error type) in this node
    // The mem_protect error is masked off for a limitted period of time.
    void dampen_mem_protect_error(const node_scptr& node, const mem_protect_error& error);

    void remove_from_dampening(lld_register_scptr mask_reg, const bit_vector& bits);

    using time_point = std::chrono::time_point<std::chrono::steady_clock>;
    la_status reenable_dampened_interrupts(interrupt_tree::time_point older_than);

    // SW action thresholds, configured through la_device_property_e::xxx
    struct thresholds {
        uint32_t mem_config[(size_t)la_mem_protect_error_e::LAST + 1];
        uint32_t mem_volatile[(size_t)la_mem_protect_error_e::LAST + 1];
        uint32_t lpm_sram_ecc[(size_t)la_mem_protect_error_e::LAST + 1];
    };
    void set_thresholds(const thresholds& val);

    void get_threshold_and_action(const bit_scptr& bit, la_notification_action_e& action_out, uint32_t& threshold_out);
    void get_threshold_and_action(const mem_protect_error& mem_error,
                                  la_notification_action_e& action_out,
                                  uint32_t& threshold_out);
    void get_threshold_and_action(const bit_scptr& bit,
                                  const lpm_sram_mem_protect& mem_error,
                                  la_notification_action_e& action_out,
                                  uint32_t& threshold_out);

    la_status save_state(json_t* out_root) const;
    la_status save_state(std::string file_name) const;

    void reset_interrupt_counters();

    // Convenience API - doesn't take interrupt_tree::node/bit arguments.
    la_status clear_interrupt(lld_register_scptr reg, const bit_vector& bits);
    la_status clear_interrupt(lld_register_scptr reg, size_t bit_i);
    la_status clear_interrupt(lld_memory_scptr reg);

    // Delegates from la_device API calls
    la_status set_interrupt_enabled(lld_register_scptr reg, const bit_vector& bits, bool enabled, bool clear);
    la_status set_interrupt_enabled(lld_register_scptr reg, size_t bit_i, bool enabled, bool clear);
    la_status get_interrupt_enabled(lld_register_scptr reg, size_t bit_i, bool& out_enabled);
    la_status set_interrupt_enabled(lld_memory_scptr mem, bool enabled, bool clear);
    la_status get_interrupt_enabled(lld_memory_scptr mem, bool& out_enabled);

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    interrupt_tree() = default;

    // Helper for traverse()
    void do_traverse(const node_scptr& node, size_t depth, node_cb node_cb, bit_cb bit_cb) const;

    // Recursively clear summary bits, ascend the tree from leaf to root
    void clear_summary_bit(const bit_scptr& bit) const;

    // Clear one or more bits in interrupt status register
    void write_interrupt_register(lld_register_scptr reg, const bit_vector& val) const;

    // Get pending and unmasked interrupt bits
    bit_vector get_pending_interrupt_bits(const node_scptr& node) const;

    // Save current masks values, disable masks, return saved masks values
    std::vector<bit_vector> save_and_disable_mem_protect_masks(const node_scptr& node) const;

    // Restore masks
    void restore_mem_protect_masks(const node_scptr& node, const std::vector<bit_vector>& save) const;

    // Read mem_protect error from a specific memory and append to 'errors'
    void read_mem_protect_error(const node_scptr& node, size_t memory_index, mem_protect_errors& errors) const;

    // Clear mem-protect errors and interrupts for this node
    void clear_mem_protect_errors_and_interrupts(const node_scptr& node);

    // Root of the tree of all nodes that are wired to MSI, most of interrupt registers are here
    node_sptr m_msi_root;

    // Individual interrupt registers (each has its own subtree) that are not wired to MSI
    std::vector<node_sptr> m_non_wired_roots;

    std::map<uint64_t /* absolute address of node::status register */, node_scptr> m_map_address_to_node;
    ll_device_wptr m_ll_device;

    struct dampen_mask_register_info {
        bool is_mask_active_low;

        // initial value of mask register
        bit_vector initial_value;

        // time_points for bits that are masked off through dampen_interrupt_mask() call.
        // Initially set to min().
        std::vector<interrupt_tree::time_point> time_points;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(dampen_mask_register_info)
    std::map<lld_register_scptr, dampen_mask_register_info> m_dampened;

    // Count per bit
    mutable std::map<bit_scptr, uint64_t /* count */> m_count_bits;

    // Count per memory entry
    struct mem_protect_error_less {
        bool operator()(const mem_protect_error& lhs, const mem_protect_error& rhs) const
        {
            return std::tie(lhs.mem, lhs.error, lhs.entry) < std::tie(rhs.mem, rhs.error, rhs.entry);
        }
    };
    mutable std::map<mem_protect_error, uint64_t /* count */, mem_protect_error_less> m_count_mem_errors;

    thresholds m_thresholds;

    la_block_id_t m_sbif_block_id;

    void dampen_interrupt_mask(lld_register_scptr mask_reg, size_t bit_i, bool is_mask_active_low);

    void increment_interrupt_count(const bit_scptr& bit) const;
    void increment_interrupt_count(const mem_protect_error& mem_error) const;
    uint64_t get_interrupt_count(const bit_scptr& bit);
    uint64_t get_interrupt_count(const mem_protect_error& mem_error);

    la_status get_memory_index_in_mask(const node_scptr& node, lld_memory_scptr mem, size_t& out_bit_i);
    la_status get_interrupt_mask_register(lld_register_scptr reg, lld_register_scptr& out_mask_reg);
    la_status do_set_interrupt_enabled(lld_register_scptr reg,
                                       lld_register_scptr mask_reg,
                                       const bit_vector& bits,
                                       bool enabled,
                                       bool clear);
    la_status get_or_set_interrupt_enabled(lld_memory_scptr mem, bool is_get, bool clear_on_set, bool& in_out_enabled);

    cause_bits do_collect_interrupts(const node_scptr& root) const;
};

} // namespace silicon_one
#endif
