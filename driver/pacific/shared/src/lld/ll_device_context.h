// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LLD_LL_DEVICE_CONTEXT_H__
#define __LEABA_LLD_LL_DEVICE_CONTEXT_H__

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"

#include "lld/lld_fwd.h"

#include "lld_types_internal.h"

#include <map>

namespace silicon_one
{
/// @brief Low level device context
class ll_device_context
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // TOP regfile is accessed indirectly through three SBIF registers:
    //  sbif.top_regfile_cfg_reg
    //  sbif.top_regfile_cfg_wdata_reg.
    //  sbif.top_regfile_cfg_read_reg.
    //
    // These registers have identical bit fields on Gibraltar and Asic4, but are located at different addresses.
    // TODO: If more ASICs are added - check that bit fields are still the same.
    struct sbif_top_addr_tupple {
        la_entry_addr_t cfg;
        la_entry_addr_t wdata;
        la_entry_addr_t rdata;
    };

    static std::map<la_device_family_e, sbif_top_addr_tupple> s_sbif_top_addr;

    static std::map<std::string, la_device_revision_e> s_envvar_asic_name_to_revision;
    static std::map<uint64_t, la_device_family_e> s_pci_device_id_to_family;
    static la_entry_addr_t get_chip_id_addr(la_device_family_e family);
    static la_device_revision_e translate_id_to_revision(la_device_family_e family, uint32_t id_val);
    static la_device_revision_e translate_family_to_revision(la_device_family_e family);
    /// @brief C'tor, the actual initialization in init().
    explicit ll_device_context(la_device_id_t device_id);

    /// @brief Default c'tor - allowed only for serialization purposes.
    ll_device_context() = default;

    /// @brief Copy c'tor - disallowed.
    ll_device_context(const ll_device_context&) = delete;

    /// @brief Destruct leaba module device.
    ~ll_device_context();

    /// @brief Initialize Leaba ll_device_context to a given device path, and use the device_tree as a reference to the reg/mem
    /// tree.
    void initialize(la_device_revision_e revision);

    pacific_tree_scptr get_pacific_tree_scptr() const;
    gibraltar_tree_scptr get_gibraltar_tree_scptr() const;
    asic4_tree_scptr get_asic4_tree_scptr() const;
    asic3_tree_scptr get_asic3_tree_scptr() const;
    asic5_tree_scptr get_asic5_tree_scptr() const;
    lld_block_scptr get_device_tree() const;
    la_device_family_e get_device_family() const;
    lld_block_scptr get_block(la_block_id_t block_id);

    bool is_asic5() const;
    bool is_asic4() const;
    bool is_asic3() const;
    bool is_asic7() const;
    bool is_gibraltar() const;
    bool is_pacific() const;

    la_uint_t get_num_of_css_arcs() const;
    void get_arc_cpu_info(size_t arc_id, arc_cpu_info& out_arc_info) const;

    uint16_t get_access_engine_count() const;

    uint32_t get_ae_reset_bits(uint32_t select_access_engines) const;

    void get_access_engine_info(size_t ae_id, access_engine_info& out_ae_info) const;

    // The code block below replaces future interface of polling on access engine.
    // Once LLD interface will be ready, this block should be removed
    void get_simulation_poll_address_list(std::vector<size_t>& out_addresses) const;

    size_t get_simulation_poll_idb_done_addr() const;

    la_block_id_t m_sbif_block_id;              // SBIF block id
    la_block_id_t m_top_regfile_block_id;       // Gibraltar top regfile
    la_device_id_t m_device_id;                 // device id this lld is attached to
    la_entry_addr_t m_sbif_reset_register_addr; // LLD_REGISTER_SBIF_RESET_REG
    lld_register_scptr m_sbif_reset_reg;
    lld_memory_scptr m_sbif_css_memory;
    la_entry_addr_t m_ae_reset_addr;
    la_entry_addr_t m_access_engine_global_cfg_addr;
    la_entry_addr_t m_access_engine_cmd_mem_override_fifo_addr;

private:
    template <class _lbr_tree>
    void initialize_helper(const _lbr_tree* lbr_tree);

    template <class _lbr_tree>
    void get_arc_cpu_info_helper(const _lbr_tree* lbr_tree, size_t arc_id, arc_cpu_info& out_arc_info) const;

    template <class _lbr_tree>
    uint16_t get_access_engine_count_helper(const _lbr_tree* lbr_tree) const;

    template <class _lbr_tree>
    void get_access_engine_info_helper(const _lbr_tree* lbr_tree, size_t ae_id, access_engine_info& out_ae_info) const;

    void get_access_engine_info_helper_asic7(const asic3_tree* lbr_tree, access_engine_info& out_ae_info) const;

    size_t m_interrupt_width_bytes; // Width of value to read from interrupt file descriptor
    la_device_revision_e m_device_revision;

    std::shared_ptr<pacific_tree> m_pacific_tree;     // Pacific tree of logical blocks with registers and memories
    std::shared_ptr<gibraltar_tree> m_gibraltar_tree; // GB tree of logical blocks with registers and memories
};
}

#endif // __LEABA_LLD_LL_DEVICE_CONTEXT_H__
