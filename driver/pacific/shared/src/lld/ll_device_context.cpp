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

#include "ll_device_context.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/leaba_kernel_types.h"

using namespace std;
using namespace silicon_one;

map<la_device_family_e, ll_device_context::sbif_top_addr_tupple> ll_device_context::s_sbif_top_addr = {
    {
        la_device_family_e::GIBRALTAR,
        {
            .cfg = gibraltar_tree::get_register_desc(gibraltar_tree::LLD_REGISTER_SBIF_TOP_REGFILE_CFG_REG).addr,
            .wdata = gibraltar_tree::get_register_desc(gibraltar_tree::LLD_REGISTER_SBIF_TOP_REGFILE_CFG_WDATA_REG).addr,
            .rdata = gibraltar_tree::get_register_desc(gibraltar_tree::LLD_REGISTER_SBIF_TOP_REGFILE_CFG_READ_REG).addr,
        },
    },
};

map<string, la_device_revision_e> ll_device_context::s_envvar_asic_name_to_revision
    = {{"GIBRALTAR_A0", la_device_revision_e::GIBRALTAR_A0},
       {"GIBRALTAR_A1", la_device_revision_e::GIBRALTAR_A1},
       {"GIBRALTAR_A2", la_device_revision_e::GIBRALTAR_A2},
       {"PACIFIC_A0", la_device_revision_e::PACIFIC_A0},
       {"PACIFIC_B0", la_device_revision_e::PACIFIC_B0},
       {"PACIFIC_B1", la_device_revision_e::PACIFIC_B1}};

map<uint64_t, la_device_family_e> ll_device_context::s_pci_device_id_to_family = {
    {LEABA_PACIFIC_DEVICE_ID, la_device_family_e::PACIFIC},
    {LEABA_GIBRALTAR_DEVICE_ID, la_device_family_e::GIBRALTAR},
};

//------------------------------------------------------------------------------
// Internal helper functions
//------------------------------------------------------------------------------
ll_device_context::ll_device_context(la_device_id_t device_id)
    : m_sbif_block_id(LA_BLOCK_ID_INVALID),
      m_top_regfile_block_id(LA_BLOCK_ID_INVALID),
      m_device_id(device_id),
      m_interrupt_width_bytes(0),
      m_device_revision(la_device_revision_e::NONE)
{
}

la_entry_addr_t
ll_device_context::get_chip_id_addr(la_device_family_e family)
{
    // m_device_tree is not created yet, use reg descriptor directly
    la_entry_addr_t chip_id_addr = 0;
    if (family == la_device_family_e::GIBRALTAR) {
        chip_id_addr = gibraltar_tree::get_register_desc(gibraltar_tree::LLD_REGISTER_TOP_CHIP_ID_REG).addr;
    } else {
        dassert_crit(false, "unexpected device family");
    }

    return chip_id_addr;
}

la_device_revision_e
ll_device_context::translate_id_to_revision(la_device_family_e family, uint32_t id_val)
{
    gibraltar::top_chip_id_reg_register val{{0}};
    union tmp_union {
        uint32_t u32;
        uint8_t u8[4];
    } tmp_val;

    tmp_val.u32 = id_val;
    for (int i = 0; i < 4; i++) {
        val.u8[i] = tmp_val.u8[i];
    }

    if (family == la_device_family_e::GIBRALTAR) {
        if (val.fields.version_code == 0 || val.fields.version_code == 1) {
            return la_device_revision_e::GIBRALTAR_A0;
        }
        if (val.fields.version_code == 2) {
            return la_device_revision_e::GIBRALTAR_A1;
        }
        if (val.fields.version_code == 3) {
            return la_device_revision_e::GIBRALTAR_A2;
        }
    }

    return la_device_revision_e::NONE;
}

la_device_revision_e
ll_device_context::translate_family_to_revision(la_device_family_e family)
{
    return la_device_revision_e::NONE;
}

void
ll_device_context::initialize(la_device_revision_e revision)
{
    m_device_revision = revision;
    log_debug(LLD, "%s: device revision=%d", __func__, (int)m_device_revision);

    // If the discovered device is PACIFIC, take the revision as is.
    // If we discover GB or Asic4, we still want a pacific tree, with revision PACIFIC_B0.
    la_device_revision_e pacific_revision
        = (m_device_revision <= la_device_revision_e::PACIFIC_B1 ? m_device_revision : la_device_revision_e::PACIFIC_B0);

    if (is_gibraltar()) {
        m_gibraltar_tree = gibraltar_tree::create(m_device_revision);
        m_top_regfile_block_id = m_gibraltar_tree->top_regfile->get_block_id();
        m_sbif_css_memory = m_gibraltar_tree->sbif->css_mem_even;
        m_ae_reset_addr = m_gibraltar_tree->sbif->reset_reg->get_desc()->addr;
        m_access_engine_global_cfg_addr = m_gibraltar_tree->sbif->acc_eng_global_cfg_reg->get_desc()->addr;
        m_access_engine_cmd_mem_override_fifo_addr
            = m_gibraltar_tree->sbif->acc_eng_command_mem_fifo_override_reg->get_desc()->addr;

        initialize_helper(m_gibraltar_tree.get());
    } else {
        m_pacific_tree = pacific_tree::create(pacific_revision);
        m_top_regfile_block_id = LA_BLOCK_ID_INVALID;
        m_sbif_css_memory = m_pacific_tree->sbif->css_mem_even;
        m_ae_reset_addr = m_pacific_tree->sbif->acc_eng_reset_reg->get_desc()->addr;
        m_access_engine_global_cfg_addr = m_pacific_tree->sbif->sbif_global_config_reg->get_desc()->addr;
        m_access_engine_cmd_mem_override_fifo_addr = m_pacific_tree->sbif->command_mem_fifo_override_reg->get_desc()->addr;
        initialize_helper(m_pacific_tree.get());
    }
}

template <class _lbr_tree>
void
ll_device_context::initialize_helper(const _lbr_tree* lbr_tree)
{
    m_sbif_block_id = lbr_tree->sbif->get_block_id();
    // m_top_regfile_block_id = lbr_tree->top_regfile->get_block_id();
    m_sbif_reset_register_addr = lbr_tree->sbif->reset_reg->get_desc()->addr;
    m_sbif_reset_reg = lbr_tree->sbif->reset_reg;
}

ll_device_context::~ll_device_context()
{
}

bool
ll_device_context::is_asic5() const
{
    return false;
}

bool
ll_device_context::is_asic4() const
{
    return false;
}

bool
ll_device_context::is_asic3() const
{
    return false;
}

bool
ll_device_context::is_asic7() const
{
    return false;
}

bool
ll_device_context::is_gibraltar() const
{
    return (m_device_revision >= la_device_revision_e::GIBRALTAR_A0 && m_device_revision <= la_device_revision_e::GIBRALTAR_A2);
}

bool
ll_device_context::is_pacific() const
{
    return (m_device_revision >= la_device_revision_e::PACIFIC_A0 && m_device_revision <= la_device_revision_e::PACIFIC_B1);
}

pacific_tree_scptr
ll_device_context::get_pacific_tree_scptr() const
{
    return m_pacific_tree;
}

gibraltar_tree_scptr
ll_device_context::get_gibraltar_tree_scptr() const
{
    return m_gibraltar_tree;
}

asic4_tree_scptr
ll_device_context::get_asic4_tree_scptr() const
{
    return nullptr;
}

asic3_tree_scptr
ll_device_context::get_asic3_tree_scptr() const
{
    return nullptr;
}

asic5_tree_scptr
ll_device_context::get_asic5_tree_scptr() const
{
    return nullptr;
}

lld_block_scptr
ll_device_context::get_device_tree() const
{
    if (is_gibraltar()) {
        return m_gibraltar_tree;
    }
    if (is_pacific()) {
        return m_pacific_tree;
    }

    dassert_crit(false, "unexpected device family");
    return nullptr;
}

la_device_family_e
ll_device_context::get_device_family() const
{
    if (is_gibraltar()) {
        return la_device_family_e::GIBRALTAR;
    }
    if (is_pacific()) {
        return la_device_family_e::PACIFIC;
    }

    dassert_crit(false, "unexpected device family");
    return la_device_family_e::NONE;
}

lld_block_scptr
ll_device_context::get_block(la_block_id_t block_id)
{
    if (is_gibraltar()) {
        return m_gibraltar_tree->get_block(block_id);
    }

    return m_pacific_tree->get_block(block_id);
}

la_uint_t
ll_device_context::get_num_of_css_arcs() const
{
    la_uint_t num = 0;

    if (is_gibraltar()) {
        num = m_gibraltar_tree->sbif->arc_run_halt_reg->get_desc()->instances;
    } else {
        num = m_pacific_tree->sbif->arc_run_halt_reg->get_desc()->instances;
    }
    return num;
}

void
ll_device_context::get_arc_cpu_info(size_t arc_id, arc_cpu_info& out_ae_info) const
{
    if (is_gibraltar()) {
        get_arc_cpu_info_helper(m_gibraltar_tree.get(), arc_id, out_ae_info);
    } else {
        get_arc_cpu_info_helper(m_pacific_tree.get(), arc_id, out_ae_info);
    }
}

template <class _lbr_tree>
void
ll_device_context::get_arc_cpu_info_helper(const _lbr_tree* lbr_tree, size_t arc_id, arc_cpu_info& out_ae_info) const
{
    out_ae_info.arc_run_halt_reg = (*lbr_tree->sbif->arc_run_halt_reg)[arc_id]->get_desc()->addr;
    out_ae_info.arc_status_reg = (*lbr_tree->sbif->arc_status_reg)[arc_id]->get_desc()->addr;
    out_ae_info.reset_reg = lbr_tree->sbif->reset_reg->get_desc()->addr;
}

uint16_t
ll_device_context::get_access_engine_count() const
{
    if (is_gibraltar()) {
        return get_access_engine_count_helper(m_gibraltar_tree.get());
    } else {
        return get_access_engine_count_helper(m_pacific_tree.get());
    }
}

template <class _lbr_tree>
uint16_t
ll_device_context::get_access_engine_count_helper(const _lbr_tree* lbr_tree) const
{
    return lbr_tree->sbif->acc_eng_go_reg->get_desc()->instances;
}

void
ll_device_context::get_access_engine_info(size_t ae_id, access_engine_info& out_ae_info) const
{
    if (is_gibraltar()) {
        get_access_engine_info_helper(m_gibraltar_tree.get(), ae_id, out_ae_info);
    } else {
        get_access_engine_info_helper(m_pacific_tree.get(), ae_id, out_ae_info);
    }
}

template <class _lbr_tree>
void
ll_device_context::get_access_engine_info_helper(const _lbr_tree* lbr_tree, size_t ae_id, access_engine_info& out_ae_info) const
{
    out_ae_info.cmd_mem_addr = (*lbr_tree->sbif->access_engine_command_mem)[ae_id]->get_desc()->addr;
    out_ae_info.data_mem_addr = (*lbr_tree->sbif->access_engine_data_mem)[ae_id]->get_desc()->addr;
    out_ae_info.go_reg_addr = (*lbr_tree->sbif->acc_eng_go_reg)[ae_id]->get_desc()->addr;
    out_ae_info.cmd_ptr_reg_addr = (*lbr_tree->sbif->acc_eng_cmd_ptr_reg)[ae_id]->get_desc()->addr;
    out_ae_info.status_reg_addr = (*lbr_tree->sbif->acc_eng_status_reg)[ae_id]->get_desc()->addr;
    // The usable portion of AE data memory is the minimum between the size of DMA buffer the size of AE data memory.
    out_ae_info.data_mem_entries = (*lbr_tree->sbif->access_engine_data_mem)[ae_id]->get_desc()->entries;
    out_ae_info.data_width = (*lbr_tree->sbif->access_engine_data_mem)[ae_id]->get_desc()->width_total;

    out_ae_info.cmd_entries = lbr_tree->sbif->access_engine_command_mem->get_desc()->entries;
}

void
ll_device_context::get_access_engine_info_helper_asic7(const asic3_tree* lbr_tree, access_engine_info& out_ae_info) const
{
}

uint32_t
ll_device_context::get_ae_reset_bits(uint32_t select_access_engines) const
{
    if (is_gibraltar()) {
        return select_access_engines << 18;
    } else { // pacific
        return select_access_engines;
    }
}

void
ll_device_context::get_simulation_poll_address_list(std::vector<size_t>& out_addresses) const
{
    la_slice_id_t rep_sid = 0; // TODO get the first active slice's id from the slice id manager
    if (is_gibraltar()) {
        out_addresses.push_back(
            m_gibraltar_tree->slice_pair[rep_sid]->idb->macdb->init_done_status_register->get_absolute_address());
        out_addresses.push_back(
            m_gibraltar_tree->slice_pair[rep_sid]->idb->encdb->init_done_status_register->get_absolute_address());
        out_addresses.push_back(m_gibraltar_tree->rx_pdr->status_register->get_absolute_address());
        out_addresses.push_back(m_gibraltar_tree->slice_pair[rep_sid]->rx_pdr->status_register->get_absolute_address());
    } else { // Pacific
        out_addresses.push_back(m_pacific_tree->rx_pdr->status_register->get_absolute_address());
        out_addresses.push_back(m_pacific_tree->slice_pair[rep_sid]->rx_pdr->status_register->get_absolute_address());
    }
}

size_t
ll_device_context::get_simulation_poll_idb_done_addr() const
{
    la_slice_id_t rep_sid = 0; // TODO get the first active slice's id from the slice id manager
    if (!is_pacific()) {
        return 0;
    }
    size_t native_l2_and_l3_num_entries
        = m_pacific_tree->slice_pair[rep_sid]->idb->res->native_l2_and_l3_lp_table->get_desc()->entries;
    size_t addr = m_pacific_tree->slice_pair[rep_sid]->idb->res->native_l2_and_l3_lp_table->get_absolute_address()
                  + native_l2_and_l3_num_entries - 1;

    return addr;
}
