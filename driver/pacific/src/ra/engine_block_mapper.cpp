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

#include "engine_block_mapper.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

engine_block_mapper::engine_block_mapper(pacific_tree_scptr ptree) : m_pacific_tree(ptree)
{
}

bool
engine_block_mapper::is_internal(database_block_e engine) const
{
    return engine > DATABASE_BLOCK_LAST_INTERNAL;
}

size_t
engine_block_mapper::get_num_block_instances(database_block_e engine) const
{
    static const size_t num_block_instances[DATABASE_BLOCK_NUM] = {
            [DATABASE_BLOCK_UNKNOWN] = 1,

            [DATABASE_BLOCK_INTERNAL_RXPP_FWD] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_INTERNAL_RXPP_TERM] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_INTERNAL_TXPP] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_INTERNAL_NPUH] = 1,

            [DATABASE_BLOCK_EXTERNAL_CDB_TOP] = 1,
            [DATABASE_BLOCK_EXTERNAL_CDB_CORE] = 1,
            [DATABASE_BLOCK_EXTERNAL_CDB_CORE_REDUCED] = 1,
            [DATABASE_BLOCK_EXTERNAL_IDB_TOP] = NUM_SLICE_PAIRS_PER_DEVICE,
            [DATABASE_BLOCK_EXTERNAL_IDB_RES] = NUM_SLICE_PAIRS_PER_DEVICE,
            [DATABASE_BLOCK_EXTERNAL_SDB_MAC] = 1,
            [DATABASE_BLOCK_EXTERNAL_SDB_ENC] = 1,
            [DATABASE_BLOCK_EXTERNAL_RXPP_FWD] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_TERM] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_ENG] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_FI_STAGE] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_TXPP] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_CLUSTER] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_NPUH_HOST] = 1,
            [DATABASE_BLOCK_EXTERNAL_NPUH_FI_ENG] = 1,
            [DATABASE_BLOCK_EXTERNAL_PDVOQ_SLICE] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_HMC_CGM] = 1,
            [DATABASE_BLOCK_EXTERNAL_RX_PDR_2_SLICES] = NUM_SLICE_PAIRS_PER_DEVICE,
            [DATABASE_BLOCK_EXTERNAL_PDOQ] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_FILB_SLICE] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RX_PDR_SHARED_DB] = 2,
            [DATABASE_BLOCK_EXTERNAL_COUNTERS] = 1,
            [DATABASE_BLOCK_EXTERNAL_COUNTERS_BANK_GROUP] = 36,
            [DATABASE_BLOCK_EXTERNAL_RX_COUNTERS] = 1,
            [DATABASE_BLOCK_EXTERNAL_TXPDR] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RX_METER] = 1,
            [DATABASE_BLOCK_EXTERNAL_RX_METER_BLOCK] = 4,
            [DATABASE_BLOCK_EXTERNAL_REASSEMBLY] = 1,
            [DATABASE_BLOCK_EXTERNAL_FRM] = 1,
    };

    return num_block_instances[engine];
}

bool
engine_block_mapper::get_blocks(database_block_e block,
                                la_slice_id_t block_idx,
                                size_t inst_idx,
                                engine_block_mapper::lld_block_vec_t& ret) const
{
    static const size_t counter_bank_4k_num = 32;
    // In Pacific, 4 slices are full network slices, and 2 are reduced (fabric)
    static const size_t network_slice_num = 4;

    size_t num_blocks = get_num_block_instances(block);
    if ((num_blocks != 1) && block_idx >= num_blocks) {
        return false;
    }

    switch (block) {
    // Internal engines, per slice
    case DATABASE_BLOCK_INTERNAL_RXPP_FWD:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_fwd->npe[0]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_fwd->npe[1]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_fwd->npe[2]);
        return true;

    case DATABASE_BLOCK_INTERNAL_RXPP_TERM:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->npe[0]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->npe[1]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->npe[2]);
        return true;

    case DATABASE_BLOCK_INTERNAL_TXPP:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->txpp->npe[0]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->txpp->npe[1]);
        return true;

    // External engines, per slice
    case DATABASE_BLOCK_EXTERNAL_RXPP_FWD:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_fwd->rxpp_fwd);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_TERM:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->rxpp_term);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_ENG:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[0]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[1]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[2]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[3]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[4]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[5]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[6]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_eng[7]);
        return true;

    case DATABASE_BLOCK_EXTERNAL_FI_STAGE:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->rxpp_term->fi_stage);
        return true;

    case DATABASE_BLOCK_EXTERNAL_TXPP:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->txpp->txpp);
        return true;

    case DATABASE_BLOCK_EXTERNAL_CLUSTER:
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->txpp->cluster[0]);
        ret.push_back(m_pacific_tree->slice[block_idx]->npu->txpp->cluster[1]);
        return true;

    // External engines, per slice-pair
    case DATABASE_BLOCK_EXTERNAL_IDB_TOP:
        ret.push_back(m_pacific_tree->slice_pair[block_idx]->idb->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_IDB_RES:
        ret.push_back(m_pacific_tree->slice_pair[block_idx]->idb->res);
        return true;

    // Internal engines, per device
    case DATABASE_BLOCK_INTERNAL_NPUH:
        ret.push_back(m_pacific_tree->npuh->npe);
        return true;

    // External engines, per device
    case DATABASE_BLOCK_EXTERNAL_CDB_TOP:
        ret.push_back(m_pacific_tree->cdb->top);
        return true;

    // External engines, per device
    case DATABASE_BLOCK_EXTERNAL_CDB_CORE:
        ret.push_back(m_pacific_tree->cdb->core[0]);
        ret.push_back(m_pacific_tree->cdb->core[1]);
        ret.push_back(m_pacific_tree->cdb->core[2]);
        ret.push_back(m_pacific_tree->cdb->core[3]);
        return true;

    // External engines, per device
    case DATABASE_BLOCK_EXTERNAL_CDB_CORE_REDUCED:
        ret.push_back(m_pacific_tree->cdb->core_reduced[0]);
        ret.push_back(m_pacific_tree->cdb->core_reduced[1]);
        ret.push_back(m_pacific_tree->cdb->core_reduced[2]);
        ret.push_back(m_pacific_tree->cdb->core_reduced[3]);
        return true;

    case DATABASE_BLOCK_EXTERNAL_SDB_MAC:
        ret.push_back(m_pacific_tree->sdb->mac);
        return true;

    case DATABASE_BLOCK_EXTERNAL_SDB_ENC:
        ret.push_back(m_pacific_tree->sdb->enc);
        return true;

    case DATABASE_BLOCK_EXTERNAL_NPUH_HOST:
        ret.push_back(m_pacific_tree->npuh->host);
        return true;

    case DATABASE_BLOCK_EXTERNAL_NPUH_FI_ENG:
        ret.push_back(m_pacific_tree->npuh->fi);
        return true;

    case DATABASE_BLOCK_EXTERNAL_HMC_CGM:
        ret.push_back(m_pacific_tree->hmc_cgm);
        return true;

    case DATABASE_BLOCK_EXTERNAL_PDVOQ_SLICE:
        // This block is special: slices 0-3 have regular implementation and slices 4-5 special implementation
        if (block_idx < network_slice_num) {
            ret.push_back(m_pacific_tree->slice[block_idx]->pdvoq);
        } else {
            ret.push_back(m_pacific_tree->slice[block_idx]->fabric_pdvoq);
        }
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_PDR_2_SLICES:
        ret.push_back(m_pacific_tree->slice_pair[block_idx]->rx_pdr);
        return true;

    case DATABASE_BLOCK_EXTERNAL_PDOQ:
        ret.push_back(m_pacific_tree->slice[block_idx]->pdoq->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_FILB_SLICE:
        // This block is special: slices 0-3 have regular implementation and slices 4-5 special implementation
        if (block_idx < network_slice_num) {
            ret.push_back(m_pacific_tree->slice[block_idx]->filb);
        } else {
            ret.push_back(m_pacific_tree->slice[block_idx]->fabric_filb);
        }
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_PDR_SHARED_DB:
        // Returns both tables
        ret.push_back(m_pacific_tree->rx_pdr_mc_db[0]);
        ret.push_back(m_pacific_tree->rx_pdr_mc_db[1]);
        return true;

    case DATABASE_BLOCK_EXTERNAL_COUNTERS:
        ret.push_back(m_pacific_tree->counters->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_COUNTERS_BANK_GROUP:
        // this is multi-instance block
        if (inst_idx < counter_bank_4k_num) {
            ret.push_back(m_pacific_tree->counters->bank_4k[inst_idx]);
        } else {
            ret.push_back(m_pacific_tree->counters->bank_6k[inst_idx - counter_bank_4k_num]);
        }
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_COUNTERS:
        ret.push_back(m_pacific_tree->rx_counters);
        return true;

    case DATABASE_BLOCK_EXTERNAL_TXPDR:
        ret.push_back(m_pacific_tree->slice[block_idx]->tx->pdr);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_METER:
        ret.push_back(m_pacific_tree->rx_meter->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_METER_BLOCK:
        // this is multi-instance block
        ret.push_back(m_pacific_tree->rx_meter->block[inst_idx]);
        return true;

    case DATABASE_BLOCK_EXTERNAL_REASSEMBLY:
        // this is multi-instance block
        ret.push_back(m_pacific_tree->reassembly);
        return true;

    case DATABASE_BLOCK_EXTERNAL_FRM:
        ret.push_back(m_pacific_tree->dmc->frm);
        return true;

    default:
        return false;
    }

    return false;
}

std::vector<lld_memory_scptr>
engine_block_mapper::get_ctm_tcam(size_t cdb_core, size_t subring_idx, size_t idx) const
{
    dassert_crit(subring_idx == 0);
    std::vector<lld_memory_scptr> ret;

    bool is_reduced = cdb_core % 2 == 0;
    size_t core_idx = cdb_core / 2;

    lld_memory_array_sptr lpm_tcams = m_pacific_tree->cdb->core[core_idx]->lpm_tcam;
    lld_memory_array_sptr acl_tcams = m_pacific_tree->cdb->core[core_idx]->acl_tcam;
    if (is_reduced) {
        lpm_tcams = m_pacific_tree->cdb->core_reduced[core_idx]->lpm_tcam;
        acl_tcams = m_pacific_tree->cdb->core_reduced[core_idx]->acl_tcam;
    }

    // Each ring is constructed from 2 LPM tcams (1024 lines each)
    size_t lpm_tcam_rings = lpm_tcams->size() / 2;
    if (idx < lpm_tcam_rings) {
        ret.push_back((*lpm_tcams)[idx * 2]);
        ret.push_back((*lpm_tcams)[idx * 2 + 1]);
    } else {
        ret.push_back((*acl_tcams)[idx - lpm_tcam_rings]);
    }

    return ret;
}

std::vector<lld_memory_scptr>
engine_block_mapper::get_ctm_sram(size_t cdb_core, size_t subring_idx, size_t idx) const
{
    dassert_crit(subring_idx == 0);
    std::vector<lld_memory_scptr> ret;

    bool is_reduced = cdb_core % 2 == 0;
    size_t core_idx = cdb_core / 2;

    if (is_reduced) {
        ret.push_back((*m_pacific_tree->cdb->core_reduced[core_idx]->associated_data_mem)[idx]);
    } else {
        ret.push_back((*m_pacific_tree->cdb->core[core_idx]->associated_data_mem)[idx]);
    }

    return ret;
}

size_t
engine_block_mapper::get_memory_array_size(size_t mem_id) const
{
    switch (mem_id) {
    case pacific_tree::LLD_MEMORY_ENE_CLUSTER_ENE_MACRO_MEMORY:
        // take the data from a representative
        return m_pacific_tree->slice[0]->npu->txpp->cluster[0]->ene_macro_memory->size();
    case pacific_tree::LLD_MEMORY_TXPP_LIGHT_FI_NPU_ENCAP_LOOKUP:
        // take the data from a representative
        return m_pacific_tree->slice[0]->npu->txpp->txpp->light_fi_npu_encap_lookup->size();
    default:
        // Never gets here.
        dassert_crit(false);
    }

    return 0;
}

size_t
engine_block_mapper::get_register_array_size(size_t reg_id) const
{
    // There should be no calls for this procedure.
    dassert_crit(false);

    return 0;
}

} // namespace silicon_one
