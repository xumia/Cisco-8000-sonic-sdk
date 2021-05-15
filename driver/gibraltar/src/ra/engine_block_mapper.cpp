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
#include "common/logger.h"
#include "ctm/ctm_common.h"
#include "lld/gibraltar_tree.h"

namespace silicon_one
{

engine_block_mapper::engine_block_mapper(gibraltar_tree_scptr ptree) : m_gibraltar_tree(ptree)
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
            [DATABASE_BLOCK_EXTERNAL_IDB_RES] = NUM_SLICE_PAIRS_PER_DEVICE,
            [DATABASE_BLOCK_EXTERNAL_IDB_MACDB] = NUM_SLICE_PAIRS_PER_DEVICE,
            [DATABASE_BLOCK_EXTERNAL_IDB_ENCDB] = NUM_SLICE_PAIRS_PER_DEVICE,
            [DATABASE_BLOCK_EXTERNAL_RXPP_FWD] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_FWD_FLC_QUEUES] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_FWD_CDB_CACHE] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_TERM] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_ENG] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_STAGE] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_TERM_SNA] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FLC_DB] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_TXPP] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_ENE_CLUSTER] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_NPUH_HOST] = 1,
            [DATABASE_BLOCK_EXTERNAL_NPUH_FI_ENG] = 1,
            [DATABASE_BLOCK_EXTERNAL_PDVOQ_SLICE] = ASIC_MAX_SLICES_PER_DEVICE_NUM,
            [DATABASE_BLOCK_EXTERNAL_DRAM_CGM] = 1,
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
    static const size_t counter_bank_8k_num = 32;

    size_t num_blocks = get_num_block_instances(block);
    if ((num_blocks != 1) && block_idx >= num_blocks) {
        return false;
    }

    switch (block) {
    // Internal engines, per slice
    case DATABASE_BLOCK_INTERNAL_RXPP_FWD:
        for (auto& rxpp_fwd_npe : m_gibraltar_tree->slice[block_idx]->npu->rxpp_fwd->npe) {
            ret.push_back(rxpp_fwd_npe);
        }
        return true;

    case DATABASE_BLOCK_INTERNAL_RXPP_TERM:
        for (auto& rxpp_term_npe : m_gibraltar_tree->slice[block_idx]->npu->rxpp_term->npe) {
            ret.push_back(rxpp_term_npe);
        }
        return true;

    case DATABASE_BLOCK_INTERNAL_TXPP:
        for (auto& txpp_npe : m_gibraltar_tree->slice[block_idx]->npu->txpp->npe) {
            ret.push_back(txpp_npe);
        }
        return true;

    // External engines, per slice
    case DATABASE_BLOCK_EXTERNAL_RXPP_FWD:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->rxpp_fwd->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_FWD_FLC_QUEUES:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->rxpp_fwd->flc_queues);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_FWD_CDB_CACHE:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->rxpp_fwd->cdb_cache);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_TERM:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->rxpp_term->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_ENG:
        for (auto& fi_eng : m_gibraltar_tree->slice[block_idx]->npu->rxpp_term->fi_eng) {
            ret.push_back(fi_eng);
        }
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FI_STAGE:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->rxpp_term->fi_stage);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_TERM_SNA:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->rxpp_term->sna);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RXPP_TERM_FLC_DB:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->rxpp_term->flc_db);
        return true;

    case DATABASE_BLOCK_EXTERNAL_TXPP:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->npu->txpp->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_ENE_CLUSTER:
        for (auto& ene_cluster : m_gibraltar_tree->slice[block_idx]->npu->txpp->ene_cluster) {
            ret.push_back(ene_cluster);
        }
        return true;

    // External engines, per slice-pair
    case DATABASE_BLOCK_EXTERNAL_IDB_RES:
        ret.push_back(m_gibraltar_tree->slice_pair[block_idx]->idb->res);
        return true;

    case DATABASE_BLOCK_EXTERNAL_IDB_MACDB:
        ret.push_back(m_gibraltar_tree->slice_pair[block_idx]->idb->macdb);
        return true;

    case DATABASE_BLOCK_EXTERNAL_IDB_ENCDB:
        ret.push_back(m_gibraltar_tree->slice_pair[block_idx]->idb->encdb);
        return true;

    // Internal engines, per device
    case DATABASE_BLOCK_INTERNAL_NPUH:
        ret.push_back(m_gibraltar_tree->npuh->npe);
        return true;

    // External engines, per device
    case DATABASE_BLOCK_EXTERNAL_CDB_TOP:
        ret.push_back(m_gibraltar_tree->cdb->top);
        return true;

    // External engines, per device
    case DATABASE_BLOCK_EXTERNAL_CDB_CORE:
        for (auto& cdb_core : m_gibraltar_tree->cdb->core) {
            ret.push_back(cdb_core);
        }
        return true;

    // External engines, per device
    case DATABASE_BLOCK_EXTERNAL_NPUH_HOST:
        ret.push_back(m_gibraltar_tree->npuh->host);
        return true;

    case DATABASE_BLOCK_EXTERNAL_NPUH_FI_ENG:
        ret.push_back(m_gibraltar_tree->npuh->fi);
        return true;

    case DATABASE_BLOCK_EXTERNAL_PDVOQ_SLICE:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->pdvoq);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_PDR_2_SLICES:
        ret.push_back(m_gibraltar_tree->slice_pair[block_idx]->rx_pdr);
        return true;

    case DATABASE_BLOCK_EXTERNAL_DRAM_CGM:
        ret.push_back(m_gibraltar_tree->dram_cgm);
        return true;

    case DATABASE_BLOCK_EXTERNAL_PDOQ:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->pdoq->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_FILB_SLICE:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->filb);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_PDR_SHARED_DB:
        // Returns both tables
        ret.push_back(m_gibraltar_tree->rx_pdr_mc_db[0]);
        ret.push_back(m_gibraltar_tree->rx_pdr_mc_db[1]);
        return true;

    case DATABASE_BLOCK_EXTERNAL_COUNTERS:
        ret.push_back(m_gibraltar_tree->counters->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_COUNTERS_BANK_GROUP:
        // this is multi-instance block
        if (inst_idx < counter_bank_8k_num) {
            ret.push_back(m_gibraltar_tree->counters->bank_8k[inst_idx]);
        } else {
            ret.push_back(m_gibraltar_tree->counters->bank_6k[inst_idx - counter_bank_8k_num]);
        }
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_COUNTERS:
        ret.push_back(m_gibraltar_tree->rx_counters);
        return true;

    case DATABASE_BLOCK_EXTERNAL_TXPDR:
        ret.push_back(m_gibraltar_tree->slice[block_idx]->tx->pdr);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_METER:
        ret.push_back(m_gibraltar_tree->rx_meter->top);
        return true;

    case DATABASE_BLOCK_EXTERNAL_RX_METER_BLOCK:
        // this is multi-instance block
        ret.push_back(m_gibraltar_tree->rx_meter->block[inst_idx]);
        return true;

    case DATABASE_BLOCK_EXTERNAL_REASSEMBLY:
        // this is multi-instance block
        ret.push_back(m_gibraltar_tree->reassembly);
        return true;

    case DATABASE_BLOCK_EXTERNAL_FRM:
        ret.push_back(m_gibraltar_tree->dmc->frm);
        return true;

    default:
        return false;
    }

    return false;
}

std::vector<lld_memory_scptr>
engine_block_mapper::get_ctm_tcam(size_t cdb_core, size_t subring_idx, size_t idx) const
{
    std::vector<lld_memory_scptr> ret;
    lld_memory_array_scptr lpm_tcams;
    lld_memory_array_scptr acl_tcams;

    if (subring_idx == 0) {
        lpm_tcams = m_gibraltar_tree->cdb->core[cdb_core]->lpm0_tcam;
        acl_tcams = m_gibraltar_tree->cdb->core[cdb_core]->ring0_acl_tcam;
    } else {
        dassert_crit(subring_idx == 1);
        lpm_tcams = m_gibraltar_tree->cdb->core[cdb_core]->lpm1_tcam;
        acl_tcams = m_gibraltar_tree->cdb->core[cdb_core]->ring1_acl_tcam;
    }

    // Each acl TCAM constructed from 2 LPM tcams (1024 lines each)
    size_t lpm_tcams_in_subring = lpm_tcams->size() / 2;
    if (idx < lpm_tcams_in_subring) {
        ret.push_back((*lpm_tcams)[idx * 2]);
        ret.push_back((*lpm_tcams)[idx * 2 + 1]);
    } else {
        ret.push_back((*acl_tcams)[idx - lpm_tcams_in_subring]);
    }
    return ret;
}

std::vector<lld_memory_scptr>
engine_block_mapper::get_ctm_sram(size_t cdb_core, size_t subring_idx, size_t idx) const
{
    std::vector<lld_memory_scptr> ret;
    if (subring_idx == 0) {
        ret.push_back((*m_gibraltar_tree->cdb->core[cdb_core]->ring0_associated_data_mem)[idx]);
    } else {
        dassert_crit(subring_idx == 1);
        ret.push_back((*m_gibraltar_tree->cdb->core[cdb_core]->ring1_associated_data_mem)[idx]);
    }
    return ret;
}

size_t
engine_block_mapper::get_memory_array_size(size_t mem_id) const
{
    la_slice_id_t rep_sid = 0; // TODO get the first active slice's id from the slice id manager
    switch (mem_id) {
    case gibraltar_tree::LLD_MEMORY_ENE_CLUSTER_ENE_MACRO_MEMORY:
        // take the data from a representative
        return m_gibraltar_tree->slice[rep_sid]->npu->txpp->ene_cluster[0]->ene_macro_memory->size();
    case gibraltar_tree::LLD_MEMORY_ENE_CLUSTER_ENE_DATA_MEMORY:
        // take the data from a representative
        return m_gibraltar_tree->slice[rep_sid]->npu->txpp->ene_cluster[0]->ene_data_memory->size();
    case gibraltar_tree::LLD_MEMORY_TXPP_LIGHT_FI_NPU_ENCAP_LOOKUP:
        // take the data from a representative
        return m_gibraltar_tree->slice[rep_sid]->npu->txpp->top->light_fi_npu_encap_lookup->size();
    default:
        // Never gets here.
        log_err(RA, "%s: unknown mem_id=%zu", __func__, mem_id);
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
