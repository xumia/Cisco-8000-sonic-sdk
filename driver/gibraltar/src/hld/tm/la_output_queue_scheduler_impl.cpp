// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "common/dassert.h"

#include "api/tm/la_interface_scheduler.h"
#include "hld_utils.h"
#include "la_ifg_scheduler_impl.h"
#include "la_output_queue_scheduler_impl.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_memory.h"
#include "system/la_device_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

enum {
    VSC_2_VOQ_MSB = 11,
    VSC_2_VOQ_LSB = 0,
    VSC_2_SLICE_MSB = 14,
    VSC_2_SLICE_LSB = 12,

    OQSE_SHAPER_RATE_LSB = 0,
    OQSE_SHAPER_RATE_MSB = 23,
    OQSE_TOPOLOGY_LSB = 64,
    OQSE_TOPOLOGY_MSB = 67,

    VSC_MAP_CFG_BIT_WIDTH = gibraltar::sch_vsc_map_cfg_memory::fields::OQSE_ID_WIDTH
                            + gibraltar::sch_vsc_map_cfg_memory::fields::OQSE_LL_BITMAP_WIDTH, ///< Width in bits of single entry in
                                                                                               /// the VSC map configuration memory.
    VSC_MAP_OQSE_BIT_WIDTH = gibraltar::sch_vsc_map_cfg_memory::fields::OQSE_ID_WIDTH,         ///< TODO add comment

    NUM_OF_OQCS_GROUPS_IN_P4_MODE = 4, ///< Number of OQCS group IDs in P4 mode(#oqcs_group_id_t)
    NUM_OF_OQCS_GROUPS_IN_P8_MODE = 8, ///< Number of OQCS group IDs in P4 mode(#oqcs_group_id_t)
    NUM_OF_OQCS_GROUPS = 8,            ///< Number of OQCS group IDs (#oqcs_group_id_t)

    FIRST_LPSE2P_MAP = (size_t)la_oq_vsc_mapping_e::RR0_RR2, ///< First VSC mapping which is available only for LPSE 2P mode.
    FIRST_LPSE8P_MAP = (size_t)la_oq_vsc_mapping_e::RR4,     ///< First VSC mapping which is available only for LPSE 28 mode.

    CREDIT_REQ_TRIGGER_ENQUEUE = 0,
    CREDIT_REQ_TRIGGER_GRANT_FEEDBACK = 2,

    VSC_MAP_CFG_DEFAULT_OQSE_ID = 0, ///< Default OQSE id.
    VSC_MAP_CFG_DEFAULT_MAPPING = 0, ///< Default VSC mapping.
};

bit_vector
la_output_queue_scheduler_impl::populate_vsc_voq_mapping_value(la_voq_gid_t ingress_voq, la_slice_id_t ingress_slice)
{
    bit_vector voq_bv(0);

    voq_bv.set_bits(11, 0, ingress_voq >> 4);
    voq_bv.set_bits(14, 12, ingress_slice);

    return voq_bv;
}

// Entry of single column in VscMapCfg - VSC mapping to OQSE
union vsc_map_cfg_t {
    uint32_t flat = 0;
    struct {
        uint32_t oqse_id : gibraltar::sch_vsc_map_cfg_memory::fields::OQSE_ID_WIDTH; ///< Map VSC to 1 of 512 OQSEs
        uint32_t oqse_ll_bitmap
            : gibraltar::sch_vsc_map_cfg_memory::fields::OQSE_LL_BITMAP_WIDTH; ///< Map VSC to 1 or 2 LLs out of 4 or 8 LLs
    } fields;
};

la_output_queue_scheduler_impl::la_output_queue_scheduler_impl(const la_device_impl_wptr& device,
                                                               la_slice_id_t slice_id,
                                                               la_ifg_id_t ifg_id,
                                                               index_handle index)
    : m_device(device),
      m_slice_id(slice_id),
      m_ifg_id(ifg_id),
      m_oqse_id(std::move(index)),
      m_groups_weights(),
      m_requested_credit_cir_burst_size(tm_utils::UNLIMITED_BUCKET_SIZE),
      m_requested_credit_eir_or_pir_burst_size(tm_utils::UNLIMITED_BUCKET_SIZE),
      m_requested_credit_oq_pir_burst_size(tm_utils::UNLIMITED_BUCKET_SIZE),
      m_requested_transmit_oq_pir_burst_size(tm_utils::UNLIMITED_BUCKET_SIZE)
{
    initialize_sch_references(m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch);
}

la_status
la_output_queue_scheduler_impl::populate_oqse_cfg(scheduling_mode_e mode, gibraltar::sch_oqse_cfg_memory& out_oqse_cfg)
{
    // Values are taken from sch LBR, memory VscMapCfg
    struct {
        size_t topology_val;
        size_t map_val;
    } res, mode2vals[] = {[(int)scheduling_mode_e::DIRECT_4SP] = {0, 0},      [(int)scheduling_mode_e::DIRECT_3SP_2WFQ] = {1, 0},
                          [(int)scheduling_mode_e::DIRECT_2SP_3WFQ] = {2, 0}, [(int)scheduling_mode_e::DIRECT_4WFQ] = {3, 0},
                          [(int)scheduling_mode_e::LP_SP_SP] = {0, 1},        [(int)scheduling_mode_e::LP_SP_WFQ] = {1, 1},
                          [(int)scheduling_mode_e::LP_WFQ_SP] = {2, 1},       [(int)scheduling_mode_e::LP_WFQ_WFQ] = {3, 1},
                          [(int)scheduling_mode_e::LP_4SP] = {0, 2},          [(int)scheduling_mode_e::LP_3SP_2WFQ] = {1, 2},
                          [(int)scheduling_mode_e::LP_2SP_3WFQ] = {2, 2},     [(int)scheduling_mode_e::LP_4WFQ] = {3, 2},
                          [(int)scheduling_mode_e::LP_8SP] = {0, 3},          [(int)scheduling_mode_e::LP_7SP_2WFQ] = {1, 3},
                          [(int)scheduling_mode_e::LP_6SP_3WFQ] = {2, 3},     [(int)scheduling_mode_e::LP_5SP_4WFQ] = {3, 3},
                          [(int)scheduling_mode_e::LP_4SP_5WFQ] = {4, 3},     [(int)scheduling_mode_e::LP_3SP_6WFQ] = {5, 3},
                          [(int)scheduling_mode_e::LP_2SP_7WFQ] = {6, 3},     [(int)scheduling_mode_e::LP_8WFQ] = {7, 3}};

    res = mode2vals[(int)mode];

    if (tm_utils::scheduling_mode_is_8p(m_scheduling_mode)) {
        // Pacific SDK supports 8p scheduler only for LPSE. see OqseCfg
        out_oqse_cfg.fields.logical_port_map0 = res.map_val;
        out_oqse_cfg.fields.logical_port_map1 = 2;
        const size_t topology_field_width = gibraltar::sch_oqse_cfg_memory::fields::OQSE0_TOPOLOGY_WIDTH;
        out_oqse_cfg.fields.oqse0_topology = bit_utils::get_bits(res.topology_val, topology_field_width - 1, 0);
        out_oqse_cfg.fields.oqse1_topology
            = bit_utils::get_bits(res.topology_val, 2 * topology_field_width - 1, topology_field_width);
    } else {
        if (m_oqse_id % 2 == 0) {
            out_oqse_cfg.fields.oqse0_topology = res.topology_val;
            out_oqse_cfg.fields.logical_port_map0 = res.map_val;
        } else {
            out_oqse_cfg.fields.oqse1_topology = res.topology_val;
            out_oqse_cfg.fields.logical_port_map1 = res.map_val;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::write_scheduling_mode()
{

    // Configure fields Oqse0Topology, Oqse1Topology, LogicalPortMap0, and LogicalPortMap1 in OqseCfg memory of SCH block
    // Note: Per OQSE pair configuration, each entry defines configuration for OQSE = 2*entry and 2*entry+1

    // TODO: calculate correct values
    // 8p mode should set all bits,
    // 4p mode should set 2 bits based on whether it is even or odd m_oqse_id
    gibraltar::sch_oqse_cfg_memory oqse_cfg;
    size_t sch_mem_line = m_oqse_id / 2;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_oqse_cfg, sch_mem_line, oqse_cfg);
    return_on_error(status);

    status = populate_oqse_cfg(m_scheduling_mode, oqse_cfg);
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(*m_sch_oqse_cfg, sch_mem_line, oqse_cfg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::initialize(la_object_id_t oid, scheduling_mode_e mode)
{
    m_oid = oid;
    m_scheduling_mode = mode;

    if (tm_utils::scheduling_mode_is_8p(mode)) {
        m_groups_weights.resize(NUM_OF_OQCS_GROUPS_IN_P8_MODE, 1);
    } else {
        m_groups_weights.resize(NUM_OF_OQCS_GROUPS_IN_P4_MODE, 1);
    }

    la_status status = write_scheduling_mode();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    for (const auto& vsc_oq : m_attached_vscs) {
        la_status status = do_detach_vsc(vsc_oq.first);
        return_on_error(status);
        la_device_impl::vsc_ownership_map_key vomk(m_slice_id, m_ifg_id, vsc_oq.first);
        m_device->m_vsc_ownership_map.erase(vomk);
    }

    m_attached_vscs.clear();

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::set_scheduling_mode(scheduling_mode_e mode)
{
    start_api_call("mode=", mode);
    if (tm_utils::scheduling_mode_is_8p(m_scheduling_mode) != tm_utils::scheduling_mode_is_8p(mode)) {
        log_err(HLD, "Cannot switch output queue scheduler between 4p and 8p modes");
        return LA_STATUS_EINVAL;
    }

    m_scheduling_mode = mode;

    return write_scheduling_mode();
}

la_status
la_output_queue_scheduler_impl::get_scheduling_mode(scheduling_mode_e& out_mode) const
{
    out_mode = m_scheduling_mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::get_group_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t& out_weight) const
{
    size_t num_groups;
    if (tm_utils::scheduling_mode_is_8p(m_scheduling_mode)) {
        num_groups = NUM_OF_OQCS_GROUPS;
    } else {
        num_groups = NUM_OF_OQCS_GROUPS_IN_P4_MODE;
    }

    if (group_id >= num_groups) {
        return LA_STATUS_EINVAL;
    }

    out_weight = m_groups_weights[group_id];
    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::get_group_actual_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t& out_weight) const
{
    size_t num_groups;
    size_t group_offset;
    if (tm_utils::scheduling_mode_is_8p(m_scheduling_mode)) {
        num_groups = NUM_OF_OQCS_GROUPS;
        group_offset = 0;
    } else {
        num_groups = NUM_OF_OQCS_GROUPS_IN_P4_MODE;
        group_offset = (m_oqse_id % 2) * NUM_OF_OQCS_GROUPS_IN_P4_MODE;
    }

    if (group_id >= num_groups) {
        return LA_STATUS_EINVAL;
    }

    // Credit scheduler
    bit_vector bv_rates;
    size_t sch_mem_line = m_oqse_id / 2;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_oqse_cfg, sch_mem_line, bv_rates);
    return_on_error(status);

    size_t lsb = (group_id + group_offset) * gibraltar::sch_oqse_cfg_memory::fields::OQSE_WFQ_WEIGHT0_WIDTH;
    size_t msb = lsb + gibraltar::sch_oqse_cfg_memory::fields::OQSE_WFQ_WEIGHT0_WIDTH - 1;
    out_weight = bit_utils::get_bits(bv_rates.get_value(), msb, lsb);

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::set_group_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t weight)
{
    start_api_call("group_id=", group_id, "weight=", weight);
    // Configure field OqseWfqWeightX in OqseCfg memory of SCH block
    // Weight valid values are 1:255
    //
    // Check valid values and supported only on even OQs (see comment above)
    size_t num_groups;
    size_t group_offset;
    if (tm_utils::scheduling_mode_is_8p(m_scheduling_mode)) {
        num_groups = NUM_OF_OQCS_GROUPS;
        group_offset = 0;
    } else {
        num_groups = NUM_OF_OQCS_GROUPS_IN_P4_MODE;
        group_offset = (m_oqse_id % 2) * NUM_OF_OQCS_GROUPS_IN_P4_MODE;
    }

    if ((group_id >= num_groups) || (weight > tm_utils::TM_WEIGHT_MAX) || (weight == 0)) {
        return LA_STATUS_EINVAL;
    }

    size_t sch_mem_line = m_oqse_id / 2;

    m_groups_weights[group_id] = weight;
    std::vector<la_rate_t> rates
        = tm_utils::convert_weight_2_rate_vector(m_groups_weights, gibraltar::sch_oqse_cfg_memory::fields::OQSE_WFQ_WEIGHT0_WIDTH);

    bit_vector bv_rates;
    la_status stat = m_device->m_ll_device->read_memory(*m_sch_oqse_cfg, sch_mem_line, bv_rates);
    return_on_error(stat);

    for (size_t i = 0; i < num_groups; i++) {
        size_t lsb = (i + group_offset) * gibraltar::sch_oqse_cfg_memory::fields::OQSE_WFQ_WEIGHT0_WIDTH;
        size_t msb = lsb + gibraltar::sch_oqse_cfg_memory::fields::OQSE_WFQ_WEIGHT0_WIDTH - 1;
        bv_rates.set_bits(msb, lsb, rates[i]);
    }

    return m_device->m_ll_device->write_memory(*m_sch_oqse_cfg, sch_mem_line, bv_rates);
}

la_status
la_output_queue_scheduler_impl::get_attached_vscs(la_vsc_oq_vec_t& out_vsc_vector) const
{
    out_vsc_vector.clear();
    // check each vsc for connection with the specific OQ
    la_vsc_gid_t vsc;
    la_oq_id_t oqse_id = m_oqse_id; // OQSE ID, in this case we have 8 OQs per TM port
    for (vsc = 0; la_device_impl::is_vsc_id_in_range(m_slice_id, vsc); ++vsc) {
        size_t sch_mem_line = vsc / tm_utils::VSC_MAP_CFG_ENTRIES;
        size_t lsb = (vsc % tm_utils::VSC_MAP_CFG_ENTRIES) * VSC_MAP_CFG_BIT_WIDTH;

        bit_vector tmp_bv;
        la_status stat = m_device->m_ll_device->read_memory(*m_sch_vsc_map_cfg, sch_mem_line, tmp_bv);
        return_on_error(stat);
        // vsc_val is 12 LSB in vsc_map_cfg
        uint32_t vsc_val = tmp_bv.bits(lsb + VSC_MAP_OQSE_BIT_WIDTH - 1, lsb).get_value();
        // map_val is 3 MSB in vsc_map_cfg
        la_oq_vsc_mapping_e map_val
            = (la_oq_vsc_mapping_e)(tmp_bv.bits(lsb + VSC_MAP_CFG_BIT_WIDTH - 1, lsb + VSC_MAP_OQSE_BIT_WIDTH).get_value());

        if (vsc_val == oqse_id) {
            if (vsc_val == VSC_MAP_CFG_DEFAULT_OQSE_ID) {
                // Default VSC to OQSE(0) mapping in the H/W, skip.
                if (m_attached_vscs.count(vsc) == 0) {
                    continue;
                }
            }
            la_vsc_oq attached_vsc;
            attached_vsc.vsc = vsc;
            attached_vsc.map = map_val;
            stat = get_attached_csms(attached_vsc);
            return_on_error(stat);
            out_vsc_vector.push_back(attached_vsc);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::get_attached_csms(la_vsc_oq& attached_vsc) const
{
    bit_vector tmp_bv;
    la_status ret;

    lld_memory_sptr dev_mem = nullptr;
    lld_memory_sptr voq_mem = nullptr;
    size_t line = 0;

    get_dev_voq_map_info(attached_vsc.vsc, dev_mem, voq_mem, line);

    if (dev_mem) {
        ret = m_device->m_ll_device->read_memory(*dev_mem, line, tmp_bv);
        return_on_error(ret);

        attached_vsc.device_id = tmp_bv.get_value();
    } else {
        attached_vsc.device_id = m_device->get_id();
    }

    ret = m_device->m_ll_device->read_memory(*voq_mem, line, tmp_bv);
    return_on_error(ret);

    attached_vsc.voq_id = (tmp_bv.bits(11, 0).get_value() << 4) + (attached_vsc.vsc % NATIVE_VOQ_SET_SIZE);
    // 4 LSB in voq value stored in CSMS are masked
    attached_vsc.slice_id = tmp_bv.bits(14, 12).get_value();

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::attach_vsc(la_vsc_gid_t vsc,
                                           la_oq_vsc_mapping_e mapping,
                                           la_device_id_t ingress_device,
                                           la_slice_id_t ingress_slice,
                                           la_voq_gid_t ingress_voq_id)
{
    start_api_call("vsc=",
                   vsc,
                   "mapping=",
                   mapping,
                   "ingress_device=",
                   ingress_device,
                   "ingress_slice=",
                   ingress_slice,
                   "ingress_voq_id=",
                   ingress_voq_id);

    la_status status = m_device->get_slice_id_manager()->is_slice_valid(ingress_slice);
    return_on_error(status);
    // Check limits
    if ((!la_device_impl::is_vsc_id_in_range(m_slice_id, vsc)) || (ingress_device >= la_device_impl::la_device_impl::MAX_DEVICES)
        || (!la_device_impl::is_voq_id_in_range(ingress_slice, ingress_voq_id))) {
        return LA_STATUS_EINVAL;
    }

    // Check if this is local or remote
    bool is_local = (m_device->get_id() == ingress_device);

    // If remote, ensure local slice and remote slice supports remote device
    if (!is_local && (!la_device_impl::is_multi_device_aware_slice(m_slice_id)
                      || !la_device_impl::is_multi_device_aware_slice(ingress_slice))) {
        return LA_STATUS_EINVAL;
    }

    if (tm_utils::scheduling_mode_is_8p(m_scheduling_mode)) {
        if ((size_t)FIRST_LPSE2P_MAP <= (size_t)mapping && (size_t)mapping < (size_t)FIRST_LPSE8P_MAP) {
            log_err(
                HLD, "%s(...); VSC mapping %d doesn't match scheduling mode %d", __func__, (int)mapping, (int)m_scheduling_mode);
            return LA_STATUS_EINVAL;
        }
    } else {
        if ((size_t)mapping >= (size_t)FIRST_LPSE8P_MAP) {
            log_err(HLD, "VSC mapping %d doesn't match scheduling mode %d", (int)mapping, (int)m_scheduling_mode);
            return LA_STATUS_EINVAL;
        }
    }

    la_device_impl::vsc_ownership_map_key vomk(m_slice_id, m_ifg_id, vsc);
    auto it = m_device->m_vsc_ownership_map.find(vomk);
    if (it != m_device->m_vsc_ownership_map.end()) {
        const auto& oqs = it->second.oqs;
        if (oqs != this) {
            log_err(HLD, "vsc %d is already attached to %s", vsc, oqs->to_string().c_str());
            return LA_STATUS_EBUSY;
        }
    }

    status = do_attach_vsc(vsc, mapping, ingress_device, ingress_slice, ingress_voq_id);
    return_on_error(status);

    m_device->m_vsc_ownership_map[vomk] = {.device_id = ingress_device, .oqs = m_device->get_sptr(this)};

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::do_attach_vsc(la_vsc_gid_t vsc,
                                              la_oq_vsc_mapping_e mapping,
                                              la_device_id_t ingress_device,
                                              la_slice_id_t ingress_slice,
                                              la_voq_gid_t ingress_voq_id)
{
    la_status status = attach_vsc_csms(vsc, ingress_device, ingress_slice, ingress_voq_id);
    return_on_error(status);

    status = attach_vsc_sch(vsc, mapping);
    return_on_error(status);

    la_vsc_oq vsc_oq;
    vsc_oq.vsc = vsc;
    vsc_oq.map = mapping;
    vsc_oq.device_id = ingress_device;
    vsc_oq.slice_id = ingress_slice;
    vsc_oq.voq_id = ingress_voq_id;
    m_attached_vscs[vsc] = vsc_oq; // If vsc already exists, the new vsc_oq will override its value.

    status = do_set_vsc_burst_size(vsc, tm_utils::UNLIMITED_BUCKET_SIZE);
    return_on_error(status);

    status = do_set_vsc_pir(vsc, LA_RATE_UNLIMITED);
    return_on_error(status);

    return status;
}

la_status
la_output_queue_scheduler_impl::detach_vsc(la_vsc_gid_t vsc)
{
    start_api_call("vsc=", vsc);

    auto it = m_attached_vscs.find(vsc);
    if (it == m_attached_vscs.end()) {
        log_err(HLD, "vsc %d not attached to this oqse", vsc);
        return LA_STATUS_ENOTFOUND;
    }

    la_status status = do_detach_vsc(vsc);
    return_on_error(status);

    m_attached_vscs.erase(vsc);

    la_device_impl::vsc_ownership_map_key vomk(m_slice_id, m_ifg_id, vsc);
    m_device->m_vsc_ownership_map.erase(vomk);

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::do_detach_vsc(la_vsc_gid_t vsc)
{
    la_status status = do_set_vsc_burst_size(vsc, tm_utils::UNLIMITED_BUCKET_SIZE);
    return_on_error(status);

    status = do_set_vsc_pir(vsc, LA_RATE_UNLIMITED);
    return_on_error(status);

    status = detach_vsc_sch(vsc);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::set_static_go(bit_vector& reachable_devices_bv)
{
    for (const auto& vsc_oq : m_attached_vscs) {
        // Static-go ahould be activated only on reachable devices.
        bool is_dev_reachable = false;
        la_device_impl::vsc_ownership_map_key vomk(m_slice_id, m_ifg_id, vsc_oq.first);
        auto it = m_device->m_vsc_ownership_map.find(vomk);
        if (it != m_device->m_vsc_ownership_map.end()) {
            is_dev_reachable = reachable_devices_bv.bit(it->second.device_id);
        }

        if (is_dev_reachable) {
            la_status status = set_static_go(vsc_oq.first);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::set_static_go(la_vsc_gid_t vsc)
{
    gibraltar::sch_credit_request_gen_debug_register reg;
    reg.fields.cr_req_gen_trigger = CREDIT_REQ_TRIGGER_ENQUEUE;
    reg.fields.cr_req_gen_go = 1;
    reg.fields.cr_req_gen_stop = 0;
    reg.fields.cr_req_gen_acc_bytes = 0;
    reg.fields.cr_req_gen_ib_state = 0;
    reg.fields.cr_req_gen_return = 0;
    reg.fields.cr_req_gen_vsc = vsc;

    la_status status = m_device->m_ll_device->write_register(
        m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch->credit_request_gen_debug, reg);
    return status;
}

la_status
la_output_queue_scheduler_impl::stop_static_go(la_vsc_gid_t vsc_id)
{
    gibraltar::sch_credit_request_gen_debug_register reg;
    reg.fields.cr_req_gen_trigger = CREDIT_REQ_TRIGGER_GRANT_FEEDBACK;
    reg.fields.cr_req_gen_go = 0;
    reg.fields.cr_req_gen_stop = 1;
    reg.fields.cr_req_gen_acc_bytes = 0;
    reg.fields.cr_req_gen_ib_state = 0;
    reg.fields.cr_req_gen_return = 0;
    reg.fields.cr_req_gen_vsc = vsc_id;

    la_status status = m_device->m_ll_device->write_register(
        m_device->m_gb_tree->slice[m_slice_id]->ifg[m_ifg_id]->sch->credit_request_gen_debug, reg);
    return status;
}

la_status
la_output_queue_scheduler_impl::attach_vsc_csms(la_vsc_gid_t vsc,
                                                la_device_id_t ingress_device,
                                                la_slice_id_t ingress_slice,
                                                la_voq_gid_t ingress_voq_id)
{
    lld_memory_sptr dev_mem = nullptr;
    lld_memory_sptr voq_mem = nullptr;
    size_t line = 0;

    get_dev_voq_map_info(vsc, dev_mem, voq_mem, line);

    // In CSMS set the map from VSC to ingress device, slice, and voq
    bit_vector voq_bv = populate_vsc_voq_mapping_value(ingress_voq_id, ingress_slice);

    if (dev_mem) {
        if ((m_slice_id > la_device_impl::CSMS_ALL_DEV_SUPPORT_LAST_SLICE)
            && (ingress_device > la_device_impl::CSMS_LAST_SUPPORTED_SUBSET_DEVICE)) {
            log_err(HLD, "Egress slice %u cannot reach ingress device %u", m_slice_id, ingress_device);
            return LA_STATUS_EINVAL;
        }

        bit_vector ingress_device_bv(ingress_device, dev_mem->get_desc()->width_bits);
        la_status ret = m_device->m_ll_device->write_memory(*dev_mem, line, ingress_device_bv);
        return_on_error(ret);
    }

    return m_device->m_ll_device->write_memory(*voq_mem, line, voq_bv);
}

la_status
la_output_queue_scheduler_impl::attach_vsc_sch(la_vsc_gid_t vsc, la_oq_vsc_mapping_e mapping)
{
    // In SCH set the map to VSC
    // Set map from VSC to OQ and VSC mapping
    // Update memory VscMapCfg at line VSC/4, fields OqseId and OqseLlBitmap
    size_t sch_mem_line = vsc / tm_utils::VSC_MAP_CFG_ENTRIES;
    size_t lsb = (vsc % tm_utils::VSC_MAP_CFG_ENTRIES) * VSC_MAP_CFG_BIT_WIDTH;
    vsc_map_cfg_t vsc_map_cfg_val;

    vsc_map_cfg_val.fields.oqse_id = m_oqse_id;
    vsc_map_cfg_val.fields.oqse_ll_bitmap = get_ll_bitmap(mapping);

    la_status status = m_device->m_ll_device->read_modify_write_memory(
        *m_sch_vsc_map_cfg, sch_mem_line, lsb + VSC_MAP_CFG_BIT_WIDTH - 1, lsb, vsc_map_cfg_val.flat);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::detach_vsc_sch(la_vsc_gid_t vsc)
{
    // In SCH set the map to VSC
    // Set map from VSC to default H/W values for OQ and VSC mapping
    // Update memory VscMapCfg at line VSC/4, fields OqseId and OqseLlBitmap
    size_t sch_mem_line = vsc / tm_utils::VSC_MAP_CFG_ENTRIES;
    size_t lsb = (vsc % tm_utils::VSC_MAP_CFG_ENTRIES) * VSC_MAP_CFG_BIT_WIDTH;
    vsc_map_cfg_t vsc_map_cfg_val;

    vsc_map_cfg_val.fields.oqse_id = VSC_MAP_CFG_DEFAULT_OQSE_ID;
    vsc_map_cfg_val.fields.oqse_ll_bitmap = get_ll_bitmap((la_oq_vsc_mapping_e)VSC_MAP_CFG_DEFAULT_MAPPING);

    la_status status = m_device->m_ll_device->read_modify_write_memory(
        *m_sch_vsc_map_cfg, sch_mem_line, lsb + VSC_MAP_CFG_BIT_WIDTH - 1, lsb, vsc_map_cfg_val.flat);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

size_t
la_output_queue_scheduler_impl::get_ll_bitmap(la_oq_vsc_mapping_e mapping) const
{
    // RR0-RR3 are shared mapping between the 4P and 8P.
    // RR0_RR2-RR1_RR3 are for LPSE 2P mode.
    // RR4-RR7 are for 8P and should be encoded 4-7.
    if ((size_t)mapping >= (size_t)FIRST_LPSE8P_MAP) {
        return (size_t)mapping - (FIRST_LPSE8P_MAP - FIRST_LPSE2P_MAP);
    }

    return (size_t)mapping;
}

la_status
la_output_queue_scheduler_impl::get_vsc_pir(la_vsc_gid_t vsc, la_rate_t& out_rate) const
{
    // Retrieve OqseShaperRate register in the SCH block
    if (!(la_device_impl::is_vsc_id_in_range(m_slice_id, vsc))) {
        return LA_STATUS_EINVAL;
    }

    uint32_t total_oqse_rate;
    la_status status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_oqse_shaper(total_oqse_rate);
    return_on_error(status);

    gibraltar::sch_oqse_shaper_configuration_register oqse_shaper_configuration;
    status = m_device->m_ll_device->read_register(*m_oqse_shaper_configuration, oqse_shaper_configuration);
    return_on_error(status);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    // See note about credits_conf_reg.fields.crdt_in_bytes in do_set_vsc_pir(..)

    la_rate_t total_oqse_rate_from_device
        = tm_utils::convert_rate_from_device_val(total_oqse_rate,
                                                 oqse_shaper_configuration.fields.oqse_shaper_incr_value,
                                                 credits_conf_reg.fields.crdt_in_bytes,
                                                 m_device->m_device_frequency_int_khz);

    gibraltar::sch_vsc_token_bucket_cfg_memory token_bucket_cfg;
    status = m_device->m_ll_device->read_memory(*m_sch_vsc_token_bucket_cfg, vsc, token_bucket_cfg);

    return_on_error(status);

    float ratio = tm_utils::convert_float_from_device_val(token_bucket_cfg.fields.vsc_rate_exponent,
                                                          token_bucket_cfg.fields.vsc_rate_mantissa);
    out_rate = ratio * total_oqse_rate_from_device;
    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::set_vsc_pir(la_vsc_gid_t vsc, la_rate_t rate)
{
    start_api_call("vsc=", vsc, "rate=", rate);
    if (!(la_device_impl::is_vsc_id_in_range(m_slice_id, vsc))) {
        return LA_STATUS_EINVAL;
    }

    // Verify the given VSC mapped to this OQSE
    size_t mapped_oqse;
    la_status stat = tm_utils::get_vsc_mapping(m_device, m_sch_vsc_map_cfg, vsc, mapped_oqse);
    return_on_error(stat);

    if (m_oqse_id != mapped_oqse) {
        return LA_STATUS_EINVAL;
    }

    return do_set_vsc_pir(vsc, rate);
}

la_status
la_output_queue_scheduler_impl::do_set_vsc_pir(la_vsc_gid_t vsc, la_rate_t rate)
{
    // Configure VscTokenBucketCfg at line vsc of SCH block
    // Token Bucket Configuration - defines ratio of OqseShaperRate that will be allocated to VSC

    // Retrieve OqseShaperRate register in the SCH block
    uint32_t total_oqse_rate;
    la_status status = m_device->m_ifg_schedulers[m_slice_id][m_ifg_id]->get_oqse_shaper(total_oqse_rate);
    return_on_error(status);

    gibraltar::sch_oqse_shaper_configuration_register oqse_shaper_configuration;
    status = m_device->m_ll_device->read_register(*m_oqse_shaper_configuration, oqse_shaper_configuration);
    return_on_error(status);

    gibraltar::ics_slice_credits_conf_reg_register credits_conf_reg;
    status = m_device->m_ll_device->read_register(m_device->m_gb_tree->slice[m_slice_id]->ics->credits_conf_reg, credits_conf_reg);
    return_on_error(status);

    // Note about the interpretation of credits_conf_reg.fields.crdt_in_bytes.
    //
    // A credit is oqse_shaper_incr_value tokens, and each token is crdt_in_bytes bytes.
    // The credit-grant side (egress device) grants credit based on its credits-rate config.
    // The interpretation of how many tokens (and bytes) a credit is, is actually done by the credit-request side (ingress device),
    // based on the config of its ICS (ingress credit-scheduler).
    // So the credit-granter doesn't know what granularity the credit-requester is going to use to tranlate the credits to bytes.
    // When the user calls a credit-grant rate configuring API (VSC is actual granter entity), to translate the bps to credits, the
    // granter SDK needs to know how the requester HW will interpret it - and it can't know.
    //
    // So technically, if we assume that the ICS config is the same in the whole system, then granter can use its local ICS config
    // to assume how the requester device will interpret the credit.

    // rate - credits_per_sec
    la_rate_t total_oqse_rate_from_device
        = tm_utils::convert_rate_from_device_val(total_oqse_rate,
                                                 oqse_shaper_configuration.fields.oqse_shaper_incr_value,
                                                 credits_conf_reg.fields.crdt_in_bytes,
                                                 m_device->m_device_frequency_int_khz);

    if ((rate > total_oqse_rate_from_device) && (rate != LA_RATE_UNLIMITED)) {
        return LA_STATUS_EINVAL;
    }

    gibraltar::sch_vsc_token_bucket_cfg_memory token_bucket_cfg;
    status = m_device->m_ll_device->read_memory(*m_sch_vsc_token_bucket_cfg, vsc, token_bucket_cfg);
    return_on_error(status);

    // Calculate exponenta and mantissa
    tm_utils::token_bucket_ratio_cfg_t ratio_cfg = tm_utils::calc_rate_ratio(total_oqse_rate_from_device, rate);
    token_bucket_cfg.fields.vsc_rate_mantissa = ratio_cfg.fields.mantissa;
    token_bucket_cfg.fields.vsc_rate_exponent = ratio_cfg.fields.exponent;

    // Set the values
    status = m_device->m_ll_device->write_memory(*m_sch_vsc_token_bucket_cfg, vsc, token_bucket_cfg);
    return_on_error(status);

    status = m_device->m_ll_device->write_memory(*m_sch_vsc_token_bucket, vsc, token_bucket_cfg.fields.vsc_max_bucket_value);

    return status;
}

la_status
la_output_queue_scheduler_impl::get_vsc_burst_size(la_vsc_gid_t vsc, size_t& out_burst) const
{
    if (!(la_device_impl::is_vsc_id_in_range(m_slice_id, vsc))) {
        return LA_STATUS_EINVAL;
    }

    // check vsc for connection with the specific OQ
    gibraltar::sch_vsc_map_cfg_memory vsc_map;
    size_t sch_mem_line = vsc / tm_utils::VSC_MAP_CFG_ENTRIES;

    la_status stat = m_device->m_ll_device->read_memory(*m_sch_vsc_map_cfg, sch_mem_line, vsc_map);
    return_on_error(stat);

    uint32_t vsc_val;
    switch (vsc % tm_utils::VSC_MAP_CFG_ENTRIES) {
    case 0:
        vsc_val = vsc_map.fields.oqse_id;
        break;
    case 1:
        vsc_val = vsc_map.fields.oqse_id1;
        break;
    case 2:
        vsc_val = vsc_map.fields.oqse_id2;
        break;
    case 3:
        vsc_val = vsc_map.fields.oqse_id3;
        break;
    default:
        dassert_crit(false && "Unreachable");
        vsc_val = 0;
        break;
    }

    if (vsc_val != m_oqse_id) {
        return LA_STATUS_EINVAL;
    }

    gibraltar::sch_vsc_token_bucket_cfg_memory token_bucket_cfg;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_vsc_token_bucket_cfg, vsc, token_bucket_cfg);
    return_on_error(status);

    out_burst = token_bucket_cfg.fields.vsc_max_bucket_value;

    return LA_STATUS_SUCCESS;
}

la_status
la_output_queue_scheduler_impl::set_vsc_burst_size(la_vsc_gid_t vsc, size_t burst)
{
    start_api_call("vsc=", vsc, "burst=", burst);

    if (!(la_device_impl::is_vsc_id_in_range(m_slice_id, vsc))) {
        return LA_STATUS_EINVAL;
    }

    return do_set_vsc_burst_size(vsc, burst);
}

la_status
la_output_queue_scheduler_impl::do_set_vsc_burst_size(la_vsc_gid_t vsc, size_t burst)
{
    // check vsc for connection with the specific OQ
    gibraltar::sch_vsc_map_cfg_memory vsc_map;
    size_t sch_mem_line = vsc / tm_utils::VSC_MAP_CFG_ENTRIES;

    la_status stat = m_device->m_ll_device->read_memory(*m_sch_vsc_map_cfg, sch_mem_line, vsc_map);
    return_on_error(stat);

    uint32_t vsc_val;
    switch (vsc % tm_utils::VSC_MAP_CFG_ENTRIES) {
    case 0:
        vsc_val = vsc_map.fields.oqse_id;
        break;
    case 1:
        vsc_val = vsc_map.fields.oqse_id1;
        break;
    case 2:
        vsc_val = vsc_map.fields.oqse_id2;
        break;
    case 3:
        vsc_val = vsc_map.fields.oqse_id3;
        break;
    default:
        dassert_crit(false && "Unreachable");
        vsc_val = 0;
        break;
    }

    if (vsc_val != m_oqse_id) {
        return LA_STATUS_EINVAL;
    }

    size_t max_bucket_value = (1 << gibraltar::sch_vsc_token_bucket_cfg_memory::fields::VSC_MAX_BUCKET_VALUE_WIDTH) - 1;
    if (burst > max_bucket_value) {
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::sch_vsc_token_bucket_cfg_memory token_bucket_cfg;
    la_status status = m_device->m_ll_device->read_memory(*m_sch_vsc_token_bucket_cfg, vsc, token_bucket_cfg);
    return_on_error(status);

    bool reset_dynamic_memory = token_bucket_cfg.fields.vsc_max_bucket_value == 0 && burst != 0 ? true : false;

    token_bucket_cfg.fields.vsc_max_bucket_value = burst;

    stat = m_device->m_ll_device->write_memory(*m_sch_vsc_token_bucket_cfg, vsc, token_bucket_cfg);
    return_on_error(stat);

    stat = m_device->m_ll_device->write_memory(*m_sch_vsc_token_bucket, vsc, token_bucket_cfg.fields.vsc_max_bucket_value);
    return_on_error(stat);

    if (reset_dynamic_memory) {
        gibraltar::sch_vsc_token_bucket_empty_memory reset_cfg;
        size_t reset_mem_line = vsc / gibraltar::sch_vsc_token_bucket_empty_memory::fields::VSC_TOKEN_BUCKET_EMPTY_FLAG_WIDTH;
        size_t reset_mem_idx = vsc % gibraltar::sch_vsc_token_bucket_empty_memory::fields::VSC_TOKEN_BUCKET_EMPTY_FLAG_WIDTH;
        stat = m_device->m_ll_device->read_memory(*m_sch_vsc_token_bucket_empty, reset_mem_line, reset_cfg);
        return_on_error(stat);

        reset_cfg.fields.vsc_token_bucket_empty_flag &= ~(1 << reset_mem_idx);
        stat = m_device->m_ll_device->write_memory(*m_sch_vsc_token_bucket_empty, reset_mem_line, reset_cfg);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_output_queue_scheduler_impl::type() const
{
    return object_type_e::OUTPUT_QUEUE_SCHEDULER;
}

std::string
la_output_queue_scheduler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_output_queue_scheduler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_output_queue_scheduler_impl::oid() const
{
    return m_oid;
}

const la_device*
la_output_queue_scheduler_impl::get_device() const
{
    return m_device.get();
}

int
la_output_queue_scheduler_impl::get_oqse_id() const
{
    return m_oqse_id;
}

void
la_output_queue_scheduler_impl::get_dev_voq_map_info(la_vsc_gid_t vsc,
                                                     lld_memory_sptr& out_dev_mem,
                                                     lld_memory_sptr& out_voq_mem,
                                                     size_t& out_line) const
{
    if (m_slice_id <= la_device_impl::CSMS_ALL_DEV_SUPPORT_LAST_SLICE) {
        out_dev_mem = (*m_device->m_gb_tree->csms->dst_dev_map_mem)[m_slice_id];
    } else if (m_slice_id == la_device_impl::CSMS_SUBSET_DEV_SUPPORT_SLICE) {
        out_dev_mem = m_device->m_gb_tree->csms->dst_dev_map_mem_red;
    }

    if (la_device_impl::is_multi_device_aware_slice(m_slice_id)) {
        out_voq_mem = (*m_device->m_gb_tree->csms->voq_vsc_dst_map_mem)[m_slice_id];
    } else {
        out_voq_mem = (*m_device->m_gb_tree->csms->vsc_dst_map_mem)[m_slice_id - la_device_impl::MAX_REMOTE_SLICE];
    }

    uint32_t entries_per_ifg_num = la_device_impl::MAX_VSCS_PER_IFG_IN_SLICE / NATIVE_VOQ_SET_SIZE;
    out_line = (vsc / NATIVE_VOQ_SET_SIZE) + (m_ifg_id * entries_per_ifg_num);
}

void
la_output_queue_scheduler_impl::cache_credit_cir_burst_size(size_t burst)
{
    m_requested_credit_cir_burst_size = burst;
    return;
}

size_t
la_output_queue_scheduler_impl::get_cached_credit_cir_burst_size() const
{
    return m_requested_credit_cir_burst_size;
}

void
la_output_queue_scheduler_impl::cache_credit_eir_or_pir_burst_size(size_t burst)
{
    m_requested_credit_eir_or_pir_burst_size = burst;
    return;
}

size_t
la_output_queue_scheduler_impl::get_cached_credit_eir_or_pir_burst_size() const
{
    return m_requested_credit_eir_or_pir_burst_size;
}

void
la_output_queue_scheduler_impl::cache_credit_oq_pir_burst_size(size_t burst)
{
    m_requested_credit_oq_pir_burst_size = burst;
    return;
}

size_t
la_output_queue_scheduler_impl::get_cached_credit_oq_pir_burst_size() const
{
    return m_requested_credit_oq_pir_burst_size;
}

void
la_output_queue_scheduler_impl::cache_transmit_oq_pir_burst_size(size_t burst)
{
    m_requested_transmit_oq_pir_burst_size = burst;
    return;
}

size_t
la_output_queue_scheduler_impl::get_cached_transmit_oq_pir_burst_size() const
{
    return m_requested_transmit_oq_pir_burst_size;
}

la_slice_id_t
la_output_queue_scheduler_impl::get_slice() const
{
    return m_slice_id;
}

la_ifg_id_t
la_output_queue_scheduler_impl::get_ifg() const
{
    return m_ifg_id;
}

bool
la_output_queue_scheduler_impl::is_system_port_queueing() const
{
    return (m_oqse_id < FIRST_LP_QUEUING_OQSE);
}

} // namespace silicon_one
