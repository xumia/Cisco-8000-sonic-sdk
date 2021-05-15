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

#ifndef __LA_LOGICAL_PORT_SCHEDULER_IMPL_H__
#define __LA_LOGICAL_PORT_SCHEDULER_IMPL_H__

#include "api/tm/la_logical_port_scheduler.h"
#include "api/types/la_tm_types.h"
#include "hld_types_fwd.h"
#include "system/la_device_impl.h"
#include "tm/la_credit_scheduler_enums.h"
#include "tm_utils.h"
#include <set>

namespace silicon_one
{

class lld_register;
class lld_memory;

class la_logical_port_scheduler_impl : public la_logical_port_scheduler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_logical_port_scheduler_impl(const la_device_impl_wptr& device,
                                            la_slice_id_t slice_id,
                                            la_ifg_id_t ifg_id,
                                            la_system_port_scheduler_id_t tid,
                                            la_rate_t port_speed);
    ~la_logical_port_scheduler_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    // la_logical_port_scheduler API-s
    la_status get_attached_oqcs(la_oq_pg_vec_t& out_oq_vector) const override;
    la_status attach_oqcs(la_output_queue_scheduler* oqcs, la_vsc_gid_t group_id) override;
    la_status detach_oqcs(la_output_queue_scheduler* oqcs) override;
    la_status get_group_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const override;
    la_status get_group_actual_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const override;
    la_status set_group_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t weight) override;
    la_status get_group_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const override;
    la_status get_group_actual_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const override;
    la_status set_group_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t weight) override;
    la_status get_oqcs_cir(la_output_queue_scheduler* oqcs, la_rate_t& out_rate) const override;
    la_status set_oqcs_cir(la_output_queue_scheduler* oqcs, la_rate_t rate) override;
    la_status get_oqcs_burst_size(la_output_queue_scheduler* oqcs, size_t& out_burst) const override;
    la_status set_oqcs_burst_size(la_output_queue_scheduler* oqcs, size_t burst) override;
    la_status get_oqcs_eir_or_pir(la_output_queue_scheduler* oqcs, la_rate_t& out_rate, bool& out_is_eir) const override;
    la_status set_oqcs_eir_or_pir(la_output_queue_scheduler* oqcs, la_rate_t rate, bool is_eir) override;
    la_status get_oqcs_eir_or_pir_burst_size(la_output_queue_scheduler* oqcs, size_t& out_burst) const override;
    la_status set_oqcs_eir_or_pir_burst_size(la_output_queue_scheduler* oqcs, size_t burst) override;
    la_status update_port_speed(la_mac_port::port_speed_e mac_port_speed,
                                const la_output_queue_scheduler_impl_wptr& eir_oqse,
                                const la_output_queue_scheduler_impl_wptr& cir_oqse);

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Implementation
    la_status do_attach_oqcs(const la_output_queue_scheduler_impl_wptr& oqcs, size_t group_id);
    la_status do_detach_oqcs(const la_output_queue_scheduler_impl_wptr& oqcs);
    bool is_oqcs_attached(const la_output_queue_scheduler_wptr& oqcs) const;
    la_status do_set_oqcs_eir_or_pir_burst_size(const la_output_queue_scheduler_wptr& oqcs, size_t burst);
    la_status do_set_oqcs_burst_size(const la_output_queue_scheduler_wptr& oqcs, size_t burst);
    la_status do_get_oqcs_cir(const la_output_queue_scheduler_wptr& oqcs, la_rate_t& out_rate) const;
    la_status do_get_oqcs_eir_or_pir(const la_output_queue_scheduler_wptr& oqcs, la_rate_t& out_rate, bool& out_is_eir) const;

private:
    enum {
        SLICE_OQSE_COUNT = 512, ///< Number of Output Queue CS in a slice.
        NUM_OF_LPCS_GROUPS = 8, ///< Number of LP CS groups.
        LPSE_MSB = 4,           ///< LPSE id msb
        LPSE_LSB = 0,           ///< LPSE id lsb
        OQ_PG_CIR_MSB = 7,      ///< OqseCirWfqWeightIndex - CIR Link List MSB
        OQ_PG_CIR_LSB = 5,      ///< OqseCirWfqWeightIndex - CIR Link List LSB
        OQ_PG_EIR_MSB = 10,     ///< OqseCirWfqWeightIndex - EIR Link List MSB
        OQ_PG_EIR_LSB = 8,      ///< OqseCirWfqWeightIndex - EIR Link List LSB
    };

    // The Device this logical port credit scheduler belongs to.
    la_device_impl_wptr m_device;

    // Object id
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // The credit scheduler this logical port credit scheduler belongs to.
    la_ifg_scheduler_impl_wptr m_cs;

    // The slice ID of this logical
    la_slice_id_t m_slice_id;

    // The interface group ID of this logical port
    la_ifg_id_t m_ifg_id;

    // The TM port ID of this logical port
    la_system_port_scheduler_id_t m_tid;

    // The underlying mac port speed
    la_rate_t m_port_speed;

    // Set of output queue scheduler objects
    std::set<la_output_queue_scheduler_impl_wptr> m_oq_sch_set;

    // Cir weights of all groups as set by the user.
    std::vector<la_wfq_weight_t> m_groups_cir_weights;

    // Eir weights of all groups as set by the user.
    std::vector<la_wfq_weight_t> m_groups_eir_weights;

    la_logical_port_scheduler_impl() = default; // For serialization purposes only.

}; // class la_logical_port_scheduler_impl

} // namespace silicon_one

#endif // __LA_LOGICAL_PORT_SCHEDULER_IMPL_H__
