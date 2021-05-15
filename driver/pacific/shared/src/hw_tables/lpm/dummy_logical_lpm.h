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

#ifndef __LEABA_DUMMY_LOGICAL_LPM_H__
#define __LEABA_DUMMY_LOGICAL_LPM_H__

#include "hw_tables/logical_lpm.h"

namespace silicon_one
{

/// @brief Empty logical LPM interface implementation.
class dummy_logical_lpm : public logical_lpm
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // Lifecycle
    /// @brief Construct an empty logical LPM.
    ///
    /// @param[in]      ldevice                       Low level device to write to.
    explicit dummy_logical_lpm(const ll_device_sptr& ldevice);

    /// @brief Logical LPM destructor.
    ~dummy_logical_lpm();

    // dummy_logical_lpm API-s
    const ll_device_sptr& get_ll_device() const override;
    la_status insert(const lpm_key_t& key, lpm_payload_t payload) override;
    la_status remove(const lpm_key_t& key) override;
    la_status modify(const lpm_key_t& key, lpm_payload_t payload) override;
    la_status update(const lpm_action_desc_vec_t& actions, size_t& out_count_success) override;
    la_status lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload) const override;
    lpm_core_scptr get_core(size_t idx) const override;
    bucketing_tree_scptr get_tree() const override;
    size_t get_num_cores() const override;
    vector_alloc<size_t> get_cores_utilization() const override;
    void set_rebalance_interval(size_t num_of_updates) override;
    size_t get_rebalance_interval() const override;
    void set_rebalance_start_fairness_threshold(double threshold) override;
    double get_rebalance_start_fairness_threshold() const override;
    void set_rebalance_end_fairness_threshold(double threshold) override;
    double get_rebalance_end_fairness_threshold() const override;
    void set_max_retries_on_fail(size_t max_retries) override;
    size_t get_max_retries_on_fail() override;
    la_status rebalance() override;
    size_t get_core_index_by_group(size_t group_index) const override;
    const lpm_distributor& get_distributer() const override;
    size_t max_size() const override;
    void lpm_hbm_collect_stats() override;
    void lpm_hbm_do_caching() override;
    void unmask_and_clear_l2_ecc_interrupt_registers() const override;
    la_status set_resource_monitor(const resource_monitor_sptr& monitor) override;
    la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const override;
    size_t size() const override;
    la_status save_state(std::string file_name) const override;
    la_status get_prefixes_statistics(std::string file_name) const override;
    la_status load_state(const std::string& file_name) override;
    size_t get_physical_usage(lpm_ip_protocol_e table_type, size_t num_of_table_logical_entries) const override;
    size_t get_available_entries(lpm_ip_protocol_e table_type) const override;

private:
    dummy_logical_lpm() = default; // allowed only for serialization purposes.

    // Members
    ll_device_sptr m_ll_device;                     ///< ll_device this LPM belongs to.
    std::unique_ptr<lpm_distributor> m_distributor; ///< Distributor TCAM.
};

} // namespace silicon_one

#endif // __LEABA_DUMMY_LOGICAL_LPM_IMPL_H__
