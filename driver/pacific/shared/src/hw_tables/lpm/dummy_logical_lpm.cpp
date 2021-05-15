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

#include "dummy_logical_lpm.h"
#include "lpm_distributor.h"

namespace silicon_one
{

logical_lpm_sptr
create_logical_lpm(const ll_device_sptr& ldevice)
{
    return std::make_shared<dummy_logical_lpm>(ldevice);
}

dummy_logical_lpm::dummy_logical_lpm(const ll_device_sptr& ldevice) : m_ll_device(ldevice)
{
    m_distributor.reset(nullptr);
}

dummy_logical_lpm::~dummy_logical_lpm()
{
}

const ll_device_sptr&
dummy_logical_lpm::get_ll_device() const
{
    return m_ll_device;
}

la_status
dummy_logical_lpm::insert(const lpm_key_t& key, lpm_payload_t payload)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::remove(const lpm_key_t& key)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::modify(const lpm_key_t& key, lpm_payload_t payload)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::update(const lpm_action_desc_vec_t& actions, size_t& out_count_success)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

size_t
dummy_logical_lpm::get_core_index_by_group(size_t group_index) const
{
    dassert_crit(false, "Should not get here");
    return 0;
}

const lpm_distributor&
dummy_logical_lpm::get_distributer() const
{
    dassert_crit(false, "Should not get here");
    return *(m_distributor);
}

lpm_core_scptr
dummy_logical_lpm::get_core(size_t idx) const
{
    return nullptr;
}

bucketing_tree_scptr
dummy_logical_lpm::get_tree() const
{
    return nullptr;
}

size_t
dummy_logical_lpm::get_num_cores() const
{
    dassert_crit(false, "Should not get here");
    return 0;
}

// Calculate number of entries in each core
vector_alloc<size_t>
dummy_logical_lpm::get_cores_utilization() const
{
    dassert_crit(false, "Should not get here");
    return vector_alloc<size_t>();
}

void
dummy_logical_lpm::set_rebalance_interval(size_t num_of_updates)
{
    dassert_crit(false, "Should not get here");
}

size_t
dummy_logical_lpm::get_rebalance_interval() const
{
    dassert_crit(false, "Should not get here");
    return 0;
}

void
dummy_logical_lpm::set_max_retries_on_fail(size_t max_retries)
{
    dassert_crit(false, "Should not get here");
}

void
dummy_logical_lpm::set_rebalance_start_fairness_threshold(double threshold)
{
    dassert_crit(false, "Should not get here");
}

double
dummy_logical_lpm::get_rebalance_start_fairness_threshold() const
{
    dassert_crit(false, "Should not get here");
    return 0;
}

void
dummy_logical_lpm::set_rebalance_end_fairness_threshold(double threshold)
{
    dassert_crit(false, "Should not get here");
}

double
dummy_logical_lpm::get_rebalance_end_fairness_threshold() const
{
    dassert_crit(false, "Should not get here");
    return 0;
}

size_t
dummy_logical_lpm::get_max_retries_on_fail()
{
    dassert_crit(false, "Should not get here");
    return 0;
}

la_status
dummy_logical_lpm::rebalance()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

void
dummy_logical_lpm::lpm_hbm_collect_stats()
{
    dassert_crit(false, "Should not get here");
}

void
dummy_logical_lpm::lpm_hbm_do_caching()
{
    dassert_crit(false, "Should not get here");
}

void
dummy_logical_lpm::unmask_and_clear_l2_ecc_interrupt_registers() const
{
    dassert_crit(false, "Should not get here");
}

size_t
dummy_logical_lpm::max_size() const
{
    return 0;
}

size_t
dummy_logical_lpm::size() const
{
    return 0;
}

la_status
dummy_logical_lpm::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::get_resource_monitor(resource_monitor_sptr& out_monitor) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::save_state(std::string file_name) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::get_prefixes_statistics(std::string file_name) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
dummy_logical_lpm::load_state(const std::string& file_name)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

size_t
dummy_logical_lpm::get_physical_usage(lpm_ip_protocol_e table_type, size_t num_of_table_logical_entries) const
{
    return 0;
}

size_t
dummy_logical_lpm::get_available_entries(lpm_ip_protocol_e table_type) const
{
    return 0;
}

} // namespace silicon_one
