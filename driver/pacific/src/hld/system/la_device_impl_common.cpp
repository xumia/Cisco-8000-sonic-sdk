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

#include "api_tracer.h"
#include "common/la_lock_guard.h"
#include "common/logger.h"
#include "hld_types.h"
#include "la_device_impl.h"
#include "system/la_remote_device_base.h"
#include "system/la_remote_port_impl.h"
#include "system/slice_id_manager_base.h"
#include <string>

using namespace std;

std::recursive_mutex m_device_creation_mutex;
array<silicon_one::la_device_impl_sptr, silicon_one::la_device_impl::MAX_DEVICES> m_devices;

static la_status
do_create_device(const char* device_path,
                 la_device_id_t dev_id,
                 const silicon_one::la_platform_cbs& cbs,
                 silicon_one::la_device*& out_device)
{
    if (dev_id >= silicon_one::la_device_impl::MAX_DEVICES) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_devices[dev_id]) {
        return LA_STATUS_EEXIST;
    }

    if (device_path == nullptr) {
        return LA_STATUS_EINVAL;
    }

    silicon_one::device_simulator* simulator = nullptr;

    // Create NSIM simulator client, based on device path.
    la_status rc = silicon_one::la_device_impl::create_nsim_simulator_client(device_path, simulator);
    return_on_error(rc);

    bool use_filtered = true;
    silicon_one::ll_device_sptr ldevice = silicon_one::ll_device::create(dev_id, device_path, simulator, cbs, use_filtered);

    if (!ldevice) {
        return LA_STATUS_ERESOURCE;
    }

    silicon_one::la_device_impl_sptr device = std::make_shared<silicon_one::la_device_impl>(ldevice);
    if (!device) {
        return LA_STATUS_ERESOURCE;
    }
    la_status status = device->pre_initialize();
    return_on_error(status);

    bool is_reset;
    status = ldevice->get_core_reset(is_reset);
    return_on_error(status);

    if (is_reset) {
        status = device->do_write_persistent_token(0 /*token - init value expected after a power cycle*/);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }
    }

    device->create_resource_manager(ldevice);
    m_devices[dev_id] = device;

    out_device = device.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_create_device(const char* device_path, la_device_id_t dev_id, silicon_one::la_device*& out_device)
{
    // Cannot use start_api_call(..) here as device object is not created yet.
    silicon_one::la_lock_guard<std::recursive_mutex> lock(m_device_creation_mutex, dev_id);
    log_debug(API, "%s(device_path='%s' dev_id=%u) #SDK version is %s#", __func__, device_path, dev_id, la_get_version_string());

    silicon_one::la_platform_cbs cbs = {.user_data = 0,
                                        .i2c_register_access = nullptr,
                                        .dma_alloc = nullptr,
                                        .dma_free = nullptr,
                                        .open_device = nullptr,
                                        .close_device = nullptr};

    la_status rc = do_create_device(device_path, dev_id, cbs, out_device);

    if (rc != LA_STATUS_SUCCESS) {
        // log flushing mechanism might have not been started.
        silicon_one::la_flush_log();
    }

    return rc;
}

la_status
la_create_device(const char* device_path,
                 la_device_id_t dev_id,
                 const silicon_one::la_platform_cbs& cbs,
                 silicon_one::la_device*& out_device)
{
    // Cannot use start_api_call(..) here as device object is not initialized yet.
    silicon_one::la_lock_guard<std::recursive_mutex> lock(m_device_creation_mutex, dev_id);
    log_debug(API,
              "%s(device_path='%s' dev_id=%u cbs=%s) #SDK version is %s#",
              __func__,
              device_path,
              dev_id,
              get_value_string(cbs).c_str(),
              la_get_version_string());

    la_status rc = do_create_device(device_path, dev_id, cbs, out_device);

    if (rc != LA_STATUS_SUCCESS) {
        // log flushing mechanism might have not been started.
        silicon_one::la_flush_log();
    }

    return rc;
}

la_status
la_destroy_device(silicon_one::la_device* device)
{
    if (!device) {
        log_err(API, "%s: NULL device.", __func__);
        return LA_STATUS_EINVAL;
    }

    la_device_id_t dev_id = device->get_id();

    silicon_one::la_lock_guard<std::recursive_mutex> lock(m_device_creation_mutex, dev_id);

    log_debug(API, "%s(device= %s)#dev_id=%u#", __func__, get_value_string(device).c_str(), dev_id);
    auto status = m_devices[dev_id]->destroy();
    return_on_error(status);
    m_devices[dev_id].reset();

    // Log flushing task is stopped, need to flush expicitly.
    silicon_one::la_flush_log();

    return LA_STATUS_SUCCESS;
}

silicon_one::la_device*
la_get_device(la_device_id_t dev_id)
{
    if (dev_id >= m_devices.size()) {
        return nullptr;
    }

    return m_devices[dev_id].get();
}

const char*
la_get_version_string()
{
    return STRINGIFY(VERSION);
}

namespace silicon_one
{

la_device_impl::save_state_runtime::save_state_runtime() : period(std::chrono::milliseconds(0)), thread_running(false)
{
}

la_status
la_device_impl::set_int_tck_frequency(int32_t property_value)
{
    dassert_crit(m_init_phase == init_phase_e::CREATED);

    if ((property_value < MIN_TCK_FREQUENCY) || (property_value > MAX_TCK_FREQUENCY)) {
        log_err(HLD,
                "%s: TCK_FREQUENCY=%d MHz is not in the allowed range [%d:%d] MHz",
                __func__,
                property_value,
                MIN_TCK_FREQUENCY,
                MAX_TCK_FREQUENCY);
        return LA_STATUS_EOUTOFRANGE;
    }

    m_tck_frequency_mhz = property_value;

    log_info(HLD, "TCK frequency is set to %d MHz", property_value);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_periodic_save_state_period(const std::chrono::milliseconds period)
{
    start_api_call("periodic_save_state_period=", period.count());

    // Map negative values to zero because they have the same logical meaning, to avoid any potential bugs when using the comparison
    // operators.
    std::chrono::milliseconds period_normalized(period);
    if (period.count() < 0) {
        period_normalized = std::chrono::milliseconds(0);
    }

    if (period_normalized.count() == m_save_state_runt.period.count()) {
        return LA_STATUS_SUCCESS;
    }

    if (m_save_state_runt.param_initialized == false) {
        log_warning(API,
                    "%s, Warning, the parameters for the periodic save state have not been initialized. And you are turning "
                    "periodic save state on.",
                    __func__);
    }

    m_save_state_runt.period = period_normalized;

    if (m_save_state_runt.task_handle != task_scheduler::INVALID_TASK_HANDLE) {
        m_notification->unregister_poll_cb(m_save_state_runt.task_handle);
    }

    if (period_normalized.count() != 0) {
        m_save_state_runt.task_handle
            = m_notification->register_poll_cb([&]() { periodic_save_state(); }, m_save_state_runt.period);

        if (m_save_state_runt.task_handle == task_scheduler::INVALID_TASK_HANDLE) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::set_periodic_save_state_parameters(const save_state_options& options, const std::string& file_name_prefix)
{
    start_api_call("periodic_save_state_option=", options, ", file_name_prefix=", file_name_prefix);

    // Sanitize the file name prefix. This should probably be in its own function.
    const char* input_char_array = file_name_prefix.c_str();

    const char* indx = strrchr(input_char_array, '/');

    int n = file_name_prefix.length();

    char file_path[PATH_MAX];
    char file_name_resolved[PATH_MAX];

    if (indx != nullptr) {
        n = indx - input_char_array;
        strncpy(file_path, input_char_array, n + 1);
        file_path[n + 1] = '\0';
    } else {
        strcpy(file_path, input_char_array);
    }

    char* rc = realpath(file_path, file_name_resolved);

    if (rc == nullptr) {
        log_err(API,
                "%s, Unable to set periodic save state parameters, file name: \"%s\" format incorrect: %s.\n",
                __func__,
                file_name_prefix.c_str(),
                strerror(errno));
        return LA_STATUS_EEXIST;
    }

    strcat(file_name_resolved, indx);

    m_save_state_runt.options = options;
    m_save_state_runt.file_name_prefix = file_name_resolved;
    m_save_state_runt.param_initialized = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_periodic_save_state_period(std::chrono::milliseconds& out_period) const
{
    start_api_getter_call();

    out_period = m_save_state_runt.period;
    if (out_period.count() < 0) {
        out_period = std::chrono::milliseconds(0);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_periodic_save_state_parameters(save_state_options& out_options, std::string& out_file_name_prefix) const
{
    start_api_getter_call();

    if (m_save_state_runt.param_initialized == false) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    out_options = m_save_state_runt.options;
    out_file_name_prefix = m_save_state_runt.file_name_prefix;

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::periodic_save_state()
{
    if (m_save_state_runt.thread_running) {
        log_warning(API, "%s: previous call to save_state(..) has not finished yet. Skiping this save_state.", __func__);
        return;
    }

    if (m_save_state_runt.save_state_status != LA_STATUS_SUCCESS) {
        log_err(API,
                "%s: previous call to save_state(..) returned error: %s.",
                __func__,
                m_save_state_runt.save_state_status.message().c_str());
    }

    m_save_state_runt.thread_running = true;
    m_save_state_runt.worker_thread = std::thread(&la_device_impl::save_state_thread, this); //, this, init_function);
    m_save_state_runt.worker_thread.detach();
}

la_status
la_device_impl::save_state_thread()
{
    la_device::save_state_options options;
    std::string file_name;

    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        options = m_save_state_runt.options;
        file_name = m_save_state_runt.file_name_prefix;
    }

    file_name += "_device_";
    file_name += std::to_string(static_cast<int>(get_id()));

    char time_stamp[64];
    add_timestamp(time_stamp, sizeof(time_stamp));
    file_name += "_";
    file_name += time_stamp;

    int property = 0;
    get_int_property(la_device_property_e::MAX_NUMBER_OF_PERIODIC_SAVE_STATE_FILES, property);

    size_t max_number_of_files = property;

    size_t current_number_of_files = m_save_state_runt.old_file_names.size();

    while (current_number_of_files != 0 && current_number_of_files >= max_number_of_files) {
        std::string file_to_delete = *(m_save_state_runt.old_file_names.begin());

        m_save_state_runt.old_file_names.pop_front();

        auto rc = remove(file_to_delete.c_str());
        if (rc == 0) {
            log_info(HLD, "%s, unable to delete old state file: %s", __func__, file_to_delete.c_str());
        }

        current_number_of_files--;
    }

    auto rc = save_state(options, file_name);

    if (rc == LA_STATUS_SUCCESS) {
        m_save_state_runt.old_file_names.push_back(file_name);
    }

    m_save_state_runt.save_state_status = rc;

    m_save_state_runt.thread_running = false;

    return rc;
}

bool
la_device_impl::is_emulated_device() const
{
    return m_device_properties[(int)la_device_property_e::EMULATED_DEVICE].bool_val;
}

bool
la_device_impl::is_simulated_or_emulated_device() const
{
    return (is_simulated_device() || is_emulated_device());
}

la_status
la_device_impl::reconnect()
{
    la_status stat = initialize_first(false);
    return_on_error(stat);
    // We do not want to register this API call in the reconnect_metadata.
    // Acquire API lock directly and avoid the generic book keeping of API calls
    // that is done in start_api_call().
    api_lock_guard<std::recursive_mutex> lock(this, __func__, true /* read_only */);

    bool ignore_in_flight = false;
    la_status rc = get_bool_property(la_device_property_e::RECONNECT_IGNORE_IN_FLIGHT, ignore_in_flight);
    return_on_error(rc);

    log_debug(API, "la_device_impl(oid=%u)::%s()#ignore_in_flight= %d#", get_id(), __func__, ignore_in_flight);

    rc = m_reconnect_handler->reconnect(ignore_in_flight);
    return_on_error(rc);

    rc = start_notifications();
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::disconnect()
{
    log_debug(API, "la_device_impl(oid=%u)::%s()", get_id(), __func__);

    {
        // Acquire API lock to serialize set_write_to_device() with API calls.
        api_lock_guard<std::recursive_mutex> lock(this, __func__, true /* read_only */);
        if (m_disconnected) {
            return;
        }

        m_ll_device->set_write_to_device(false);
        m_disconnected = true;
    }
    // API lock is released.

    // Stop pollers, state machines, interrupt handling etc.
    // Must be called outside of API lock.
    // m_notification->stop() blocks until la_device's worker threads terminate.
    m_notification->stop();
}

la_status
la_device_impl::get_fuse_userbits(std::vector<uint32_t>& out_fuse_userbits) const
{
    start_api_getter_call();
    for (size_t i = 0; i < NUMBER_OF_FUSE_REGISTERS; ++i) {
        bit_vector bv = m_fuse_userbits.bits_from_lsb(32 * i, 32);
        out_fuse_userbits.push_back(bv.get_value());
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_heartbeat(la_heartbeat_t& out_heartbeat) const
{
    start_api_getter_call();
    out_heartbeat = m_heartbeat;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::acquire_device_lock(bool blocking)
{
    if (blocking) {
        m_mutex.lock();
        return LA_STATUS_SUCCESS;
    }

    bool locked = m_mutex.try_lock();

    return (locked ? LA_STATUS_SUCCESS : LA_STATUS_EAGAIN);
}

void
la_device_impl::release_device_lock()
{
    m_mutex.unlock();
}

la_status
la_device_impl::open_notification_fds(int mask, int& out_fd_critical, int& out_fd_normal)
{
    start_api_call_allow_warm_boot("mask=", mask);

    return m_notification->open_notification_pipes(mask, out_fd_critical, out_fd_normal);
}

la_status
la_device_impl::close_notification_fds()
{
    start_api_call_allow_warm_boot("");

    return m_notification->close_notification_pipes();
}

void
la_device_impl::do_poll_fe_routing_table_npl()
{
    log_debug(HLD, "la_device_impl::poll_fe_routing_table_npl() begins.");

    const auto& table(m_tables.frm_db_fabric_routing_table);
    npl_frm_db_fabric_routing_table_t::key_type k;
    npl_frm_db_fabric_routing_table_t::value_type v;
    npl_frm_db_fabric_routing_table_t::entry_pointer_type tmp_fe_routing_table[MAX_DEVICES];

    size_t num_entries = table->get_entries(tmp_fe_routing_table, MAX_DEVICES);
    dassert_crit(num_entries <= MAX_DEVICES);

    bool did_links_change = false;
    la_device_id_vec_t changed_devices;

    for (size_t i = 0; i < num_entries; i++) {
        std::vector<size_t> current_links_to_device;
        const npl_fabric_port_can_reach_device_e* table_data
            = tmp_fe_routing_table[i]->value().payloads.frm_db_fabric_routing_table_result.fabric_routing_table_data;
        for (int pos = 0; pos < NUM_FABRIC_PORTS_IN_DEVICE; pos++) {
            if (table_data[pos] == NPL_FABRIC_PORT_CAN_REACH_DEVICE_TRUE) {
                current_links_to_device.push_back(pos);
            }
        }
        la_device_id_t dev_id = tmp_fe_routing_table[i]->key().egress_device_id;
        if (current_links_to_device != m_device_to_links[dev_id]) {
            did_links_change = true;
            m_device_to_links[dev_id] = current_links_to_device;
            changed_devices.push_back(dev_id);
        }
    }

    if (did_links_change) {
        update_on_fabric_links_changed(changed_devices);
    }
}

void
la_device_impl::update_current_links_state_and_handle_link_changes(const bit_vector& tmp_fe_routing_table,
                                                                   const size_t line_width_total)
{
    bool did_links_change = false;
    la_device_id_vec_t changed_devices;

    for (la_device_id_t dev_id = 0; dev_id < MAX_DEVICES; dev_id++) {
        std::vector<size_t> current_links_to_device;
        for (int pos = 0; pos < NUM_FABRIC_PORTS_IN_DEVICE; pos++) {
            if (tmp_fe_routing_table.bit(dev_id * line_width_total * bit_utils::BITS_IN_BYTE + pos)) {
                current_links_to_device.push_back(pos);
            }
        }
        if (current_links_to_device != m_device_to_links[dev_id]) {
            did_links_change = true;
            m_device_to_links[dev_id] = current_links_to_device;
            changed_devices.push_back(dev_id);
        }
    }

    if (did_links_change) {
        update_on_fabric_links_changed(changed_devices);
    }
}

la_status
la_device_impl::configure_fe_broadcast_bmp(const size_t fe_broadcast_bmp_entries)
{
    // 1. Compute LCM (lowest common multiplier) of connected LC's links numbers.
    // 2. Fill LCM entries in the table, such that i-th entry chooses the i-th link of each device (modulo the device's links
    // number)
    // In this way, we ensure that links of the same device appear in equal number of entries.
    // (Links of different devices may appear in different number of entries.)
    // For example, if this FE is connected (only) to two LCs: LC1 with 2 links {0,1} and LC2 with 3 links {2,3,4}, then:
    // 1. LCM(2,3) = 6, so we will configure 6 entries (lines) of the table.
    // 2. The entries will be as follows:
    // 2.0. '10100' - we choose link at index 0 (0%2) of LC1 (which is link 0), and link at index 0 (0%3) for LC2 (which is link 2)
    // 2.1. '01010' - we choose link at index 1 (1%2) of LC1 (which is link 1), and link at index 1 (1%3) for LC2 (which is link 3)
    // 2.2. '10001' - we choose link at index 0 (2%2) of LC1 (which is link 0), and link at index 2 (2%3) for LC2 (which is link 4)
    // 2.3. '01100' - we choose link at index 1 (3%2) of LC1 (which is link 1), and link at index 0 (3%3) for LC2 (which is link 2)
    // 2.4. '10010' - we choose link at index 0 (4%2) of LC1 (which is link 0), and link at index 1 (4%3) for LC2 (which is link 3)
    // 2.5. '01001' - we choose link at index 1 (5%2) of LC1 (which is link 1), and link at index 2 (5%3) for LC2 (which is link 4)
    size_t links_lcm = 1;
    for (la_device_id_t dev_id = 0; dev_id < MAX_DEVICES; dev_id++) {
        la_uint64_t dev_links_num = m_device_to_links[dev_id].size();
        if (dev_links_num == 0) {
            continue;
        }
        links_lcm = lcm(dev_links_num, links_lcm);
    }

    size_t num_entries_to_configure = std::min(links_lcm, fe_broadcast_bmp_entries);

    auto& table(m_tables.fe_broadcast_bmp_table);
    npl_fe_broadcast_bmp_table_t::key_type key;
    npl_fe_broadcast_bmp_table_t::value_type value;
    npl_fe_broadcast_bmp_table_t::entry_pointer_type dummy_entry;

    value.action = NPL_FE_BROADCAST_BMP_TABLE_ACTION_WRITE;

    for (size_t entry_idx = 0; entry_idx < num_entries_to_configure; entry_idx++) {
        bit_vector broadcast_entry(0, NUM_FABRIC_PORTS_IN_DEVICE);
        for (la_device_id_t dev_id = 0; dev_id < MAX_DEVICES; dev_id++) {
            size_t dev_links_num = m_device_to_links[dev_id].size();
            if (dev_links_num == 0) {
                continue;
            }
            size_t chosen_link_index = entry_idx % dev_links_num;
            broadcast_entry.set_bit(m_device_to_links[dev_id][chosen_link_index], 1);
        }

        key.random_bc_bmp_entry.rnd_entry = entry_idx;
        uint64_t* bits = (uint64_t*)broadcast_entry.byte_array();
        value.payloads.fe_broadcast_bmp_table_result.links_bmp[0] = bits[0];
        value.payloads.fe_broadcast_bmp_table_result.links_bmp[1] = bits[1];

        la_status status = table->set(key, value, dummy_entry);
        return_on_error(status);
    }

    la_status status = configure_fe_configurations_reg1(num_entries_to_configure);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_egress_multicast_fabric_replication_voq_set(la_voq_set*& out_voq_set) const
{
    start_api_getter_call();

    if (m_device_mode != device_mode_e::LINECARD) {
        return LA_STATUS_EINVAL;
    }

    out_voq_set = m_egress_multicast_fabric_replication_voq_set.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_remote_device(la_device_id_t remote_device_id,
                                     la_device_revision_e remote_device_revision,
                                     la_remote_device*& out_remote_device)
{
    start_api_call("remote_device_id=", remote_device_id, "remote_device_revision=", remote_device_revision);

    if (remote_device_id >= MAX_DEVICES) {
        return LA_STATUS_EINVAL;
    }

    if (remote_device_revision > la_device_revision_e::LAST) {
        return LA_STATUS_EINVAL;
    }

    auto remote_device = std::make_shared<la_remote_device_base>(shared_from_this());
    la_object_id_t oid;
    la_status status = register_object(remote_device, oid);
    return_on_error(status);
    status = remote_device->initialize(oid, remote_device_id, remote_device_revision);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    out_remote_device = remote_device.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_remote_device(const la_remote_device_base_wptr& remote_device)
{
    if (remote_device == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (remote_device->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = remote_device->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::create_remote_port(la_remote_device* remote_device,
                                   la_slice_id_t remote_slice_id,
                                   la_ifg_id_t remote_ifg_id,
                                   la_uint_t remote_first_serdes_id,
                                   la_uint_t remote_last_serdes_id,
                                   la_mac_port::port_speed_e remote_port_speed,
                                   la_remote_port*& out_remote_port)
{
    start_api_call("remote_device=",
                   remote_device,
                   "remote_slice_id=",
                   remote_slice_id,
                   "remote_ifg_id=",
                   remote_ifg_id,
                   "remote_first_serdes_id=",
                   remote_first_serdes_id,
                   "remote_last_serdes_id=",
                   remote_last_serdes_id,
                   "remote_port_speed=",
                   remote_port_speed);

    if (remote_device == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (remote_device->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_device_id_t remote_device_id = remote_device->get_remote_device_id();
    if (remote_device_id >= MAX_DEVICES) {
        return LA_STATUS_EINVAL;
    }

    if (remote_slice_id >= MAX_REMOTE_SLICE) {
        return LA_STATUS_EINVAL;
    }
    if (remote_ifg_id >= NUM_IFGS_PER_SLICE) {
        return LA_STATUS_EINVAL;
    }

    if (remote_first_serdes_id > remote_last_serdes_id) {
        return LA_STATUS_EINVAL;
    }

    if (remote_port_speed == la_mac_port::port_speed_e::E_800G) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    // TODO - verify the remote port is unique in device location

    auto remote_port = std::make_shared<la_remote_port_impl>(shared_from_this());

    la_object_id_t oid;
    la_status status = register_object(remote_port, oid);
    return_on_error(status);

    la_uint_t remote_first_pif_id = get_pif_from_serdes(remote_first_serdes_id);
    la_uint_t remote_last_pif_id = get_pif_from_serdes(remote_last_serdes_id);

    status = remote_port->initialize(oid,
                                     remote_device,
                                     remote_slice_id,
                                     remote_ifg_id,
                                     remote_first_serdes_id,
                                     remote_last_serdes_id,
                                     remote_first_pif_id,
                                     remote_last_pif_id,
                                     remote_port_speed);
    if (status != LA_STATUS_SUCCESS) {
        deregister_object(oid);
        return status;
    }

    // TODO - store the created remote ports, with device location info
    out_remote_port = remote_port.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::destroy_remote_port(const la_remote_port_impl_wptr& remote_port)
{
    if (remote_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (remote_port->get_device() != this) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = remote_port->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

void
la_device_impl::init_valid_ifgs_for_mcg_counters()
{
    // one ifg per slice
    // only network slices
    // only active slices
    // slice 0 ifg 1 - reserved for npu host port
    // slices 0,2,4 ifg 0 - reserved for pci ports

    for (la_slice_id_t slice : get_used_slices()) {
        if (!is_network_slice(slice)) {
            // fabric slice
            continue;
        }

        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            la_slice_ifg si = {.slice = slice, .ifg = ifg};
            if (m_slice_id_manager->is_slice_ifg_valid(si) != LA_STATUS_SUCCESS) {
                // inactive ifg
                continue;
            }

            if (((slice == 0) && (ifg == 1)) || // npu host port
                ((slice == 0) && (ifg == 0))
                || // pci port
                ((slice == 2) && (ifg == 0))
                ||                              // pci port
                ((slice == 4) && (ifg == 0))) { // pci port
                continue;
            }

            m_valid_ifgs_for_mcg_counters.push_back(si);
            // TODO is this restriction really needed?
            //            break; // one ifg per slice
        }
    }

    m_valid_ifg_for_mcg_counter_ptr = 0;
}

la_status
la_device_impl::get_next_ifg_for_mcg_counter(la_slice_ifg& out_slice_ifg)
{
    if (m_valid_ifgs_for_mcg_counters.size() == 0) {
        return LA_STATUS_ERESOURCE;
    }

    out_slice_ifg = m_valid_ifgs_for_mcg_counters[m_valid_ifg_for_mcg_counter_ptr];
    m_valid_ifg_for_mcg_counter_ptr += 1;
    m_valid_ifg_for_mcg_counter_ptr %= m_valid_ifgs_for_mcg_counters.size();
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_add_to_mc_copy_id_table(la_slice_id_t slice, npl_mc_copy_id_map_key_t key, npl_mc_copy_id_map_value_t value)
{
    auto& use_count_map(m_mc_copy_id_table_use_count[slice]);

    // A single entry in the table covers a range of AC ports
    auto it = use_count_map.find(key.cud_mapping_local_vars_mc_copy_id_17_12_);
    if (it != use_count_map.end()) {
        // An entry already exists. Just increment the use count
        (it->second)++;
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_tables.mc_copy_id_map[slice]);
    npl_mc_copy_id_map_entry_t* entry = nullptr;
    la_status status = table->insert(key, value, entry);
    return_on_error(status);

    use_count_map[key.cud_mapping_local_vars_mc_copy_id_17_12_] = 1;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_remove_from_mc_copy_id_table(la_slice_id_t slice, npl_mc_copy_id_map_key_t key)
{
    auto& use_count_map(m_mc_copy_id_table_use_count[slice]);

    // A single entry in the table covers a range of AC ports
    auto it = use_count_map.find(key.cud_mapping_local_vars_mc_copy_id_17_12_);
    if (it == use_count_map.end()) {
        log_err(HLD, "could not find key in map. slice=%d key=%lx", slice, key.cud_mapping_local_vars_mc_copy_id_17_12_);
        return LA_STATUS_EUNKNOWN;
    }

    (it->second)--;
    if (it->second != 0) {
        // The entry is still needed
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_tables.mc_copy_id_map[slice]);

    la_status status = table->erase(key);
    return_on_error(status);

    use_count_map.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::remove_from_mc_copy_id_table(la_slice_id_t slice, uint64_t mc_copy_id)
{
    npl_mc_copy_id_map_key_t key;
    key.cud_mapping_local_vars_mc_copy_id_17_12_ = bit_utils::get_bits(mc_copy_id, 17, 12);

    la_status status = do_remove_from_mc_copy_id_table(slice, key);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

const la_slice_id_vec_t&
la_device_impl::get_used_slices() const
{
    return m_slice_id_manager->get_used_slices_internal();
}

const la_slice_pair_id_vec_t&
la_device_impl::get_used_slice_pairs() const
{
    return m_slice_id_manager->get_used_slice_pairs_internal();
}

const slice_ifg_vec_t&
la_device_impl::get_used_ifgs() const
{
    return m_slice_id_manager->get_used_ifgs();
}

la_status
la_device_impl::set_resource_monitor(la_resource_descriptor::type_e resource_type, const resource_monitor_sptr& monitor)
{
    switch (resource_type) {
    case la_resource_descriptor::type_e::NEXT_HOP:
        m_resource_monitors.next_hop_resource_monitor = monitor;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_resource_monitor(la_resource_descriptor::type_e resource_type, resource_monitor_sptr& out_monitor) const
{
    switch (resource_type) {
    case la_resource_descriptor::type_e::NEXT_HOP:
        out_monitor = m_resource_monitors.next_hop_resource_monitor;
        break;

    default:
        return LA_STATUS_EUNKNOWN;
        break;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_npl_vlan_edit_command(const la_vlan_edit_command& edit_command, npl_ive_profile_and_data_t& npl_edit_command)
{
    // Rewrite flag is only valid when no pop/push operations occur.
    if (edit_command.pcpdei_rewrite_only && (edit_command.num_tags_to_pop != 0 || edit_command.num_tags_to_push != 0)) {
        return LA_STATUS_EINVAL;
    }

    const npl_vlan_edit_command_main_type_e main_type[la_vlan_edit_command::MAX_POP_OPERATIONS + 1]
                                                     [la_vlan_edit_command::MAX_PUSH_OPERATIONS + 1]
        = {{NPL_VLAN_EDIT_COMMAND_MAIN_OTHER, NPL_VLAN_EDIT_COMMAND_MAIN_OTHER, NPL_VLAN_EDIT_COMMAND_MAIN_PUSH_2},
           {NPL_VLAN_EDIT_COMMAND_MAIN_OTHER, NPL_VLAN_EDIT_COMMAND_MAIN_OTHER, NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2},
           {NPL_VLAN_EDIT_COMMAND_MAIN_OTHER, NPL_VLAN_EDIT_COMMAND_MAIN_OTHER, NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2}};

    const npl_vlan_edit_command_secondary_type_e secondary_type[la_vlan_edit_command::MAX_POP_OPERATIONS + 1]
                                                               [la_vlan_edit_command::MAX_PUSH_OPERATIONS + 1]
        = {{NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP, NPL_VLAN_EDIT_COMMAND_SECONDARY_PUSH_1, NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP},
           {NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_1,
            NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1,
            NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP},
           {NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_2,
            NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1,
            NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP}};

    if (edit_command.num_tags_to_pop > la_vlan_edit_command::MAX_POP_OPERATIONS
        || edit_command.num_tags_to_push > la_vlan_edit_command::MAX_PUSH_OPERATIONS) {
        return LA_STATUS_ERESOURCE;
    }

    // Ensure command is fully initialized.
    memset(&npl_edit_command, 0, sizeof(npl_edit_command));

    npl_edit_command.main_type = main_type[edit_command.num_tags_to_pop][edit_command.num_tags_to_push];
    npl_edit_command.vid1 = edit_command.tag0.tci.fields.vid;

    if (edit_command.num_tags_to_push == 2) {
        npl_edit_command.secondary_type_or_vid_2.vid2 = edit_command.tag1.tci.fields.vid;
        npl_edit_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type
            = static_cast<npl_vlan_edit_command_secondary_type_e>(0x0);
    } else {
        npl_edit_command.secondary_type_or_vid_2.vid2 = 0x0;

        if (edit_command.pcpdei_rewrite_only) {
            npl_edit_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type
                = NPL_VLAN_EDIT_COMMAND_SECONDARY_REMARK;

            return LA_STATUS_SUCCESS;
        }

        npl_edit_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type
            = secondary_type[edit_command.num_tags_to_pop][edit_command.num_tags_to_push];
    }

    if (edit_command.num_tags_to_push == 0) {
        return LA_STATUS_SUCCESS;
    }

    size_t tpid_profile_index;
    la_status status = update_tpid_table(edit_command, tpid_profile_index);

    return_on_error(status);

    npl_edit_command.prf = tpid_profile_index;
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::get_la_vlan_edit_command(const npl_ive_profile_and_data_t& npl_edit_command, la_vlan_edit_command& out_edit_command)
{
    out_edit_command.tag0.tci.fields.vid = npl_edit_command.vid1;
    out_edit_command.pcpdei_rewrite_only = false;

    if (npl_edit_command.main_type != npl_vlan_edit_command_main_type_e::NPL_VLAN_EDIT_COMMAND_MAIN_OTHER) {
        out_edit_command.num_tags_to_push = 2;
        out_edit_command.tag1.tci.fields.vid = npl_edit_command.secondary_type_or_vid_2.vid2;

        const la_uint_t tags_to_pop[npl_vlan_edit_command_main_type_e::NPL_VLAN_EDIT_COMMAND_MAIN_PUSH_2 + 1]
            = {[npl_vlan_edit_command_main_type_e::NPL_VLAN_EDIT_COMMAND_MAIN_OTHER] = 0,
               [npl_vlan_edit_command_main_type_e::NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_2_2] = 2,
               [npl_vlan_edit_command_main_type_e::NPL_VLAN_EDIT_COMMAND_MAIN_TRANSLATE_1_2] = 1,
               [npl_vlan_edit_command_main_type_e::NPL_VLAN_EDIT_COMMAND_MAIN_PUSH_2] = 0};

        out_edit_command.num_tags_to_pop = tags_to_pop[npl_edit_command.main_type];

    } else {
        out_edit_command.tag1.tci.fields.vid = 0;

        const std::pair<la_uint_t, la_uint_t>
            tags_to_pop_push[((int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1) + 1]
            = {[(int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP] = {0, 0},
               [(int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_REMARK] = {0, 0},
               [(int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_1] = {1, 0},
               [(int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_1_1] = {1, 1},
               [(int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_PUSH_1] = {0, 1},
               [(int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_POP_2] = {2, 0},
               [(int)npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_TRANSLATE_2_1] = {2, 1}};

        out_edit_command.num_tags_to_pop
            = tags_to_pop_push[(int)npl_edit_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type].first;
        out_edit_command.num_tags_to_push
            = tags_to_pop_push[(int)npl_edit_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type].second;

        if (npl_vlan_edit_command_secondary_type_e::NPL_VLAN_EDIT_COMMAND_SECONDARY_REMARK
            == npl_edit_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type) {
            out_edit_command.pcpdei_rewrite_only = true;
            return LA_STATUS_SUCCESS;
        }
    }

    la_status status = populate_vlan_edit_command_tpids(npl_edit_command.prf, out_edit_command);
    return status;
}

} // namespace silicon_one
