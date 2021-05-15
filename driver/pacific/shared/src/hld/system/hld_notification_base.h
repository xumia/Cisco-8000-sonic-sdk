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

#ifndef __HLD_NOTIFICATION_BASE_H__
#define __HLD_NOTIFICATION_BASE_H__

#include "api/system/la_device.h"
#include "api/types/la_notification_types.h"
#include "common/bit_vector.h"
#include "common/pipe.h"
#include "common/task_scheduler.h"
#include "hld_types_fwd.h"
#include "lld/interrupt_tree.h"

#include <atomic>
#include <chrono>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <thread>

namespace silicon_one
{

class la_device_impl;
class la_mac_port_base;

class hld_notification_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum class poll_interval_e { POLL_INTERVAL_SLOW, POLL_INTERVAL_FAST };

    /// @brief c'tor
    explicit hld_notification_base(const la_device_impl_wptr& device);

    virtual ~hld_notification_base(){};

    /// @brief Initialize internal objects and load the interrupt tree
    ///
    /// @return     Status code.
    virtual la_status initialize() = 0;

    /// @brief Get la_device.
    const la_device* get_device() const;

    /// @brief Register notifications and interrupts pollers.
    void register_pollers();

    /// @brief Start worker threads.
    ///
    /// @return     Status code.
    la_status start();

    /// @brief Stop worker threads.
    void stop();

    /// @brief Create two pipes for critical and normal notifications.
    ///
    /// @param[in]  mask                Bit mask of notification types.
    /// @param[out] fdr_critical_out    File descriptor for the read end of the pipe.
    /// @param[out] fdr_normal_out      File descriptor for the read end of the pipe.
    ///
    /// @return     Status code.
    la_status open_notification_pipes(int mask, int& out_fdr_critical, int& out_fdr_normal);

    /// @brief Close notification pipes.
    ///
    /// @return     Status code.
    la_status close_notification_pipes();

    enum class notification_pipe_e { CRITICAL = 0, NORMAL, LAST };

    /// @brief  Send notification upstream on a NORMAL pipe.
    ///
    /// @param[in]  desc Notification descriptor.
    ///
    /// @return     Status code.
    la_status notify(const la_notification_desc& desc);

    /// @brief  Send notification upstream on a specified pipe.
    ///
    /// @param[in]  desc    Notification descriptor.
    /// @param[in]  pipe_e  Notification pipe type.
    ///
    /// @return     Status code.
    la_status notify(const la_notification_desc& desc, notification_pipe_e pipe_e);

    /// @brief  Get a pointer to the internal interrupt_tree object.
    ///
    /// @return     Pointer to interrupt_tree.
    interrupt_tree* get_interrupt_tree();

    // We store poll callbacks in std::list.
    // Addition and removal of elements in std::list does not affect iterators and references.
    // Hence, list::iterator can be used as a "handle".
    using poll_cb = std::function<void()>;
    /// @brief  Register poll callback.
    ///
    /// @param[in]  cb              Callback function.
    /// @param[in]  poll_interval   Poll interval type.
    ///
    /// @return     Handle that should be used to unregister the callback.
    task_scheduler::task_handle register_poll_cb(poll_cb cb, hld_notification_base::poll_interval_e poll_interval);

    /// @brief  Register poll callback.
    ///
    /// @param[in]  cb             Callback function.
    /// @param[in]  poll_interval  Time beetwen two poll_cb calls.
    ///
    /// @return     Handle that should be used to unregister the callback.
    task_scheduler::task_handle register_poll_cb(poll_cb cb, std::chrono::milliseconds poll_interval);

    /// @brief  Get poll interval.
    ///
    /// @param[in]  Interval type.
    /// @param[out] Interval time in microseconds.
    ///
    void get_poll_interval(hld_notification_base::poll_interval_e type, std::chrono::milliseconds& interval);

    /// @brief  Unregister poll callback.
    ///
    /// @param[in]  handle  Handle that was returned by poll_register().
    void unregister_poll_cb(task_scheduler::task_handle handle);

    /// @brief  Unregister all poll callbacks.
    ///
    void unregister_all_poll_cbs();

    /// @brief Set thread name
    ///
    /// @param[in] native_thread  Thread for which the name should be set.
    /// @param[in] device         Device to which the thread belongs.
    /// @param[in] suffix         Suffix to be added at the end of thread name.
    static la_status set_thread_name(const std::thread::native_handle_type native_thread,
                                     const la_device_id_t device_id,
                                     const char* suffix);

    /// @brief Handle pending MSI interrupts
    /// Useful for warm boot flow to handle interrupts arrived while SDK is down.
    void handle_pending_msi_interrupts();

    void poll_npu_host_events();

protected:
    using pipe_uptr = std::unique_ptr<silicon_one::pipe>;

    std::array<pipe_uptr, (int)notification_pipe_e::LAST> m_notification_pipes;
    std::array<size_t, (int)notification_pipe_e::LAST> m_notification_pipes_errors;

    // The mask remembers which notifications should be raised.
    int m_notify_mask;

    struct worker {
        std::thread th;
        silicon_one::pipe self_pipe;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(worker)
    using worker_uptr = std::unique_ptr<worker>;

    /// @brief Task scheduler. Periodically calls scheduled callbacks.
    task_scheduler m_task_scheduler;

    virtual void init_static_mapping(const la_device_impl_wptr& la_device, vector_alloc<lld_memory_scptr>& out_vect) const = 0;

    worker_uptr create_worker(void (hld_notification_base::*func)(worker* w), const char* name);
    void destroy_worker(worker& w);

    // Interrupt worker, listens to interrupts from LLD, handles them and dispatches upstream notifications.
    worker_uptr m_worker_interrupt;
    void worker_interrupt_thread(worker* w);

    // Hotplug and AER handling helpers
    void handle_pci_event(int pci_event_fd);

    // Interrupt handling helpers
    void handle_lld_interrupt(int interrupt_fd, size_t interrupt_width_bytes);
    void do_handle_lld_interrupt(interrupt_tree::cause_bits& cause_bits);

    virtual bool is_msi_clear() = 0;

    void handle_max_counter_overflow_interrupt(const interrupt_tree::cause_bits& max_counter_group);
    void handle_mem_protect(const interrupt_tree::node_wcptr& node);
    void handle_link_down(const la_mac_port_base_wptr& mac_port, const interrupt_tree::bit_scptr& bit);
    void handle_link_error(const la_mac_port_base_wcptr& mac_port, const interrupt_tree::cause_bits& cause_bits);
    void handle_other(const interrupt_tree::bit_scptr& bit);
    virtual void handle_credit_grant_dest_dev_unreachable(const interrupt_tree::cause_bits& cause_bits);
    virtual void handle_queue_aged_out(const interrupt_tree::bit_scptr& bit);
    void handle_lpm_sram_mem_protect(const interrupt_tree::bit_scptr& lpm_sram_bit);
    void handle_mmu_has_error_buffer(const interrupt_tree::bit_scptr& bit);

    void notify_mem_protect(const interrupt_tree::mem_protect_error& error);
    void notify_other(const interrupt_tree::bit_scptr& cause_bit);

    // Poll helpers
    enum {
        POLL_INTERVAL_MILLISECONDS_DEFAULT = 100,    ///< Default poll interval in mSec - 100miliSec
        POLL_FAST_INTERVAL_MILLISECONDS_DEFAULT = 3, ///< Default fast poll interval in uSec - 3miliSec
        THREAD_NAME_MAX_SIZE = 15
    };

    /// @brief Checks pci state. If pci fails it unschedules slow_poll_function and fast_poll_function.
    void unschedule_polling_tasks_if_pci_unaccessible();

    la_device_impl_wptr m_device;
    interrupt_tree_wptr m_interrupt_tree;
    std::atomic<la_notification_id_t> m_notification_id;

    interrupt_tree::time_point m_next_restore_interrupt_masks;
    interrupt_tree::time_point m_next_reset_interrupt_counters;
    interrupt_tree::time_point m_next_poll_non_wired_interrupts;

    // Find a registered MAC port given an interrupt bit.
    la_mac_port_base_wptr find_mac_port(const interrupt_tree::bit_scptr& cause_bit) const;

    // Map block_id -> serdes location
    struct mac_pool_serdes_base {
        la_slice_id_t slice_i;
        la_ifg_id_t ifg_i;
        uint32_t serdes_base;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(mac_pool_serdes_base)
    std::map<la_block_id_t, mac_pool_serdes_base> m_mac_pool_serdes_bases;

    // Get slice/ifg/serdes ids given an interrupt bit.
    bool get_mac_port_ids(const interrupt_tree::bit_scptr& cause_bit,
                          la_slice_id_t& out_slice,
                          la_ifg_id_t& out_ifg,
                          la_uint_t& out_serdes) const;

    struct interrupt_groups {
        // Group mem_protect interrupts by CIF block.
        std::set<interrupt_tree::node_scptr> mem_protect_nodes;

        // Group LPM and shared-sram ECC error bits.
        interrupt_tree::cause_bits lpm_sram_mem_protect;

        // Group link_down interrupts by MAC port.
        std::map<la_mac_port_base_wptr, interrupt_tree::bit_scptr> link_down_ports;

        // Group link_error interrupts by MAC port.
        std::map<la_mac_port_base_wptr, interrupt_tree::cause_bits> link_error_ports;

        interrupt_tree::cause_bits max_counter_group;

        interrupt_tree::cause_bits credit_dev_unreachable;

        interrupt_tree::cause_bits queue_aged_out;

        interrupt_tree::cause_bits mmu_has_error_buffer;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(interrupt_groups)

    // Insert a single cause 'bit' to a group.
    // Return 'true' if inserted, 'false' if not.
    bool insert_cause_to_group(const interrupt_tree::bit_scptr& bit, interrupt_groups& out);

    // Split a list of interrupt cause bits to groups.
    void split_interrupt_causes(interrupt_tree::cause_bits& bits, interrupt_groups& out);

    void periodic_restore_interrupt_masks();
    void periodic_reset_interrupt_counters();
    void periodic_poll_non_wired_interrupts();
    void periodic_poll_msi_interrupts();

    bool is_mem_protect_fixable(const interrupt_tree::mem_protect_error& e) const;

    bool mem_protect_quirk_is_fixable(const interrupt_tree::mem_protect_error& e) const;
    bool mem_protect_quirk_should_notify(const interrupt_tree::mem_protect_error& e) const;
    bool mem_protect_quirk_soft_action(const interrupt_tree::mem_protect_error& e,
                                       la_notification_action_e& action,
                                       uint32_t& action_threshold) const;

    // Check if PCI interface accessible and send notification about it
    bool check_pci_accessible();

    hld_notification_base() = default; // For serialization puposes only.
};

} // namespace silicon_one
#endif
