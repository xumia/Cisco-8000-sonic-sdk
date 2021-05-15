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

#include "system/hld_notification_base.h"
#include "api/types/la_common_types.h"
#include "api/types/la_notification_types.h"
#include "api_tracer.h"
#include "common/device_id.h"
#include "common/file_utils.h"
#include "common/gen_utils.h"
#include "common/pipe.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/device_mem_structs.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/gibraltar_tree.h"
#include "lld/leaba_kernel_types.h"
#include "lld/ll_device.h"
#include "system/counter_manager.h"
#include "system/la_device_impl.h"
#include "system/la_hbm_handler_impl.h"
#include "system/la_mac_port_base.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_output_queue_scheduler_impl.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>

using namespace std;

namespace silicon_one
{

const la_device*
hld_notification_base::get_device() const
{
    return m_device.get();
}

void
thread_scheduler_init_function(const la_device_impl_wcptr& device)
{
    silicon_one::push_device_id(device->get_id());

    hld_notification_base::set_thread_name(pthread_self(), device->get_id(), "ts");
}

la_status
hld_notification_base::open_notification_pipes(int mask, int& out_fdr_critical, int& out_fdr_normal)
{
    if (!mask) {
        log_err(INTERRUPT, "%s: zero notification mask", __func__);
        return LA_STATUS_EINVAL;
    }

    if (m_notify_mask) {
        log_err(INTERRUPT, "%s: notification pipes are already open", __func__);
        return LA_STATUS_EEXIST;
    }

    log_debug(INTERRUPT, "%s: mask=0x%x", __func__, m_notify_mask);

    pipe_uptr critical_pipe = silicon_one::make_unique<silicon_one::pipe>();
    la_status rc = critical_pipe->open();
    return_on_error(rc);

    pipe_uptr normal_pipe = silicon_one::make_unique<silicon_one::pipe>();
    rc = normal_pipe->open();
    return_on_error(rc);

    // Pipe capacity: "man 7 pipe", section "Pipe capacity"
    // The depth of pipe is 1 page (4KB) on Linux < 2.6.11 or 16 pages (64KB) since Linux 2.6.11.
    // Since Linux 2.6.35 the capacity can be queried and set, and go beyond the default 64KB up to 1MB.

    // Set capacity to 1MB, ignore failure.
    critical_pipe->set_capacity(1024 * 1024);
    normal_pipe->set_capacity(1024 * 1024);

    // Set the "write" end of each pipe to non-blocking
    int fdw = critical_pipe->get_fdw();
    file_utils::fd_set_blocking(fdw, false /* blocking */);
    fdw = normal_pipe->get_fdw();
    file_utils::fd_set_blocking(fdw, false /* blocking */);

    out_fdr_critical = critical_pipe->get_fdr();
    out_fdr_normal = normal_pipe->get_fdr();

    m_notify_mask = mask;
    m_notification_pipes[(int)notification_pipe_e::CRITICAL] = std::move(critical_pipe);
    m_notification_pipes[(int)notification_pipe_e::NORMAL] = std::move(normal_pipe);

    log_debug(INTERRUPT, "%s: mask=0x%x, fdr_critical=%d, fdr_normal=%d", __func__, mask, out_fdr_critical, out_fdr_normal);

    return LA_STATUS_SUCCESS;
}

la_status
hld_notification_base::close_notification_pipes()
{
    m_notify_mask = 0;

    for (size_t i = 0; i < m_notification_pipes.size(); ++i) {
        m_notification_pipes[i] = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

hld_notification_base::hld_notification_base(const la_device_impl_wptr& la_device)
    : m_notification_pipes(),
      m_notify_mask(0),
      m_device(la_device),
      m_interrupt_tree(la_device->m_ll_device->get_interrupt_tree_sptr()),
      m_notification_id(0)
{
    m_notification_pipes_errors.fill(0);
}

void
hld_notification_base::register_pollers()
{
    register_poll_cb([&]() { periodic_restore_interrupt_masks(); }, hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
    register_poll_cb([&]() { periodic_reset_interrupt_counters(); }, hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
    register_poll_cb([&]() { periodic_poll_non_wired_interrupts(); }, hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
    register_poll_cb([&]() { unschedule_polling_tasks_if_pci_unaccessible(); },
                     hld_notification_base::poll_interval_e::POLL_INTERVAL_SLOW);
    register_poll_cb([&]() { periodic_poll_msi_interrupts(); }, hld_notification_base::poll_interval_e::POLL_INTERVAL_FAST);
}

la_status
hld_notification_base::start()
{
    // Always start the tasks scheduler thread.
    m_task_scheduler.spawn([=]() { thread_scheduler_init_function(m_device); });

    int pci_event_fd, interrupt_fd;
    size_t interrupt_width_bytes;
    m_device->m_ll_device->get_event_fds(pci_event_fd, interrupt_fd, interrupt_width_bytes);
    if (interrupt_fd < 0) {
        // Do not launch interrupt worker thread if there is no interrupt file descriptor.
        // pci_event_fd is optional.
        //
        // This is not an error. Error conditions are checked earlier at lld level.
        log_debug(INTERRUPT, "%s: no LLD interrupt fd", __func__);

        return LA_STATUS_SUCCESS;
    }

    m_worker_interrupt = create_worker(&hld_notification_base::worker_interrupt_thread, "inter");
    if (!m_worker_interrupt) {
        return LA_STATUS_EUNKNOWN;
    }

    auto now = chrono::steady_clock::now();
    int interval = 0;

    m_device->get_int_property(la_device_property_e::RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS, interval);
    m_next_restore_interrupt_masks = now + chrono::milliseconds(interval);

    m_device->get_int_property(la_device_property_e::RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS, interval);
    m_next_reset_interrupt_counters = now + chrono::seconds(interval);

    m_device->get_int_property(la_device_property_e::POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS, interval);
    m_next_poll_non_wired_interrupts = now + chrono::milliseconds(interval);

    return LA_STATUS_SUCCESS;
}

void
hld_notification_base::stop()
{
    if (m_worker_interrupt) {
        destroy_worker(*m_worker_interrupt);
    }
    m_task_scheduler.terminate();
}

hld_notification_base::worker_uptr
hld_notification_base::create_worker(void (hld_notification_base::*func)(worker*), const char* name)
{
    worker_uptr worker = silicon_one::make_unique<hld_notification_base::worker>();

    la_status rc = worker->self_pipe.open();
    if (rc) {
        log_err(INTERRUPT, "%s: failed to create a pipe", __func__);
        return nullptr;
    }

    worker->th = std::thread(func, this, worker.get());

    rc = set_thread_name(worker->th.native_handle(), m_device->get_id(), name);
    if (rc) {
        return nullptr;
    }

    return worker;
}

void
hld_notification_base::destroy_worker(hld_notification_base::worker& worker)
{
    // Wake up the thread and tell it to terminate
    uint8_t val = 1;
    worker.self_pipe.write(&val, sizeof(val));

    if (worker.th.joinable()) {
        worker.th.join();
    }
}

interrupt_tree*
hld_notification_base::get_interrupt_tree()
{
    return m_interrupt_tree.get();
}

// The worker thread listens to an interrupt from LLD, retrieves & parses Pacific interrupt tree,
// and, finally, pushes notifications to the uppper layer.
void
hld_notification_base::worker_interrupt_thread(hld_notification_base::worker* w)
{
    silicon_one::push_device_id(m_device->get_id());
    int pci_event_fd, interrupt_fd;
    size_t interrupt_width_bytes;
    m_device->m_ll_device->get_event_fds(pci_event_fd, interrupt_fd, interrupt_width_bytes);

    int self_pipe_fd = w->self_pipe.get_fdr();

    // Listen on self-pipe, LLD interrupt and PCI event (optional).
    enum { SELF_PIPE = 0, INTERRUPT_FD, PCI_EVENT_FD };
    struct pollfd fds[] = {
            [SELF_PIPE] = {.fd = self_pipe_fd, .events = POLLIN, .revents = 0},
            [INTERRUPT_FD] = {.fd = interrupt_fd, .events = POLLIN, .revents = 0},
            [PCI_EVENT_FD] = {.fd = pci_event_fd, .events = POLLPRI, .revents = 0},
    };

    // pci_event_fd is optional
    size_t fds_n;
    if (pci_event_fd < 0) {
        fds_n = array_size(fds) - 1;
    } else {
        fds_n = array_size(fds);

        // How pollable sysfs attribute works: Greg KH, https://lkml.org/lkml/2006/4/14/126
        // sysfs attribute is initially ready for "read", must issue a dummy read() to clear. Otherwise, poll() wouldn't block.
        leaba_pci_event_t dummy;
        read(pci_event_fd, &dummy, sizeof(dummy));
    }

    size_t msi_storm_count = 0;
    bool is_msi_storm = false;

    while (1) {
        log_xdebug(INTERRUPT, "%s: poll - waiting", __func__);
        if (poll(fds, fds_n, -1) < 0) {
            if (errno == EINTR) {
                log_info(INTERRUPT, "%s: poll() interrupted by a signal or a timeout, errno %d", __func__, errno);
                continue;
            }
            if (errno == EAGAIN) {
                continue;
            }
            log_err(INTERRUPT, "%s: poll() failed, errno %d", __func__, errno);
            return;
        }

        int msi_storm_threshold = 0;
        m_device->get_int_property(la_device_property_e::MSI_DAMPENING_THRESHOLD, msi_storm_threshold);
        if (is_msi_storm && msi_storm_count == 0) {
            is_msi_storm = false;
            log_debug(INTERRUPT, "%s: out of msi storm", __func__);
        } else if (msi_storm_count >= (size_t)msi_storm_threshold) {
            if (!is_msi_storm) {
                is_msi_storm = true;
                log_debug(INTERRUPT, "%s: having msi storm", __func__);
            }
            int interval = 0;
            m_device->get_int_property(la_device_property_e::MSI_DAMPENING_INTERVAL_MILLISECONDS, interval);
            // Must sleep outside of lock!
            this_thread::sleep_for(chrono::milliseconds(interval));
        }

        // Use the book keeping of API lock (e.g. RPFO in-flight) but avoid logging by not using start_api_call()
        api_lock_guard<std::recursive_mutex> lock(m_device, __func__);

        // PCI event - hotplug or AER
        if (fds[PCI_EVENT_FD].revents) {
            handle_pci_event(pci_event_fd);
        }

        // lld interrupt
        if (fds[INTERRUPT_FD].revents) {
            handle_lld_interrupt(interrupt_fd, interrupt_width_bytes);
            if (is_msi_clear()) {
                msi_storm_count = 0;
            } else {
                ++msi_storm_count;
            }
        }

        // self-pipe - terminate the worker thread
        // Placed last to allow draining events in case of warm-boot
        if (fds[SELF_PIPE].revents) {
            uint8_t val = 0;
            w->self_pipe.read(&val, sizeof(val));
            log_info(INTERRUPT, "%s: terminating", __func__);
            return;
        }
    }
}

void
hld_notification_base::get_poll_interval(hld_notification_base::poll_interval_e type, std::chrono::milliseconds& out_interval)
{
    int val = 0, default_val;

    if (type == poll_interval_e::POLL_INTERVAL_FAST) {
        m_device->get_int_property(la_device_property_e::POLL_FAST_INTERVAL_MILLISECONDS, val);
        default_val = POLL_FAST_INTERVAL_MILLISECONDS_DEFAULT;
    } else {
        m_device->get_int_property(la_device_property_e::POLL_INTERVAL_MILLISECONDS, val);
        default_val = POLL_INTERVAL_MILLISECONDS_DEFAULT;
    }

    val = val > 0 ? val : default_val;
    out_interval = std::chrono::milliseconds(val);
}

void
hld_notification_base::unschedule_polling_tasks_if_pci_unaccessible()
{
    bool pci_accessible = check_pci_accessible();

    if (pci_accessible) {
        return;
    }

    log_err(INTERRUPT, "PCI is dead, unschedule polling tasks");

    task_scheduler::task_desc_container tasks = m_task_scheduler.get_tasks();

    for (auto it = tasks.begin(); it != tasks.end(); it++) {
        m_task_scheduler.unschedule_task(it->handle);
    }
}

task_scheduler::task_handle
hld_notification_base::register_poll_cb(hld_notification_base::poll_cb cb, hld_notification_base::poll_interval_e interval)
{
    api_lock_guard<std::recursive_mutex> lock(m_device, __func__);

    log_debug(INTERRUPT, "%s: number of registered tasks so far %ld.", __func__, m_task_scheduler.get_num_tasks());

    task_scheduler::task_handle handle;

    handle = m_task_scheduler.schedule_periodic_task(
        [&, cb]() {
            api_lock_guard<std::recursive_mutex> lock(m_device, __func__);
            cb();
        },
        [&, interval]() -> std::chrono::milliseconds {
            std::chrono::milliseconds period;
            get_poll_interval(interval, period);
            return period;
        });

    if (handle == task_scheduler::INVALID_TASK_HANDLE) {
        std::chrono::milliseconds period;
        get_poll_interval(interval, period);

        log_err(INTERRUPT, "%s: unable to schedule polling cb of period %ld.", __func__, period.count());
        return handle;
    }

    return handle;
}

task_scheduler::task_handle
hld_notification_base::register_poll_cb(hld_notification_base::poll_cb cb, std::chrono::milliseconds poll_interval)
{
    api_lock_guard<std::recursive_mutex> lock(m_device, __func__);

    log_debug(INTERRUPT, "%s: number of registered tasks so far %ld.", __func__, m_task_scheduler.get_num_tasks());

    task_scheduler::task_handle handle;

    handle = m_task_scheduler.schedule_periodic_task(
        [&, cb]() {
            api_lock_guard<std::recursive_mutex> lock(m_device, __func__);
            cb();
        },
        [&, poll_interval]() -> std::chrono::milliseconds { return poll_interval; });

    if (handle == task_scheduler::INVALID_TASK_HANDLE) {
        log_err(INTERRUPT, "%s: unable to schedule polling cb of period %ld.", __func__, poll_interval.count());
        return handle;
    }

    return handle;
}

void
hld_notification_base::unregister_poll_cb(task_scheduler::task_handle pos)
{
    api_lock_guard<std::recursive_mutex> lock(m_device, __func__);

    log_debug(INTERRUPT, "%s: number of registered polling cbs of all periods=%ld.", __func__, m_task_scheduler.get_num_tasks());

    m_task_scheduler.unschedule_task(pos);
}

void
hld_notification_base::unregister_all_poll_cbs()
{
    api_lock_guard<std::recursive_mutex> lock(m_device, __func__);

    log_debug(INTERRUPT, "%s: number of registered polling cbs of all periods=%ld.", __func__, m_task_scheduler.get_num_tasks());
    m_task_scheduler.unschedule_all_tasks();
}

void
hld_notification_base::periodic_restore_interrupt_masks()
{
    auto now = chrono::steady_clock::now();

    // TODO: The 'if' below should go away if polling at constant intervals is replaced with an event queue.
    if (now < m_next_restore_interrupt_masks) {
        return;
    }

    // Restore interrupt masks that were disabled before m_next_restore_interrupt_masks.
    // For each mask bit, take into account the number of times it was disabled so far.
    m_interrupt_tree->reenable_dampened_interrupts(m_next_restore_interrupt_masks);

    int interval_msec = 0;
    m_device->get_int_property(la_device_property_e::RESTORE_INTERRUPT_MASKS_INTERVAL_MILLISECONDS, interval_msec);
    m_next_restore_interrupt_masks = now + chrono::milliseconds(interval_msec);
}

void
hld_notification_base::periodic_reset_interrupt_counters()
{
    auto now = chrono::steady_clock::now();

    // TODO: The 'if' below should go away if polling at constant intervals is replaced with an event queue.
    if (now < m_next_reset_interrupt_counters) {
        return;
    }

    m_interrupt_tree->reset_interrupt_counters();

    int interval_sec = 0;
    m_device->get_int_property(la_device_property_e::RESET_INTERRUPT_COUNTERS_INTERVAL_SECONDS, interval_sec);
    m_next_reset_interrupt_counters = now + chrono::seconds(interval_sec);
}

void
hld_notification_base::periodic_poll_non_wired_interrupts()
{
    bool enabled = false;
    m_device->get_bool_property(la_device_property_e::PROCESS_INTERRUPTS, enabled);
    if (!enabled) {
        return;
    }

    // TODO: The below code should go away if polling at constant intervals is replaced with an event queue.
    auto now = chrono::steady_clock::now();
    if (now < m_next_poll_non_wired_interrupts) {
        return;
    }
    int interval = 0;
    m_device->get_int_property(la_device_property_e::POLL_NON_WIRED_INTERRUPTS_INTERVAL_MILLISECONDS, interval);
    m_next_poll_non_wired_interrupts = now + chrono::milliseconds(interval);

    interrupt_tree::cause_bits cause_bits = m_interrupt_tree->collect_non_wired_interrupts();
    if (cause_bits.empty()) {
        log_xdebug(INTERRUPT, "%s: have not found interrupt causes", __func__);
    } else {
        do_handle_lld_interrupt(cause_bits);
    }
}

void
hld_notification_base::periodic_poll_msi_interrupts()
{
    bool process_interrupts = false;
    bool poll_msi = false;
    m_device->get_bool_property(la_device_property_e::PROCESS_INTERRUPTS, process_interrupts);
    m_device->get_bool_property(la_device_property_e::POLL_MSI, poll_msi);
    if (!process_interrupts || !poll_msi) {
        return;
    }

    handle_pending_msi_interrupts();
}

void
hld_notification_base::handle_pending_msi_interrupts()
{
    interrupt_tree::cause_bits cause_bits = m_interrupt_tree->collect_msi_interrupts();
    if (cause_bits.empty()) {
        log_xdebug(INTERRUPT, "%s: have not found interrupt causes", __func__);
    } else {
        do_handle_lld_interrupt(cause_bits);
    }
}

bool
hld_notification_base::insert_cause_to_group(const interrupt_tree::bit_scptr& bit, interrupt_groups& out)
{
    // Remove MEM_PROTECT cause bits from list; remember the corresponding node.
    if (bit->type == interrupt_type_e::MEM_PROTECT) {
        out.mem_protect_nodes.insert(bit->parent.lock());
        return true;
    }

    if (bit->type == interrupt_type_e::LPM_SRAM_ECC_1B || bit->type == interrupt_type_e::LPM_SRAM_ECC_2B) {
        out.lpm_sram_mem_protect.push_back(bit);
        return true;
    }

    if (bit->type == interrupt_type_e::DRAM_CORRUPTED_BUFFER) {
        out.mmu_has_error_buffer.push_back(bit);
        return true;
    }

    // Remove LINK_DOWN cause bits from list; remember the corresponding
    // mac port and any of its interrupt bits. We don't care which, because
    // we only keep the bit in order to get to its summary.
    if (bit->type == interrupt_type_e::MAC_LINK_DOWN) {
        la_mac_port_base_wptr mac_port = find_mac_port(bit);
        if (mac_port) {
            out.link_down_ports[mac_port] = bit;
            return true;
        }

        // We might get here immediately after a mac_port is destroyed.
        // If this happens, the interrupt is cleared by the generic handle_other().
        log_debug(INTERRUPT,
                  "MAC_LINK_DOWN interrupt for unknown port, %s, %s",
                  interrupt_tree::to_string(bit->parent.lock()).c_str(),
                  interrupt_tree::to_string(bit).c_str());
    }

    if (bit->type == interrupt_type_e::MAC_LINK_ERROR) {
        la_mac_port_base_wptr mac_port = find_mac_port(bit);
        if (mac_port) {
            auto it = out.link_error_ports.find(mac_port);
            if (it == out.link_error_ports.end()) {
                out.link_error_ports[mac_port] = interrupt_tree::cause_bits{bit};
            } else {
                out.link_error_ports[mac_port].push_back(bit);
            }

            return true;
        }

        // We might get here immediately after a mac_port is destroyed.
        // If this happens, the interrupt is cleared by the generic handle_other().
        log_debug(INTERRUPT,
                  "MAC_LINK_ERROR interrupt for unknown port, %s, %s",
                  interrupt_tree::to_string(bit->parent.lock()).c_str(),
                  interrupt_tree::to_string(bit).c_str());
    }

    if (bit->type == interrupt_type_e::COUNTER_THRESHOLD_CROSSED) {
        out.max_counter_group.push_back(bit);
        return true;
    }

    if (bit->type == interrupt_type_e::CREDIT_DEV_UNREACHABLE) {
        out.credit_dev_unreachable.push_back(bit);
        return true;
    }

    if (bit->type == interrupt_type_e::QUEUE_AGED_OUT) {
        out.queue_aged_out.push_back(bit);
        return true;
    }

    return false;
}

void
hld_notification_base::split_interrupt_causes(interrupt_tree::cause_bits& bits, hld_notification_base::interrupt_groups& out)
{
    // Return 'true' if 'bit' should be erased from the 'bits' list.
    auto remove_condition = ([&](const interrupt_tree::bit_scptr& bit) {
        bool inserted = insert_cause_to_group(bit, out);

        return inserted;
    });

    bits.erase(std::remove_if(bits.begin(), bits.end(), remove_condition), bits.end());
}

void
hld_notification_base::handle_lld_interrupt(int interrupt_fd, size_t interrupt_width_bytes)
{
    // The vanilla UIO works with 32bit counter, UMD works with eventfd, hence, 64bit counter.
    // If read() is called with the wrong size, it will fail with errno==EINVAL
    uint64_t val = 0;
    ssize_t nread = read(interrupt_fd, &val, interrupt_width_bytes);
    if (nread != (ssize_t)interrupt_width_bytes) {
        log_err(INTERRUPT, "%s: interrupt - unexpected nread=%zd, errno=%d", __func__, nread, errno);
        return;
    }

    bool enabled = false;
    m_device->get_bool_property(la_device_property_e::PROCESS_INTERRUPTS, enabled);

    log_debug(INTERRUPT, "%s: got lld interrupt, val=0x%lx, enabled=%d", __func__, val, (int)enabled);
    if (!enabled) {
        return;
    }

    // Collect interrupt causes - individual bits

    // WA : Loop until msi is clear. This is due to bug when there is a new interrupt in other sub-tree
    // than first one and before the first one is cleared
    int msi_storm_guard = 0;
    m_device->get_int_property(la_device_property_e::MSI_DAMPENING_THRESHOLD, msi_storm_guard);
    for (int n = 0; !is_msi_clear() && n < msi_storm_guard; n++) {
        if (n > 0) {
            log_xdebug(
                INTERRUPT, "%s: msi was not cleared in the first run! Possible accompanying interrupts. Run No. <%d>", __func__, n);
        }

        interrupt_tree::cause_bits cause_bits = m_interrupt_tree->collect_msi_interrupts();
        if (cause_bits.empty()) {
            log_debug(INTERRUPT, "%s: have not found interrupt causes", __func__);
        } else {
            do_handle_lld_interrupt(cause_bits);
        }
    }
}

void
hld_notification_base::do_handle_lld_interrupt(interrupt_tree::cause_bits& cause_bits)
{
    // Sip through all collected interrupt bits and split them into logical groups
    interrupt_groups groups;
    split_interrupt_causes(cause_bits, groups);

    log_debug(INTERRUPT,
              "%s: max_counter_group %ld, mem_protect nodes %ld, link_down mac_ports %ld, link_error mac_ports %ld, "
              "credit_dev_unreachable %ld, queue_aged_out %ld, other interrupt bits %ld",
              __func__,
              groups.max_counter_group.size(),
              groups.mem_protect_nodes.size(),
              groups.link_down_ports.size(),
              groups.link_error_ports.size(),
              groups.credit_dev_unreachable.size(),
              groups.queue_aged_out.size(),
              cause_bits.size());

    // Handle link-down interrupts at mac port level
    for (const auto el : groups.link_down_ports) {
        handle_link_down(el.first, el.second);
    }

    // Handle Max Counter overflow interrupt if needed
    handle_max_counter_overflow_interrupt(groups.max_counter_group);

    // Handle credits grant destination device unreachable interrupt
    handle_credit_grant_dest_dev_unreachable(groups.credit_dev_unreachable);

    // Handle queue aged out interrupt
    for (const auto bit : groups.queue_aged_out) {
        handle_queue_aged_out(bit);
    }

    // Handle mem_protect interrupts at 'node' level
    for (const auto el : groups.mem_protect_nodes) {
        handle_mem_protect(el);
    }

    // Handle LPM SRAM ecc 1b/2b interrupts.
    for (const auto el : groups.lpm_sram_mem_protect) {
        handle_lpm_sram_mem_protect(el);
    }

    // Handle link-error interrupts at mac port level
    for (const auto el : groups.link_error_ports) {
        handle_link_error(el.first, el.second);
    }

    // Handle HBM 2b-ecc interrupt - there is only one interrupt bit of this type.
    for (const auto el : groups.mmu_has_error_buffer) {
        handle_mmu_has_error_buffer(el);
    }

    // Generic interrupt handling
    for (const auto el : cause_bits) {
        handle_other(el);
    }

    log_xdebug(INTERRUPT, "%s: done", __func__);
}

// Handle Max Counter overflow interrupts in one call to refresh max counters
void
hld_notification_base::handle_max_counter_overflow_interrupt(const interrupt_tree::cause_bits& max_counter_group)
{
    if (!max_counter_group.empty()) {
        m_device->m_counter_bank_manager->refresh_max_counters();
        for (const auto el : max_counter_group) {
            m_interrupt_tree->clear_interrupt_cause(el);
            m_interrupt_tree->clear_interrupt_summary(el->parent.lock());
        }
    }
}

void
hld_notification_base::handle_credit_grant_dest_dev_unreachable(const interrupt_tree::cause_bits& cause_bits)
{
    if (cause_bits.empty()) {
        return;
    }

    csms_debug_unreach_gnt_capture_reg_register debug_unreach_reg;
    m_device->m_ll_device->read_register(m_device->m_ll_device->get_pacific_tree()->csms->debug_unreach_gnt_capture_reg,
                                         debug_unreach_reg);

    union unreach_gnt_reg {
        struct {
            // Each field is 16 bits. 1 bit for IFG, 15 bits for VSC. IFG is the MSB
            la_vsc_gid_t vsc_id : 15;
            la_ifg_id_t ifg_id : 1;
        } fields;

        uint64_t flat;
    };

    unreach_gnt_reg reg_per_slice[4] = {
        {.flat = debug_unreach_reg.fields.debug_unreach_gnt_capture0},
        {.flat = debug_unreach_reg.fields.debug_unreach_gnt_capture1},
        {.flat = debug_unreach_reg.fields.debug_unreach_gnt_capture2},
        {.flat = debug_unreach_reg.fields.debug_unreach_gnt_capture3},
    };

    bit_vector reachable_devices_bv(0, silicon_one::la_device_impl::MAX_DEVICES);
    m_device->get_reachable_devices(reachable_devices_bv);

    const interrupt_tree::bit_scptr dev_unreach_bit = cause_bits[0]; // Checked before that cause_bits not empty

    for (la_slice_id_t slice_id :
         m_device->get_slice_id_manager()->get_slices_by_fabric_type(fabric_slices_type_e::HW_NON_FABRIC)) {
        la_ifg_id_t vsc_ifg_id = reg_per_slice[slice_id].fields.ifg_id;
        la_vsc_gid_t vsc_id = reg_per_slice[slice_id].fields.vsc_id;

        la_device_impl::vsc_ownership_map_key vomk(slice_id, vsc_ifg_id, vsc_id);
        auto it = m_device->m_vsc_ownership_map.find(vomk);
        if (it == m_device->m_vsc_ownership_map.end()) {
            continue;
        }

        // If remote device is unreachable - then we want to stop static-go, which sends credits at line rate to that device.
        bool is_dev_reachable;
        size_t remote_dev_id = it->second.device_id;
        is_dev_reachable = reachable_devices_bv.bit(remote_dev_id);
        if (is_dev_reachable) {
            continue;
        }
        // Also need to check VSC is in static-go to avoid unrequired notifications.
        sch_vsc_credit_deficit_memory vsc_credit_deficit_mem;
        m_device->m_ll_device->read_memory(
            m_device->m_ll_device->get_pacific_tree()->slice[slice_id]->ifg[vsc_ifg_id]->sch->vsc_credit_deficit,
            vsc_id,
            vsc_credit_deficit_mem);
        bool is_vsc_in_static_go = vsc_credit_deficit_mem.fields.static_go;
        if (!is_vsc_in_static_go) {
            continue;
        }

        const auto& oqs = it->second.oqs;
        oqs->stop_static_go(vsc_id);

        lld_register_scptr interrupt_reg = dev_unreach_bit->parent->status;
        la_notification_desc desc;
        bzero(&desc, sizeof(desc));
        desc.block_id = interrupt_reg->get_block_id();
        desc.addr = interrupt_reg->get_desc()->addr;
        desc.bit_i = dev_unreach_bit->bit_i;
        desc.type = la_notification_type_e::CREDIT_GRANT_DEV_UNREACHABLE;
        desc.u.dev_unreachable.remote_dev_id = remote_dev_id;
        desc.u.dev_unreachable.slice_id = slice_id;
        desc.u.dev_unreachable.ifg_id = vsc_ifg_id;
        desc.u.dev_unreachable.vsc_id = vsc_id;

        notify(desc, notification_pipe_e::NORMAL);
    }

    for (const auto bit : cause_bits) {
        m_interrupt_tree->clear_interrupt_cause(bit);
        m_interrupt_tree->clear_interrupt_summary(bit->parent.lock());
    }
}

void
hld_notification_base::handle_queue_aged_out(const interrupt_tree::bit_scptr& bit)
{
    ics_slice_scrb_status_reg_register scrb_status;
    for (const auto& slice : m_device->m_ll_device->get_pacific_tree()->slice) {
        std::vector<la_voq_gid_t> encountered_voqs;
        m_device->m_ll_device->read_register(slice->ics->scrb_status_reg, scrb_status);
        uint64_t context_num = scrb_status.fields.aged_out_context_num;
        uint64_t context_valid = scrb_status.fields.aged_out_context_valid;

        if (!context_valid) {
            continue;
        }

        pdvoq_slice_context2voq_memory context2voq;
        m_device->m_ll_device->read_memory(*slice->ics->context2voq, context_num, context2voq);
        la_voq_gid_t voq_id = context2voq.fields.context2voq_bits;

        // Verify that notification for this VOQ wasn't already sent.
        bool is_voq_exist = false;
        for (const auto voq : encountered_voqs) {
            if (voq == voq_id) {
                is_voq_exist = true;
            }
        }
        if (is_voq_exist) {
            continue;
        }
        encountered_voqs.push_back(voq_id);

        // Prepare interrupt notification and send it.
        lld_register_scptr interrupt_reg = bit->parent->status;
        la_notification_desc desc;
        bzero(&desc, sizeof(desc));
        desc.block_id = interrupt_reg->get_block_id();
        desc.addr = interrupt_reg->get_desc()->addr;
        desc.bit_i = bit->bit_i;
        desc.type = la_notification_type_e::QUEUE_AGED_OUT;
        desc.u.voq_info.voq_id = voq_id;

        notify(desc, notification_pipe_e::NORMAL);

        // Clear the interrupt by re-triggering the scrubber.
        m_device->m_ll_device->write_register(*slice->ics->scrb_aging_trig_reg, 0);
        m_device->m_ll_device->write_register(*slice->ics->scrb_aging_trig_reg, 1);
    }

    m_interrupt_tree->clear_interrupt_cause(bit);
    m_interrupt_tree->clear_interrupt_summary(bit->parent.lock());
}

// Handle mem_protect errors for one interrupt node (i.e. one CIF block)
void
hld_notification_base::handle_mem_protect(const interrupt_tree::node_wcptr& node)
{
    // Because mem_protect interrupt bits are interdependent, we handle mem_protect at node level

    const interrupt_tree::node_scptr node_sptr = node.lock();
    // Collect mem_protect errors of all types
    interrupt_tree::mem_protect_errors mem_protect_errors = m_interrupt_tree->collect_mem_protect_errors(node_sptr);

    for (const auto& e : mem_protect_errors) {
        // Check if fixable (entry in range, non-volatile, ...):
        bool is_fixable = is_mem_protect_fixable(e);

        log_debug(INTERRUPT, "%s: %s, line=0x%x, is_fixable=%d", __func__, e.mem->get_name().c_str(), e.entry, is_fixable);

        if (is_fixable) {
            // Write shadowed mem values back to HW
            m_device->m_ll_device->refresh_memory(*e.mem, e.entry);
        } else {
            // Dampen non-fixable mem_protect error
            m_interrupt_tree->dampen_mem_protect_error(node_sptr, e);
        }
    }

    // Clear all mem_protect interrupts at node level at once
    static constexpr uint64_t val = (1 << (uint64_t)la_mem_protect_error_e::ECC_1B)
                                    | (1 << (uint64_t)la_mem_protect_error_e::ECC_2B)
                                    | (1 << (uint64_t)la_mem_protect_error_e::PARITY);
    m_interrupt_tree->clear_interrupt_cause(node_sptr, val);

    // notify for each {block, mem_instance, mem_entry}
    for (const auto& e : mem_protect_errors) {
        notify_mem_protect(e);
    }
}

void
hld_notification_base::handle_lpm_sram_mem_protect(const interrupt_tree::bit_scptr& bit)
{
    lld_register_scptr interrupt_reg = bit->parent->status;

    size_t lpm_index;
    la_status rc = m_device->get_cdb_core_lpm_index(interrupt_reg, lpm_index);
    return_void_on_error_log(
        rc, INTERRUPT, ERROR, "%s: unexpected interrupt register %s", __func__, interrupt_reg->get_name().c_str());

    la_mem_protect_error_e mem_error
        = (bit->type == interrupt_type_e::LPM_SRAM_ECC_1B ? la_mem_protect_error_e::ECC_1B : la_mem_protect_error_e::ECC_2B);

    lpm_sram_mem_protect error_info{.error = mem_error,
                                    .cdb_core_block_id = interrupt_reg->get_block_id(),

                                    // cdb->core[].lpm_shared_sram_err_add_reg[] contains the address of the last access
                                    // instead of being latched to the last error address.
                                    // As a result, error address is unknown.
                                    .addr = UINT32_MAX,
                                    .lpm_index = (uint8_t)lpm_index};

    // Re-write SRAM content
    m_device->lpm_sram_mem_protect_handler(*interrupt_reg->get_block(), error_info);

    // No additional internal state to clear, it is sufficient to only clear the interrupt bit.
    m_interrupt_tree->clear_interrupt_cause(bit);

    // Dampen this interrupt, because interrupt handling is potentially heavy (error-address is unknown).
    m_interrupt_tree->dampen_interrupt_cause(bit);

    // Raise notification
    la_notification_desc desc{};
    desc.block_id = interrupt_reg->get_block_id();
    desc.addr = interrupt_reg->get_desc()->addr;
    desc.bit_i = bit->bit_i;
    desc.type = la_notification_type_e::LPM_SRAM_MEM_PROTECT;
    desc.u.lpm_sram_mem_protect = error_info;

    m_interrupt_tree->get_threshold_and_action(bit, error_info, desc.requested_action, desc.action_threshold);

    notify(desc, notification_pipe_e::NORMAL);
}

void
hld_notification_base::handle_mmu_has_error_buffer(const interrupt_tree::bit_scptr& cause_bit)
{
    log_debug(INTERRUPT, "%s: %s", __func__, interrupt_tree::to_string(cause_bit).c_str());

    m_interrupt_tree->clear_interrupt_cause(cause_bit);

    std::vector<dram_corrupted_buffer> dram_corrupted_buffers;
    m_device->m_hbm_handler->check_dram_buffer_errors(dram_corrupted_buffers);
    log_debug(INTERRUPT, "%s: %ld dram buffers are corrupted", __func__, dram_corrupted_buffers.size());
    if (dram_corrupted_buffers.empty()) {
        return;
    }

    lld_register_scptr reg = cause_bit->parent->status;
    la_notification_desc desc;
    bzero(&desc, sizeof(desc));
    desc.block_id = reg->get_block_id();
    desc.addr = reg->get_desc()->addr;
    desc.bit_i = cause_bit->bit_i;
    desc.type = la_notification_type_e::DRAM_CORRUPTED_BUFFER;

    for (const auto& d : dram_corrupted_buffers) {
        m_interrupt_tree->get_threshold_and_action(cause_bit, desc.requested_action, desc.action_threshold);
        desc.u.dram_corrupted_buffer = d;

        notification_pipe_e pipe_e = (desc.requested_action == la_notification_action_e::NONE ? notification_pipe_e::NORMAL
                                                                                              : notification_pipe_e::CRITICAL);

        notify(desc, pipe_e);
    }
}

void
hld_notification_base::notify_mem_protect(const interrupt_tree::mem_protect_error& e)
{
    bool should_notify = mem_protect_quirk_should_notify(e);
    if (!should_notify) {
        return;
    }

    log_debug(INTERRUPT, "%s: mem=%s, entry=0x%x, error=%d", __func__, e.mem->get_name().c_str(), e.entry, (int)e.error);

    la_notification_desc desc;
    bzero(&desc, sizeof(desc));
    desc.block_id = e.mem->get_block_id();
    desc.addr = lld_register::MEM_PROTECT_INTERRUPT;
    desc.bit_i = (uint32_t)e.error;
    desc.type = la_notification_type_e::MEM_PROTECT;

    bool quirk_applied = mem_protect_quirk_soft_action(e, desc.requested_action, desc.action_threshold);
    if (!quirk_applied) {
        m_interrupt_tree->get_threshold_and_action(e, desc.requested_action, desc.action_threshold);
    }

    desc.u.mem_protect.error = e.error;
    desc.u.mem_protect.instance_addr = e.mem->get_desc()->addr;
    desc.u.mem_protect.entry = e.entry;

    notification_pipe_e pipe_e
        = (desc.requested_action == la_notification_action_e::NONE ? notification_pipe_e::NORMAL : notification_pipe_e::CRITICAL);
    notify(desc, pipe_e);
}

void
hld_notification_base::handle_link_down(const la_mac_port_base_wptr& mac_port, const interrupt_tree::bit_scptr& cause_bit)
{
    log_debug(INTERRUPT, "%s: %s", __func__, interrupt_tree::to_string(cause_bit).c_str());

    // Clear summary bits
    m_interrupt_tree->clear_interrupt_summary(cause_bit->parent.lock());

    // Read & clear MAC_LINK_DOWN interrupt cause registers for this mac_port.
    // Raise link-down notification.
    mac_port->handle_link_down_interrupt();
}

void
hld_notification_base::handle_link_error(const la_mac_port_base_wcptr& mac_port, const interrupt_tree::cause_bits& cause_bits)
{
    for (const auto cause_bit : cause_bits) {
        log_debug(INTERRUPT, "%s: %s", __func__, interrupt_tree::to_string(cause_bit).c_str());
        m_interrupt_tree->clear_interrupt_cause(cause_bit);
        m_interrupt_tree->dampen_interrupt_cause(cause_bit);
    }

    // Raise link-error notification, all link-error bits for this port are aggregated in one notification.
    mac_port->handle_link_error_interrupt(cause_bits);
}

void
hld_notification_base::handle_other(const interrupt_tree::bit_scptr& cause_bit)
{
    log_debug(INTERRUPT, "%s: %s", __func__, interrupt_tree::to_string(cause_bit).c_str());

    m_interrupt_tree->clear_interrupt_cause(cause_bit);

    if (cause_bit->type == interrupt_type_e::SUMMARY) {
        // Chopped off interrupt branch (which has a SUMMARY bit as a leaf).
        // Dont disable the mask for summary interrupt and dont raise notification.
        return;
    }

    m_interrupt_tree->dampen_interrupt_cause(cause_bit);
    notify_other(cause_bit);
}

void
hld_notification_base::notify_other(const interrupt_tree::bit_scptr& cause_bit)
{
    lld_register_scptr reg = cause_bit->parent->status;
    la_notification_desc desc;
    bzero(&desc, sizeof(desc));
    desc.block_id = reg->get_block_id();
    desc.addr = reg->get_desc()->addr;
    desc.bit_i = cause_bit->bit_i;

    desc.type = la_notification_type_e::OTHER;
    m_interrupt_tree->get_threshold_and_action(cause_bit, desc.requested_action, desc.action_threshold);

    notification_pipe_e pipe_e
        = (desc.requested_action == la_notification_action_e::NONE ? notification_pipe_e::NORMAL : notification_pipe_e::CRITICAL);

    notify(desc, pipe_e);
}

la_status
hld_notification_base::notify(const la_notification_desc& desc)
{
    return notify(desc, notification_pipe_e::NORMAL);
}

la_status
hld_notification_base::notify(const la_notification_desc& desc, hld_notification_base::notification_pipe_e pipe_e)
{
    // From pipe(7) man page: "POSIX.1 says that write(2)s of less than PIPE_BUF bytes must be atomic...
    // POSIX.1 requires PIPE_BUF to be at least 512 bytes...
    static_assert(sizeof(la_notification_desc) <= PIPE_BUF,
                  "sizeof(la_notification_desc) is too large to support atomic write(). Consider implementing a lock.");

    // Check if this notification type is enabled
    if (!bit_utils::get_bit(m_notify_mask, (uint8_t)desc.type)) {
        log_debug(INTERRUPT, "%s: notification type=%s is disabled", __func__, to_string(desc.type).c_str());
        return LA_STATUS_SUCCESS;
    }

    // Send on "critical" or "normal" pipe, based on requested_action
    size_t pipe_i = (size_t)pipe_e;
    if (!m_notification_pipes[pipe_i]) {
        log_debug(INTERRUPT, "%s: pipe %ld is not ready", __func__, pipe_i);
        return LA_STATUS_SUCCESS;
    }

    la_notification_desc desc_copy = desc;
    desc_copy.id = ++m_notification_id; // the increment is atomic

    auto since_epoch = chrono::system_clock::now().time_since_epoch();
    desc_copy.timestamp_ns = chrono::duration_cast<chrono::nanoseconds>(since_epoch).count();

    log_debug(INTERRUPT,
              "%s: id=%ld, timestamp_ns=%ld, type=%s, requested_action=%s, action_threshold=%d",
              __func__,
              desc_copy.id,
              desc_copy.timestamp_ns,
              to_string(desc_copy.type).c_str(),
              to_string(desc_copy.requested_action).c_str(),
              desc_copy.action_threshold);

    // Non-blocking write.
    //
    // Atomicity: see "man 7 pipe", section PIPE_BUF.
    // In our case, sizeof(la_notification_desc) < PIPE_BUF ===> write to pipe is atomic.
    // Since the write is non-blocking, it returns immediately in case of failure:
    //  - EAGAIN means that the pipe is full.
    //  - We may get other errors as well, e.g. EPIPE if the "read" end was closed.
    //
    // Pipe capacity: "man 7 pipe", section "Pipe capacity"
    // The depth of pipe is 1 page (4KB) on Linux < 2.6.11 or 16 pages (64KB) since Linux 2.6.11.
    // Since Linux 2.6.35 the capacity can be queried and set, and go beyond the default 64KB up to 1MB.
    static_assert(sizeof(la_notification_desc) < PIPE_BUF, "Notification descriptor is too large to be written atomically");
    ssize_t n = m_notification_pipes[pipe_i]->write(&desc_copy, sizeof(desc_copy));
    if (n != sizeof(desc_copy)) {
        ++m_notification_pipes_errors[pipe_i];
        if (m_notification_pipes_errors[pipe_i] == 1) {
            // Prevent log flooding, print only the first error.
            if (errno == EAGAIN) {
                log_err(INTERRUPT, "%s: notification pipe %ld is full", __func__, pipe_i);
            } else {
                log_err(INTERRUPT,
                        "%s: failed writing notification type=%s, to pipe %ld, errno=%d",
                        __func__,
                        to_string(desc.type).c_str(),
                        pipe_i,
                        errno);
            }
        }
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
hld_notification_base::set_thread_name(const std::thread::native_handle_type native_thread,
                                       const la_device_id_t device_id,
                                       const char* suffix)
{
    char thread_name[THREAD_NAME_MAX_SIZE + 1]; // limited to 15 characters plus '\0'
    snprintf(thread_name, sizeof(thread_name), "dev %hu %s", device_id, suffix);

    int rc2 = pthread_setname_np(native_thread, thread_name);
    if (rc2) {
        log_err(INTERRUPT, "pthread_setname_np() failed, name=%s, errno=%d", thread_name, errno);
        return LA_STATUS_ESIZE;
    }

    return LA_STATUS_SUCCESS;
}

bool
hld_notification_base::get_mac_port_ids(const interrupt_tree::bit_scptr& cause_bit,
                                        la_slice_id_t& out_slice,
                                        la_ifg_id_t& out_ifg,
                                        la_uint_t& out_serdes) const
{
    la_block_id_t block_id = cause_bit->parent->status->get_block_id();
    uint64_t addr = cause_bit->parent->status->get_absolute_address();

    // Find a matching mac_pool
    auto it = m_mac_pool_serdes_bases.find(block_id);
    if (it != m_mac_pool_serdes_bases.end()) {
        out_slice = it->second.slice_i;
        out_ifg = it->second.ifg_i;
        out_serdes = it->second.serdes_base + cause_bit->bit_i;
        return true;
    }

    bool is_gb = m_device->m_ll_device->is_gibraltar();
    bool is_pl = m_device->m_ll_device->is_asic4();
    bool is_ar = m_device->m_ll_device->is_asic5();

    // No matching mac_pool. Check IFGB registers that correspond to serdeses.
    for (la_slice_ifg ifg_dat : m_device->get_used_ifgs()) {
        uint64_t ifgb_interrupt_reg = 0;
        if (is_gb) {
            auto tree = m_device->m_ll_device->get_gibraltar_tree();
            const auto& ifg = tree->slice[ifg_dat.slice]->ifg[ifg_dat.ifg];
            ifgb_interrupt_reg = ifg->ifgb->tx_tsf_ovf_interrupt_reg->get_absolute_address();
        } else if (is_pl) {
            // BJO - gone in latest
            // auto tree = m_device->m_ll_device->get_asic4_tree();
            // const auto& ifg = tree->slice[ ifg_dat.slice]->ifg[ifg_dat.ifg];
            // ifgb_interrupt_reg = ifg->ifgb->tx_tsf_ovf_interrupt_reg->get_absolute_address();
        } else if (is_ar) {
            // BJO - gone in latest
            // auto tree = m_device->m_ll_device->get_asic5_tree();
            // const auto& ifg = tree->slice[slice_id]->ifg[ifg_id];
            // ifgb_interrupt_reg = ifg->ifgb->tx_tsf_ovf_interrupt_reg->get_absolute_address();
        } else {
            auto tree = m_device->m_ll_device->get_pacific_tree();
            const auto& ifg = tree->slice[ifg_dat.slice]->ifg[ifg_dat.ifg];
            ifgb_interrupt_reg = ifg->ifgb->tx_tsf_ovf_interrupt_reg->get_absolute_address();
        }

        // TODO: GB - slice[first_slice]->ifg[0]->ifgb->rx_oobe_crc_err_interrupt_reg

        // Only tx timestamp error register is considered, 18bits on Pacific.
        // Other IFGB interrupt registers do not correspond to serdeses.
        if (ifgb_interrupt_reg == addr) {
            out_slice = ifg_dat.slice;
            out_ifg = ifg_dat.ifg;
            out_serdes = cause_bit->bit_i;
            return true;
        }
    }

    return false;
}

la_mac_port_base_wptr
hld_notification_base::find_mac_port(const interrupt_tree::bit_scptr& cause_bit) const
{
    la_slice_id_t slice_id;
    la_ifg_id_t ifg_id;
    la_uint_t serdes_id;
    bool ok = get_mac_port_ids(cause_bit, slice_id, ifg_id, serdes_id);
    if (!ok) {
        return nullptr;
    }

    la_mac_port* mac_port;
    la_status rc = m_device->get_mac_port(slice_id, ifg_id, serdes_id, mac_port);
    if (rc) {
        return nullptr;
    }

    la_mac_port_base* port_base = static_cast<la_mac_port_base*>(mac_port);
    return m_device->get_sptr(port_base);
}

static const char*
pci_event_to_string(leaba_pci_event_e pci_event)
{
    const char* strs[]{
            [0] = "unknown",
            [LEABA_PCI_EVENT_HOTPLUG_REMOVE] = "HOTPLUG_REMOVE",
            [LEABA_PCI_EVENT_AER_NON_RECOVERABLE] = "AER_NON_RECOVERABLE",
            [LEABA_PCI_EVENT_AER_RECOVERABLE] = "AER_RECOVERABLE",
            [LEABA_PCI_EVENT_AER_RECOVERED] = "AER_RECOVERED",
    };

    static_assert(array_size(strs) == LEABA_PCI_EVENT_LAST + 1, "bad size of strings array");

    return (pci_event < array_size(strs) ? strs[pci_event] : "unknown");
}

void
hld_notification_base::handle_pci_event(int pci_event_fd)
{
    // sysfs attr is a seekable file. Must call lseek(0) between poll() and read().
    // Otherwise, read() will return immediately with size 0 and kernel's sysfs "show" will not even be called.

    leaba_pci_event_t val;
    lseek(pci_event_fd, 0L, SEEK_SET);
    ssize_t nread = read(pci_event_fd, &val, sizeof(val));
    if (nread != sizeof(val)) {
        log_err(INTERRUPT, "%s: pci_event - unexpected nread=%zd, errno=%d", __func__, nread, errno);
        return;
    }

    leaba_pci_event_e event = (leaba_pci_event_e)val;
    log_info(INTERRUPT, "%s: event=%s", __func__, pci_event_to_string(event));

    la_pci_notification_type_e type;
    switch (event) {
    case LEABA_PCI_EVENT_HOTPLUG_REMOVE:
        type = la_pci_notification_type_e::HOT_REMOVE;
        break;
    case LEABA_PCI_EVENT_AER_NON_RECOVERABLE:
        type = la_pci_notification_type_e::AER_NON_RECOVERABLE;
        break;
    case LEABA_PCI_EVENT_AER_RECOVERABLE:
        type = la_pci_notification_type_e::AER_RECOVERABLE;
        break;
    case LEABA_PCI_EVENT_AER_RECOVERED:
        type = la_pci_notification_type_e::AER_RECOVERED;
        break;
    default:
        return;
    }

    la_notification_desc desc{.id = 0,
                              .block_id = LA_BLOCK_ID_INVALID,
                              .addr = 0,
                              .bit_i = 0,
                              .timestamp_ns = 0,
                              .type = la_notification_type_e::PCI,
                              .requested_action = la_notification_action_e::HARD_RESET,
                              .action_threshold = 1,
                              .u = {.pci = {.type = type}}};

    notify(desc, notification_pipe_e::CRITICAL);
}

bool
hld_notification_base::is_mem_protect_fixable(const interrupt_tree::mem_protect_error& e) const
{
    const lld_memory_desc_t* mdesc = e.mem->get_desc();

    if (e.entry >= mdesc->entries) {
        return false;
    }
    if (mdesc->is_volatile()) {
        return false;
    }
    if (mdesc->subtype == lld_memory_subtype_e::X_Y_TCAM) {
        return false;
    }

    bool is_fixable = mem_protect_quirk_is_fixable(e);

    return is_fixable;
}

bool
hld_notification_base::mem_protect_quirk_is_fixable(const interrupt_tree::mem_protect_error& e) const
{
    // Pacific quirks
    const auto& tree = m_device->m_ll_device->get_pacific_tree();

    if (tree != nullptr) {
        // pacific_tree.slice[]->pdvoq->static_mapping is not CPU accessible when ASIC is under traffic.
        vector_alloc<lld_memory_scptr> static_mapping;
        init_static_mapping(m_device, static_mapping);

        bool found = contains(static_mapping, e.mem);

        return !found;
    }

    return true;
}

bool
hld_notification_base::mem_protect_quirk_should_notify(const interrupt_tree::mem_protect_error& e) const
{
    const auto& tree = m_device->m_ll_device->get_pacific_tree();

    if (tree != nullptr) {
        // sch and fabric_sch are known to read an entry out-of-range after soft-reset.
        if (e.entry >= e.mem->get_desc()->entries) {
            log_debug(INTERRUPT, "%s: mem=%s, entry=0x%x - out of range", __func__, e.mem->get_name().c_str(), e.entry);
            return false;
        }
    }

    return true;
}

bool
hld_notification_base::mem_protect_quirk_soft_action(const interrupt_tree::mem_protect_error& e,
                                                     la_notification_action_e& action,
                                                     uint32_t& action_threshold) const
{
    const auto& tree = m_device->m_ll_device->get_pacific_tree();

    if (tree != nullptr && e.error == la_mem_protect_error_e::ECC_2B) {
        // Unlike other memories, pacific_tree.slice[]->pdvoq->static_mapping ECC-2b requires a hard-reset on 1st occurence.
        vector_alloc<lld_memory_scptr> static_mapping;
        init_static_mapping(m_device, static_mapping);

        bool found = contains(static_mapping, e.mem);
        if (found) {
            action = la_notification_action_e::HARD_RESET;
            action_threshold = 1;
            return true;
        }
    }

    return false;
}

bool
hld_notification_base::check_pci_accessible()
{
    if (m_device->m_ll_device->check_health() == true) {
        return true;
    }
    // Sent notification that device is not present.
    la_notification_desc desc{.id = 0,
                              .block_id = LA_BLOCK_ID_INVALID,
                              .addr = 0,
                              .bit_i = 0,
                              .timestamp_ns = 0,
                              .type = la_notification_type_e::PCI,
                              .requested_action = la_notification_action_e::HARD_RESET,
                              .action_threshold = 1,
                              .u = {.pci = {.type = la_pci_notification_type_e::NODEV}}};
    notify(desc, notification_pipe_e::CRITICAL);
    return false;
}

} // namespace silicon_one
