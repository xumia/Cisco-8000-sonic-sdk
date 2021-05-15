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

#include "npu_host_event_queue_gibraltar.h"

#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

npu_host_event_queue_gibraltar::npu_host_event_queue_gibraltar(const la_device_impl_wptr& device)
    : npu_host_event_queue_base(device)
{
}

npu_host_event_queue_gibraltar::~npu_host_event_queue_gibraltar()
{
}

std::vector<bit_vector>
npu_host_event_queue_gibraltar::collect_npu_host_events()
{
    gibraltar::npu_host_cpu_q_config_write_adress_register write_address_reg{{0}};
    gibraltar::npu_host_cpu_q_config_read_adress_register read_address_reg{{0}};

    auto& lld = m_device->m_ll_device;
    auto& npuh = m_device->m_gb_tree->npuh;

    la_status status = lld->read_register(npuh->host->cpu_q_config_write_adress, write_address_reg);
    if (status != LA_STATUS_SUCCESS) {
        log_err(INTERRUPT, "%s: read of write_address_reg failed", __func__);
        return {};
    }

    status = lld->read_register(npuh->host->cpu_q_config_read_adress, read_address_reg);
    if (status != LA_STATUS_SUCCESS) {
        log_err(INTERRUPT, "%s: read of read_address_reg failed", __func__);
        return {};
    }

    if (read_address_reg.fields.read_address == write_address_reg.fields.write_adress) {
        // Pointers equal, nothing to do.
        return {};
    }

    // Chop and loop using 10 bits, to wrap around the ring.
    struct evq_address {
        uint64_t val : 10;
    };

    evq_address write_address = {write_address_reg.fields.write_adress};
    evq_address read_address = {read_address_reg.fields.read_address};

    // If the msb of the read/write ptrs are different and
    // the write 10b is greater than the read 10b
    // we have wrapped.
    if (((write_address_reg.fields.write_adress & (1 << 10)) != (read_address_reg.fields.read_address & (1 << 10)))
        && (write_address.val >= read_address.val)) {
        gibraltar::npu_host_evq_counters_register evq_counter{{0}};
        lld->read_register(npuh->host->evq_counters, evq_counter);
        log_err(INTERRUPT,
                "%s: eventq wrapped arrived %ld dropped %ld",
                __func__,
                evq_counter.fields.events_arrived_to_evq,
                evq_counter.fields.events_dropped_in_evq);
        if (write_address.val == read_address.val) {
            // If we wrapped and the ptr are equal, bump the read ptr ahead by one
            // to do some work.
            read_address.val++;
        }
        // Continue processing messages even though there was a wrap.
    }

    std::vector<bit_vector> events;

    for (; read_address.val != write_address.val; ++read_address.val) {
        bit_vector result;
        status = lld->read_memory(npuh->host->event_queue, read_address.val, result);
        if (status != LA_STATUS_SUCCESS) {
            log_err(INTERRUPT, "%s: read of eventq failed %lx", __func__, read_address.val);
            continue;
        }

        events.push_back(std::move(result));
    }

    // Update event queue, use full 11-bit value
    read_address_reg.fields.read_address = write_address_reg.fields.write_adress;
    lld->write_register(npuh->host->cpu_q_config_read_adress, read_address_reg);

    return events;
}

} // namespace silicon_one
