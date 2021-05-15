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

#include "counter_bank_utils.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

void
counter_bank_utils::dispatch_read_counter_command(const la_device_impl_wptr& device,
                                                  counter_read_command_e cmd,
                                                  size_t counter_read_address)
{
    gibraltar::counters_cpu_read_register read_reg;
    read_reg.fields.read_target = static_cast<size_t>(cmd);
    read_reg.fields.read_reset = 1;
    read_reg.fields.counter_read_address = counter_read_address;
    read_reg.fields.ready = 0;
    read_reg.fields.dummy_padding = 0;

    log_xdebug(HLD, "%s: Reading counter counter_read_address=%zd", __func__, counter_read_address);

    // Write a 'read-counter' command, specifiying the current counter
    la_status status = device->m_ll_device->write_register(device->m_gb_tree->counters->top->cpu_read, read_reg);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "%s: write_register cpu_read failed: %d\n", __func__, status.value());
        return;
    }

    // Sample the command register until the 'ready' flag is set
    do {
        status = device->m_ll_device->read_register(device->m_gb_tree->counters->top->cpu_read, read_reg);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "%s: read_register cpu_read failed: %d\n", __func__, status.value());
            return;
        }

    } while (read_reg.fields.ready == 0);
}

} // namespace silicon_one
