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

#include "arc_cpu.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "ll_device_impl.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"

#include <chrono>
#include <thread>

using namespace silicon_one;
using namespace std;

static constexpr auto ARC_CPU_RESET_DELAY = chrono::microseconds(10);

arc_cpu::arc_cpu(ll_device_impl_wptr lld, const arc_cpu_info& arc_info, uint8_t arc_id)
    : m_ll_device(lld), m_arc_id(arc_id), m_arc_run_halt_reg(0), m_arc_status_reg(0), m_reset_reg(0)
{
    initialize(arc_info);
}

void
arc_cpu::initialize(const arc_cpu_info& arc_info)
{
    log_debug(ARC, "%s arc_cpu[%d]: TODO registers here", __func__, m_arc_id);

    m_arc_run_halt_reg = arc_info.arc_run_halt_reg;
    m_arc_status_reg = arc_info.arc_status_reg;
    m_reset_reg = arc_info.reset_reg;
}

uint8_t
arc_cpu::get_arc_id() const
{
    return m_arc_id;
}

la_status
arc_cpu::go()
{
    return m_ll_device->sbif_write_register(m_arc_run_halt_reg, 0x1);
}

la_status
arc_cpu::halt()
{
    return m_ll_device->sbif_write_register(m_arc_run_halt_reg, 0x2);
}

la_status
arc_cpu::reset()
{
    la_status status;
    uint32_t reset_val;

    // Read the current value
    bool tmp = m_ll_device->get_shadow_read_enabled();
    m_ll_device->set_shadow_read_enabled(false);
    status = m_ll_device->sbif_read_register(m_reset_reg, &reset_val);
    return_on_error(status);
    m_ll_device->set_shadow_read_enabled(tmp);

    // Clear the bit for this ARC ID, bits 4:1 are ARC reset bits
    reset_val &= ~(1 << (m_arc_id + 1));
    status = m_ll_device->sbif_write_register(m_reset_reg, reset_val);
    return_on_error(status);

    std::this_thread::sleep_for(ARC_CPU_RESET_DELAY);

    // Set the bit for this ARC ID, bits 4:1 are ARC reset bits
    reset_val |= (1 << (m_arc_id + 1));
    status = m_ll_device->sbif_write_register(m_reset_reg, reset_val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}
