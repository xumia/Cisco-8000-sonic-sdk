// BEGIN_LEGAL
//
// Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "system/init_performance_helper_base.h"
#include "../../../shared/src/lld/ll_device_context.h"
#include "common/bit_vector.h"

namespace silicon_one
{

// Dword offset of init metadata in CSS memory
static constexpr size_t CSS_MEMORY_INIT_METADATA_BASE = (size_t)la_css_memory_layout_e::INIT_METADATA / 4;

enum boot_state_e {
    UNKNOWN = 0x0,
    COMPLETED = 0x2A,
};

init_performance_helper_base::init_performance_helper_base(const la_device_impl_wptr& device)
    : m_device(device), m_optimization_enabled(false)
{
}

init_performance_helper_base::init_performance_helper_base()
{
}

init_performance_helper_base::~init_performance_helper_base()
{
}

la_status
init_performance_helper_base::store_to_css(const bool init_completed) const
{
    log_xdebug(HLD, "%s", __func__);

    init_metadata idata{0};
    idata.boot_state
        = (init_completed) ? static_cast<uint32_t>(boot_state_e::COMPLETED) : static_cast<uint32_t>(boot_state_e::UNKNOWN);

    auto css_memory = m_device->get_ll_device_sptr()->get_device_context()->m_sbif_css_memory;

    la_status status = m_device->m_ll_device->write_memory(
        *css_memory, CSS_MEMORY_INIT_METADATA_BASE, sizeof(idata) / 4 /* count */, sizeof(idata) /* in_val_sz */, &idata);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
init_performance_helper_base::load_from_css(bool& out_init_completed) const
{
    log_xdebug(HLD, "%s", __func__);

    auto css_memory = m_device->get_ll_device_sptr()->get_device_context()->m_sbif_css_memory;

    // This is a primitive read using bv to avoid having specializations for every ASIC family if we are to use memory struct
    // generated from LBR
    bit_vector css_mem_entry;
    la_status status = m_device->m_ll_device->read_memory(*css_memory, CSS_MEMORY_INIT_METADATA_BASE, css_mem_entry);
    return_on_error(status);

    init_metadata idata{0};
    idata.boot_state = css_mem_entry.bits_from_lsb(0, 32).get_value();

    log_debug(HLD, "%s : idata.boot_state = %d bv:css_mem_entry %s", __func__, idata.boot_state, css_mem_entry.to_string().c_str());

    if (idata.boot_state == static_cast<uint32_t>(boot_state_e::COMPLETED)) {
        out_init_completed = true;
    } else {
        out_init_completed = false;
    }

    return LA_STATUS_SUCCESS;
}

la_status
init_performance_helper_base::reset()
{
    bool enable_boot_optimization;
    m_device->get_bool_property(la_device_property_e::ENABLE_BOOT_OPTIMIZATION, enable_boot_optimization);
    if (!enable_boot_optimization) {
        return LA_STATUS_SUCCESS;
    }

    bool completed;
    la_status status = load_from_css(completed);
    return_on_error(status);

    status = store_to_css(false);
    return_on_error(status);

    m_optimization_enabled = completed;

    return LA_STATUS_SUCCESS;
}

la_status
init_performance_helper_base::set_init_completed() const
{
    bool enable_boot_optimization;
    m_device->get_bool_property(la_device_property_e::ENABLE_BOOT_OPTIMIZATION, enable_boot_optimization);
    if (!enable_boot_optimization) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = store_to_css(true);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

bool
init_performance_helper_base::is_optimization_enabled() const
{
    return m_optimization_enabled;
}

} // namespace silicon_one
