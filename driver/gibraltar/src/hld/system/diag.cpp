// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "diag_mbist.h"
#include "la_hbm_handler_impl.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"

#include "api/system/la_hbm_handler.h"

using namespace std;

namespace silicon_one
{

la_status
la_device_impl::diagnostics_test(test_feature_e feature)
{
    start_api_call("feature=", feature);

    if (is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    // Check if the device is in reset. Otherwise, we cannot run MBIST on GB.
    bool core_hard_rstn;
    la_status rc = read_core_hard_rstn(core_hard_rstn);
    return_on_error(rc);
    if (core_hard_rstn || m_init_phase != init_phase_e::CREATED) {
        log_warning(HLD,
                    "%s: running MBIST on an active device, core_hard_rstn=%d, init_phase=%d",
                    __func__,
                    core_hard_rstn,
                    (int)m_init_phase);
    }

    // Enable cpu2jtag
    rc = m_cpu2jtag_handler->enable(m_device_frequency_int_khz, m_tck_frequency_mhz);
    return_on_error_log(rc, HLD, ERROR, "%s: failed enabling cpu2jtag", __func__);

    switch (feature) {
    case test_feature_e::MEM_BIST:
        rc = mbist_run();
        break;

    case test_feature_e::HBM: {
        auto hbm_handler = std::make_shared<la_hbm_handler_impl>(shared_from_this());
        rc = hbm_handler->run_mbist(false);
    } break;

    case test_feature_e::MEM_BIST_CHIPLETS:
        rc = LA_STATUS_ENOTIMPLEMENTED;
        break;
    }

    bool ignore_mbist_errors = false;
    get_bool_property(la_device_property_e::IGNORE_MBIST_ERRORS, ignore_mbist_errors);
    if (rc) {
        log_warning(HLD, "%s: Device diagnostics failed, ignore=%d", __func__, ignore_mbist_errors);
        if (!ignore_mbist_errors) {
            return_on_error(rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_run()
{
    std::unique_ptr<mbist> obj = silicon_one::make_unique<mbist>(this);

    bool enable_mbist_repair = false;
    get_bool_property(la_device_property_e::ENABLE_MBIST_REPAIR, enable_mbist_repair);

    mbist::result res{};
    la_status rc = obj->run(enable_mbist_repair, res);

    return rc;
}
}
