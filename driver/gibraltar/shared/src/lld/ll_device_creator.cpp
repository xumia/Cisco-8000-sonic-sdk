// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "ll_device_impl.h"
#include "ll_filtered_device_impl.h"
#include "lld/ll_device.h"

#include "common/logger.h"

#include <fstream>
#include <linux/limits.h>

using namespace std;
using namespace silicon_one;

ll_device_sptr
ll_device::create(la_device_id_t device_id,
                  const char* device_path,
                  device_simulator* sim,
                  const la_platform_cbs& cbs,
                  bool filtered_dev)
{
    char* lld_filtering_allowed_config_file_char = getenv("LLD_ALLOWED_BLOCK_ID_FILE");

    bool use_filtered = false;

    // Don't allow unbound input strings
    char dp[PATH_MAX];
    strncpy(dp, device_path, sizeof(dp) - 1);
    dp[sizeof(dp) - 1] = '\0';

    std::string lld_filtering_allowed_config_file = "empty";
    if (lld_filtering_allowed_config_file_char) {
        lld_filtering_allowed_config_file = std::string(lld_filtering_allowed_config_file_char);
        std::ifstream infile(lld_filtering_allowed_config_file_char);
        use_filtered = infile.good();
        if (!use_filtered) {
            log_warning(LLD, "File %s is unaccessible, not using LLD filtered", lld_filtering_allowed_config_file_char);
        }
    }

    filtered_dev |= use_filtered;
    ll_device_impl_sptr dev
        = filtered_dev ? std::make_shared<ll_filtered_device_impl>(device_id, use_filtered, lld_filtering_allowed_config_file)
                       : std::make_shared<ll_device_impl>(device_id);

    log_info(LLD, "Using %s LLD implementation", filtered_dev ? "filtered" : "regular");

    if (!dev) {
        return nullptr;
    }

    if (!dev->initialize(dp, sim, cbs)) {
        return nullptr;
    }

    log_info(LLD,
             "%s: (ID = %d, path = %s) completed successfully. Using %s LLD implementation",
             __func__,
             device_id,
             device_path,
             use_filtered ? "filtered" : "regular");

    return dev;
}

ll_device_sptr
ll_device::create(la_device_id_t device_id, const char* device_path, device_simulator* sim, const la_platform_cbs& cbs)
{
    return create(device_id, device_path, sim, cbs, false);
}

ll_device_sptr
ll_device::create(la_device_id_t device_id, const char* device_path)
{
    la_platform_cbs cbs = {.user_data = 0,
                           .i2c_register_access = nullptr,
                           .dma_alloc = nullptr,
                           .dma_free = nullptr,
                           .open_device = nullptr,
                           .close_device = nullptr};

    return create(device_id, device_path, nullptr /* sim */, cbs);
}
