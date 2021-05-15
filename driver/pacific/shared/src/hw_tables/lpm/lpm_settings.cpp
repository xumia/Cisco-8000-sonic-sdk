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

//
#include "hw_tables/lpm_settings.h"
#include "lpm_common.h"
#include "nplapi/npl_constants.h"

namespace silicon_one
{
lpm_settings
create_lpm_settings(const ll_device_sptr& ldevice)
{
    lpm_settings settings;
    constexpr size_t DONT_CARE = std::numeric_limits<size_t>::max();
    settings.l1_double_bucket_size = 8;
    settings.max_bucket_depth = 16;
    settings.l2_buckets_per_sram_row = 2;
    settings.l2_max_number_of_hbm_buckets = 0;
    settings.tcam_single_width_key_weight = 1;
    settings.tcam_double_width_key_weight = 2;
    settings.tcam_quad_width_key_weight = 4;
    size_t LPM_LPTS_TRAP_BIT = 0;
    settings.trap_destination = NPL_LPM_COMPRESSED_DESTINATION_LPTS_MASK_DEFAULT | (1 << LPM_LPTS_TRAP_BIT);
    settings.l1_buckets_per_sram_row = 2;

    if (is_gibraltar_revision(ldevice)) {
        settings.num_cores = 16;
        settings.num_distributor_lines = 128;
        settings.l2_max_number_of_sram_buckets = 4096;
        settings.distributor_row_width = 80;
        settings.l2_double_bucket_size = 18;
        settings.l2_max_bucket_size = 18;
        settings.hbm_max_bucket_size = 24;
        settings.l1_max_sram_buckets = 4096;
        settings.l1_max_bucket_size = 6;
        settings.tcam_max_quad_entries = 240;
        settings.tcam_bank_size = 512;
        settings.tcam_num_banksets = 2;
    } else if (is_asic4_revision(ldevice)) {
        settings.num_cores = 16;
        settings.num_distributor_lines = 256;
        settings.l2_max_number_of_sram_buckets = 4096;
        settings.distributor_row_width = DONT_CARE;
        settings.l2_double_bucket_size = 18; // TO DO - adjust when decide how to split SRAM banks.
        settings.l2_max_bucket_size = 18;    // TO DO - adjust when decide how to split SRAM banks.
        settings.hbm_max_bucket_size = 24;   // TO DO - adjust when HBM is supported.
        settings.l1_max_sram_buckets = 8192;
        settings.l1_max_bucket_size = 8;
        settings.tcam_max_quad_entries = DONT_CARE; // relevant only for Pacific/GB.
        settings.tcam_bank_size = 2048;
        settings.tcam_num_banksets = 1;
    } else if (is_asic5_revision(ldevice)) {
        settings.num_cores = 1;
        settings.num_distributor_lines = 0;
        settings.l2_max_number_of_sram_buckets = 8192;
        settings.distributor_row_width = DONT_CARE;
        settings.l2_double_bucket_size = 64;
        settings.l2_max_bucket_size = 64;
        settings.hbm_max_bucket_size = 0; // No HBM in Asic5.
        settings.l1_max_sram_buckets = 2048;
        settings.l1_max_bucket_size = 8;
        settings.tcam_max_quad_entries = DONT_CARE; // relevant only for Pacific/GB.
        settings.tcam_bank_size = 512;
        settings.tcam_num_banksets = 1;
    } else if (is_pacific_revision(ldevice)) {
        settings.num_cores = 16;
        settings.num_distributor_lines = 128;
        settings.l2_max_number_of_sram_buckets = 4096;
        settings.distributor_row_width = 80;
        settings.l2_double_bucket_size = 20;
        settings.l2_max_bucket_size = 17;
        settings.hbm_max_bucket_size = 24;
        settings.l1_max_sram_buckets = 4096;
        settings.l1_max_bucket_size = 6;
        settings.tcam_max_quad_entries = 240;
        settings.tcam_bank_size = 512;
        settings.tcam_num_banksets = 2;
    } else {
        dassert_crit(is_asic3_revision(ldevice));
        settings.num_cores = 12;
        settings.num_distributor_lines = 256;
        settings.l2_max_number_of_sram_buckets = 4096;
        settings.distributor_row_width = DONT_CARE;
        settings.l2_double_bucket_size = 16;
        settings.l2_max_bucket_size = 16;
        settings.hbm_max_bucket_size = 0;
        settings.l1_max_sram_buckets = 1024;
        settings.l1_max_bucket_size = 8;
        settings.tcam_max_quad_entries = DONT_CARE;
        settings.tcam_bank_size = 256;
        settings.tcam_num_banksets = 1;
    }

    return settings;
}
}
