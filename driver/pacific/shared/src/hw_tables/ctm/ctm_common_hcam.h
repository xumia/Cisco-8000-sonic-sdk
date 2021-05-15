// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CTM_COMMON_HCAM_H__
#define __CTM_COMMON_HCAM_H__

#include "api/types/la_common_types.h"
#include "ctm/ctm_common.h"

namespace silicon_one
{
enum hcam_dir { NONE, HCAM_RX, HCAM_TX };

struct tcam_desc_hcam {
    la_slice_id_t slice_idx;
    hcam_dir rx_or_tx;
    size_t tcam_idx; // 0-2

    tcam_desc_hcam() : slice_idx(0), rx_or_tx(hcam_dir::HCAM_RX), tcam_idx(0){};
    tcam_desc_hcam(la_slice_id_t in_slice_idx, hcam_dir in_rx_or_tx, size_t in_tcam_idx)
        : slice_idx(in_slice_idx), rx_or_tx(in_rx_or_tx), tcam_idx(in_tcam_idx){};
    bool operator==(const tcam_desc_hcam& ref) const
    {
        return std::tie(slice_idx, rx_or_tx, tcam_idx) == std::tie(ref.slice_idx, ref.rx_or_tx, ref.tcam_idx);
    }
    bool operator<(const tcam_desc_hcam& ref) const
    {
        return std::tie(slice_idx, rx_or_tx, tcam_idx) < std::tie(ref.slice_idx, ref.rx_or_tx, ref.tcam_idx);
    }
};

}; // namespace silicon_one

#endif // __CTM_COMMON_HCAM_H__
