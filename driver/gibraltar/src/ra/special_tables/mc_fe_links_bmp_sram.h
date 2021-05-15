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

#ifndef __MC_FE_LINKS_BMP_SRAM__
#define __MC_FE_LINKS_BMP_SRAM__

#include "mc_fe_links_bmp_sram_base.h"

namespace silicon_one
{

class mc_fe_links_bmp_sram : public mc_fe_links_bmp_sram_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit mc_fe_links_bmp_sram(const ll_device_sptr& ldevice);

protected:
    lld_memory_sptr get_rx_pdr_mc_db_memory(uint64_t shared_db_num, uint64_t shared_db_verifier_mem_num) override;

private:
    mc_fe_links_bmp_sram() = default; // For serialization purposes only.
};
}

#endif
