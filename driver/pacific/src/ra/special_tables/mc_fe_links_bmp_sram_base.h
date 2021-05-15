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

#ifndef __MC_FE_LINKS_BMP_SRAM_BASE__
#define __MC_FE_LINKS_BMP_SRAM_BASE__

#include "hw_tables/logical_sram.h"
#include "lld/lld_fwd.h"

namespace silicon_one
{

class ll_device;

class mc_fe_links_bmp_sram_base : public logical_sram
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    mc_fe_links_bmp_sram_base(const ll_device_sptr& ldevice);

    /// Logical SRAM API
    virtual la_status write(size_t line, const bit_vector& value);
    virtual size_t max_size() const;

protected:
    mc_fe_links_bmp_sram_base() = default; // For serialization purposes only.
    virtual lld_memory_sptr get_rx_pdr_mc_db_memory(uint64_t shared_db_num, uint64_t shared_db_verifier_mem_num) = 0;

    // Pointer to low level device.
    ll_device_sptr m_ll_device;

private:
    void add_ecc_to_entry(bit_vector128_t& entry, size_t ecc_lsb) const;
};
}

#endif
