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

#ifndef __LEABA_APB_IMPL_GIBRALTAR_H__
#define __LEABA_APB_IMPL_GIBRALTAR_H__

#include "apb_impl.h"
#include "srm/srm_serdes_address.h"

using namespace std;

namespace silicon_one
{

class apb_impl_pcie_gibraltar : public apb_impl
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    apb_impl_pcie_gibraltar(ll_device_sptr ldev);
    virtual ~apb_impl_pcie_gibraltar() = default;

    /// @brief Overrides
    la_status configure(uint32_t clk_div) override;
    la_status write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv) override;
    la_status read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv) override;

private:
    apb_impl_pcie_gibraltar() = default; // For serialization purposes only
    la_status do_write_read_pcie(bool is_write, uint32_t apb_select, uint32_t addr, const bit_vector* in_bv, bit_vector* out_bv);
    gibraltar_tree_scptr m_gibraltar_tree;
};

class apb_impl_serdes_gibraltar : public apb_impl
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    apb_impl_serdes_gibraltar(ll_device_sptr ldev);
    virtual ~apb_impl_serdes_gibraltar() = default;

    /// @brief Overrides
    la_status configure(uint32_t clk_div) override;
    la_status write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv) override;
    la_status read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv) override;

private:
    union apb_ctrl_16 {
        enum { SIZE = 6, SIZE_IN_BITS = 41 };

        struct fields {
            uint64_t apb_wr_or_rd : 1;
            uint64_t apb_sel : 8;
            uint64_t apb_wr_data : 16;
            uint64_t apb_addr : 16;
            uint64_t dummy_padding : 23;
        } fields;

        uint8_t u8[SIZE];
        inline operator bit_vector()
        {
            uint64_t* storage = (uint64_t*)this;
            return bit_vector(storage, SIZE_IN_BITS);
        }
    };
    union apb_ctrl_24 {
        enum { SIZE = 6, SIZE_IN_BITS = 45 };

        struct fields {
            uint64_t apb_wr_or_rd : 1;
            uint64_t apb_sel : 12;
            uint64_t apb_wr_data : 16;
            uint64_t apb_addr : 16;
            uint64_t dummy_padding : 23;
        } fields;

        uint8_t u8[SIZE];
        inline operator bit_vector()
        {
            uint64_t* storage = (uint64_t*)this;
            return bit_vector(storage, SIZE_IN_BITS);
        }
    };
    union apb_rd_16 {
        enum { SIZE = 3, SIZE_IN_BITS = 24 };

        struct fields {
            uint64_t apb_cmd_done : 8;
            uint64_t apb_rd_data : 16;
            uint64_t dummy_padding : 40;
        } fields;

        uint8_t u8[SIZE];
        inline operator bit_vector()
        {
            uint64_t* storage = (uint64_t*)this;
            return bit_vector(storage, SIZE_IN_BITS);
        }
    };
    union apb_rd_24 {
        enum { SIZE = 4, SIZE_IN_BITS = 28 };

        struct fields {
            uint64_t apb_cmd_done : 12;
            uint64_t apb_rd_data : 16;
            uint64_t dummy_padding : 36;
        } fields;

        uint8_t u8[SIZE];
        inline operator bit_vector()
        {
            uint64_t* storage = (uint64_t*)this;
            return bit_vector(storage, SIZE_IN_BITS);
        }
    };

    enum { APB_SERDES_POLL_MAX = 10 };
    apb_impl_serdes_gibraltar() = default; // For serialization purposes only
    la_status do_write_read(bool is_write,
                            srm_serdes_address serdes_addr,
                            uint32_t addr,
                            const bit_vector* in_bv,
                            bit_vector* out_bv);

    template <class _apb_ctrl, class _apb_rd>
    la_status do_write_read_serdes(lld_register_sptr apb_ctrl_reg,
                                   lld_register_sptr apb_rd_reg,
                                   bool is_write,
                                   uint32_t serdes_select,
                                   uint32_t addr,
                                   const bit_vector* in_bv,
                                   bit_vector* out_bv);

    gibraltar_tree_scptr m_gibraltar_tree;
};

class apb_impl_hbm_gibraltar : public apb_impl
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    apb_impl_hbm_gibraltar(ll_device_sptr ldev);
    virtual ~apb_impl_hbm_gibraltar() = default;

    /// @brief Overrides
    la_status configure(uint32_t clk_div) override;
    la_status write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv) override;
    la_status read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv) override;

private:
    apb_impl_hbm_gibraltar() = default; // For serialization purposes only
    gibraltar_tree_scptr m_gibraltar_tree;
};

} // namespace silicon_one

#endif
