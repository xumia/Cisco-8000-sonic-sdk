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

#include "apb_impl_gibraltar.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/gibraltar_reg_structs.h"

#include <chrono>
#include <thread>

using namespace std;

namespace silicon_one
{

apb_impl_pcie_gibraltar::apb_impl_pcie_gibraltar(ll_device_sptr ldev)
    : apb_impl(ldev, apb_interface_type_e::PCIE), m_gibraltar_tree(ldev->get_gibraltar_tree_scptr())

{
}

apb_impl_serdes_gibraltar::apb_impl_serdes_gibraltar(ll_device_sptr ldev)
    : apb_impl(ldev, apb_interface_type_e::SERDES), m_gibraltar_tree(ldev->get_gibraltar_tree_scptr())
{
}

apb_impl_hbm_gibraltar::apb_impl_hbm_gibraltar(ll_device_sptr ldev)
    : apb_impl(ldev, apb_interface_type_e::HBM), m_gibraltar_tree(ldev->get_gibraltar_tree_scptr())
{
}

/// @brief Gibraltar PCIe/MAC port/HBM SerDes implementations
la_status
apb_impl_pcie_gibraltar::configure(uint32_t clk_div)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
apb_impl_pcie_gibraltar::write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv)
{
    start_apb_call("%s: apb_select=0x%x, addr=0x%x, in_bv=0x%s", __func__, apb_select, addr, in_bv.to_string().c_str());

    return do_write_read_pcie(true, apb_select, addr, &in_bv, nullptr);
}

la_status
apb_impl_pcie_gibraltar::read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv)
{
    start_apb_call("%s: apb_select=0x%x, addr=0x%x", __func__, apb_select, addr);

    return do_write_read_pcie(false, apb_select, addr, nullptr, &out_bv);
}

la_status
apb_impl_pcie_gibraltar::do_write_read_pcie(bool is_write,
                                            uint32_t apb_select,
                                            uint32_t addr,
                                            const bit_vector* in_bv,
                                            bit_vector* out_bv)
{
    // Check if 'select' has exactly one pcie_apb bit
    if (apb_select != (uint32_t)pcie_apb_select_e::CORE && apb_select != (uint32_t)pcie_apb_select_e::PHY) {
        log_err(APB, "bad apb_select=0x%x", apb_select);
        return LA_STATUS_EINVAL;
    }

    // Write the address + data, 'valid' remains deasserted
    m_ll_device->write_register(m_gibraltar_tree->sbif->pcie_apb_addr_cfg_reg, addr);
    if (is_write) {
        m_ll_device->write_register(m_gibraltar_tree->sbif->pcie_apb_wdata_cfg_reg, *in_bv);
    }

    // Assert core_valid or phy_valid + 'write' if is_write==true
    gibraltar::sbif_pcie_apb_cfg_reg_register cfg_val = {{0}};
    cfg_val.fields.pcie_apb_core_valid = (apb_select & (uint32_t)pcie_apb_select_e::CORE) ? 1 : 0;
    cfg_val.fields.pcie_apb_phy_valid = (apb_select & (uint32_t)pcie_apb_select_e::PHY) ? 1 : 0;
    cfg_val.fields.pcie_apb_write = is_write ? 1 : 0;
    m_ll_device->write_register(m_gibraltar_tree->sbif->pcie_apb_cfg_reg, cfg_val);

    // Deassert all bits
    m_ll_device->write_register(m_gibraltar_tree->sbif->pcie_apb_cfg_reg, 0);

    // Wait before reading status
    this_thread::sleep_for(chrono::microseconds(1));

    // Read the status, status is sticky and gets updated by read/write response.
    bit_vector apb_status;
    m_ll_device->read_register(m_gibraltar_tree->sbif->pcie_apb_status_reg, apb_status);
    if (apb_select & apb_status.get_value()) {
        log_err(APB, "apb error, apb_select=0x%x, status=0x%lx", apb_select, apb_status.get_value());
        return LA_STATUS_EUNKNOWN;
    }

    // If 'write', we are done
    if (is_write) {
        return LA_STATUS_SUCCESS;
    }

    // Read the data
    if (apb_select & (uint32_t)pcie_apb_select_e::CORE) {
        m_ll_device->read_register(m_gibraltar_tree->sbif->pcie_apb_core_rdata_status_reg, *out_bv);
    } else {
        m_ll_device->read_register(m_gibraltar_tree->sbif->pcie_apb_phy_rdata_status_reg, *out_bv);
    }

    return LA_STATUS_SUCCESS;
}

static inline la_status
is_serdes_pool16(size_t slice, size_t ifg, bool& out_is_16)
{
    static constexpr bool is_16[apb_impl::NUM_SLICES_PER_DEVICE_GB][apb_impl::NUM_IFGS_PER_SLICE_GB]
        = {{false, false}, {false, true}, {true, false}, {false, true}, {true, false}, {false, false}};
    if (slice >= apb_impl::NUM_SLICES_PER_DEVICE_GB || ifg >= apb_impl::NUM_IFGS_PER_SLICE_GB) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_is_16 = is_16[slice][ifg];

    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_serdes_gibraltar::configure(uint32_t clk_div)
{
    start_apb_call("%s: clk_div=0x%x", __func__, clk_div);

    const uint32_t max_clock_divider = (1 << gibraltar::serdes_pool16_apb_clk_div_register::SIZE_IN_BITS) - 1;
    if (clk_div > max_clock_divider) {
        log_err(APB, "%s: clk_div=0x%x exceeds max=%d", __func__, clk_div, max_clock_divider);
        return LA_STATUS_EOUTOFRANGE;
    }

    gibraltar::serdes_pool16_apb_clk_div_register val{{0}};
    val.fields.apb_clk_div_val = clk_div;

    for (size_t slice = 0; slice < NUM_SLICES_PER_DEVICE_GB; ++slice) {
        for (size_t ifg = 0; ifg < NUM_IFGS_PER_SLICE_GB; ++ifg) {
            bool is_16 = false;
            is_serdes_pool16(slice, ifg, is_16);

            lld_register_sptr reg = (is_16 ? m_gibraltar_tree->slice[slice]->ifg[ifg]->serdes_pool16->apb_clk_div
                                           : m_gibraltar_tree->slice[slice]->ifg[ifg]->serdes_pool24->apb_clk_div);

            la_status rc = m_ll_device->write_register(reg, val);
            return_on_error(rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_serdes_gibraltar::write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv)
{
    srm_serdes_address serdes_addr = {{0}};
    serdes_addr.u32 = apb_select;
    start_apb_call(
        "%s: addressing_mode=%d, device_id=%d, slice=%d, ifg=%d, serdes_package=%d, serdes_index=%d, addr=0x%x, in_bv=0x%s",
        __func__,
        serdes_addr.fields.addressing_mode,
        serdes_addr.fields.device_id,
        serdes_addr.fields.slice,
        serdes_addr.fields.ifg,
        serdes_addr.fields.serdes_package,
        serdes_addr.fields.serdes_index,
        addr,
        in_bv.to_string().c_str());

    switch ((srm_serdes_addressing_mode_e)serdes_addr.fields.addressing_mode) {
    case srm_serdes_addressing_mode_e::SERDES:
    case srm_serdes_addressing_mode_e::IFG: {
        la_status rc = do_write_read(true /* is_write */, serdes_addr, addr, &in_bv, nullptr);
        return_on_error(rc);
        break;
    }
    case srm_serdes_addressing_mode_e::DEVICE: {
        // TODO: consider using CIF multicast instead of looping through slices/ifgs.
        auto tmp = serdes_addr;
        tmp.fields.addressing_mode = (uint32_t)srm_serdes_addressing_mode_e::IFG;
        for (uint32_t slice = 0; slice < NUM_SLICES_PER_DEVICE_GB; ++slice) {
            for (uint32_t ifg = 0; ifg < NUM_IFGS_PER_SLICE_GB; ++ifg) {
                tmp.fields.slice = slice;
                tmp.fields.ifg = ifg;
                la_status rc = do_write_read(true /* is_write */, tmp, addr, &in_bv, nullptr);
                return_on_error(rc);
            }
        }
        break;
    }
    default:
        log_err(APB, "%s: bad addressing mode=%d", __func__, serdes_addr.fields.addressing_mode);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_serdes_gibraltar::read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv)
{
    srm_serdes_address serdes_addr = {{0}};
    serdes_addr.u32 = apb_select;
    start_apb_call("%s: addressing_mode=%d, device_id=%d, slice=%d, ifg=%d, serdes_package=%d, serdes_index=%d, addr=0x%x",
                   __func__,
                   serdes_addr.fields.addressing_mode,
                   serdes_addr.fields.device_id,
                   serdes_addr.fields.slice,
                   serdes_addr.fields.ifg,
                   serdes_addr.fields.serdes_package,
                   serdes_addr.fields.serdes_index,
                   addr);

    if (serdes_addr.fields.addressing_mode != (uint32_t)srm_serdes_addressing_mode_e::SERDES) {
        log_err(APB, "%s: bad addressing mode=%d", __func__, serdes_addr.fields.addressing_mode);
        return LA_STATUS_EINVAL;
    }

    return do_write_read(false /* is_write */, serdes_addr, addr, nullptr, &out_bv);
}

la_status
apb_impl_serdes_gibraltar::do_write_read(bool is_write,
                                         srm_serdes_address serdes_addr,
                                         uint32_t addr,
                                         const bit_vector* in_bv,
                                         bit_vector* out_bv)
{
    size_t slice = serdes_addr.fields.slice;
    size_t ifg = serdes_addr.fields.ifg;

    bool is_16 = false;
    la_status rc = is_serdes_pool16(slice, ifg, is_16);
    return_on_error(rc);

    uint32_t serdes_select;
    if (serdes_addr.fields.addressing_mode == (uint32_t)srm_serdes_addressing_mode_e::SERDES) {
        serdes_select = 1 << serdes_addr.fields.serdes_package;
    } else if (serdes_addr.fields.addressing_mode == (uint32_t)srm_serdes_addressing_mode_e::IFG) {
        serdes_select = is_16 ? 0xff : 0xfff;
    } else {
        return LA_STATUS_EINVAL;
    }

    if (is_16) {
        const auto& lbr = m_gibraltar_tree->slice[slice]->ifg[ifg]->serdes_pool16;
        rc = do_write_read_serdes<apb_ctrl_16, apb_rd_16>(
            lbr->apb_ctrl_reg, lbr->apb_rd_reg, is_write, serdes_select, addr, in_bv, out_bv);
    } else {
        const auto& lbr = m_gibraltar_tree->slice[slice]->ifg[ifg]->serdes_pool24;
        rc = do_write_read_serdes<apb_ctrl_24, apb_rd_24>(
            lbr->apb_ctrl_reg, lbr->apb_rd_reg, is_write, serdes_select, addr, in_bv, out_bv);
    }

    return rc;
}

template <class _apb_ctrl, class _apb_rd>
la_status
apb_impl_serdes_gibraltar::do_write_read_serdes(lld_register_sptr apb_ctrl_reg,
                                                lld_register_sptr apb_rd_reg,
                                                bool is_write,
                                                uint32_t serdes_select,
                                                uint32_t addr,
                                                const bit_vector* in_bv,
                                                bit_vector* out_bv)
{
    log_debug(APB,
              "%s: apb_ctrl=%s, apb_ctrl_bits=%d, apb_rd=%s, apb_rd_bits=%d, is_write=%d, serdes_select=0x%x",
              __func__,
              apb_ctrl_reg->get_name().c_str(),
              _apb_ctrl::SIZE_IN_BITS,
              apb_rd_reg->get_name().c_str(),
              _apb_rd::SIZE_IN_BITS,
              is_write,
              serdes_select);
    dassert_crit(_apb_ctrl::SIZE_IN_BITS == apb_ctrl_reg->get_desc()->width_in_bits);
    dassert_crit(_apb_rd::SIZE_IN_BITS == apb_rd_reg->get_desc()->width_in_bits);

    // Send APB request
    _apb_ctrl apv_ctrl_val{{0}};
    apv_ctrl_val.fields.apb_wr_or_rd = is_write;
    apv_ctrl_val.fields.apb_sel = serdes_select;
    apv_ctrl_val.fields.apb_wr_data = (is_write ? (uint16_t)in_bv->get_value() : 0);
    apv_ctrl_val.fields.apb_addr = (uint16_t)addr;

    la_status rc = m_ll_device->write_register(apb_ctrl_reg, apv_ctrl_val);
    return_on_error(rc);

    // Wait for completion
    _apb_rd apb_rd_val{{0}};
    int poll_i = 0;
    for (; poll_i < APB_SERDES_POLL_MAX; ++poll_i) {
        rc = m_ll_device->read_register(apb_rd_reg, apb_rd_val);
        return_on_error(rc);

        if (apb_rd_val.fields.apb_cmd_done & serdes_select) {
            break;
        }

        this_thread::yield();
    }

    if (poll_i == APB_SERDES_POLL_MAX) {
        log_err(APB,
                "%s: no APB response, %s, is_write=%d, serdes_select=0x%x",
                __func__,
                apb_rd_reg->get_name().c_str(),
                is_write,
                serdes_select);
        return LA_STATUS_EUNKNOWN;
    }

    if (!is_write) {
        *out_bv = apb_rd_val.fields.apb_rd_data;
    }

    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_hbm_gibraltar::configure(uint32_t clk_div)
{
    start_apb_call("%s: clk_div=0x%x", __func__, clk_div);

    const uint32_t max_clock_divider = (1 << gibraltar::hbm_hbm_clock_config_register::fields::APB_CLOCK_DIVISION_WIDTH) - 1;
    if (clk_div > max_clock_divider) {
        log_err(APB, "%s: clk_div=0x%x exceeds max=0x%x", __func__, clk_div, max_clock_divider);
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status rc;

    // Put APB in reset
    for (const auto& hbm : m_gibraltar_tree->hbm->db) {
        gibraltar::hbm_hbm_resets_register val;

        rc = m_ll_device->read_register(hbm->hbm_resets, val);
        return_on_error(rc);

        val.fields.apb_rstn = 0;
        rc = m_ll_device->write_register(hbm->hbm_resets, val);
        return_on_error(rc);
    }

    // Set APB clk divider
    for (const auto& hbm : m_gibraltar_tree->hbm->db) {
        gibraltar::hbm_hbm_clock_config_register val;

        rc = m_ll_device->read_register(hbm->hbm_clock_config, val);
        return_on_error(rc);

        val.fields.apb_clock_division = clk_div;
        rc = m_ll_device->write_register(hbm->hbm_clock_config, val);
        return_on_error(rc);
    }

    // Take APB out of reset
    for (const auto& hbm : m_gibraltar_tree->hbm->db) {
        gibraltar::hbm_hbm_resets_register val;

        rc = m_ll_device->read_register(hbm->hbm_resets, val);
        return_on_error(rc);

        val.fields.apb_rstn = 1;
        rc = m_ll_device->write_register(hbm->hbm_resets, val);
        return_on_error(rc);
    }

    // Give control to APB bus (HBM PHY has two masters - APB and IEEE, here we give control to APB).
    for (const auto& hbm : m_gibraltar_tree->hbm->db) {
        gibraltar::hbm_apb_ctrl_register val;

        rc = m_ll_device->read_register(hbm->apb_ctrl, val);
        return_on_error(rc);

        val.fields.apb_ctrl_mode = 0;
        rc = m_ll_device->write_register(hbm->apb_ctrl, val);
        return_on_error(rc);

        val.fields.apb_ctrl_req = 1;
        rc = m_ll_device->write_register(hbm->apb_ctrl, val);
        return_on_error(rc);

        val.fields.apb_ctrl_req = 0;
        rc = m_ll_device->write_register(hbm->apb_ctrl, val);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_hbm_gibraltar::write(uint32_t apb_select, uint32_t addr, const bit_vector& in_bv)
{
    start_apb_call("%s: apb_select=0x%x, addr=0x%x, in_bv=0x%s", __func__, apb_select, addr, in_bv.to_string().c_str());

    // "write" can target hbm->db[0] or hbm->db[1] or both - bits 0 and/or 1 must be set.
    if (!(apb_select & 0x3) || (apb_select & ~0x3)) {
        return LA_STATUS_EINVAL;
    }
    const uint32_t num_of_entries = m_gibraltar_tree->hbm->db[0]->phy_apb->get_desc()->entries;
    if (addr >= num_of_entries) {
        return LA_STATUS_EOUTOFRANGE;
    }

    for (size_t i = 0; i < 2; ++i) {
        if (!bit_utils::get_bit(apb_select, i)) {
            continue;
        }
        la_status rc = m_ll_device->write_memory(m_gibraltar_tree->hbm->db[i]->phy_apb, addr, in_bv);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
apb_impl_hbm_gibraltar::read(uint32_t apb_select, uint32_t addr, bit_vector& out_bv)
{
    start_apb_call("%s: apb_select=0x%x, addr=0x%x", __func__, apb_select, addr);

    // "read" can target either hbm->db[0] or hbm->db[1] but not both.
    if (apb_select != 0x1 && apb_select != 0x2) {
        return LA_STATUS_EINVAL;
    }

    size_t idx = (apb_select == 0x1 ? 0 : 1);

    // Check valid
    const uint32_t num_of_entries = m_gibraltar_tree->hbm->db[idx]->phy_apb->get_desc()->entries;
    if (addr >= num_of_entries) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Read
    la_status rc = m_ll_device->read_memory(m_gibraltar_tree->hbm->db[idx]->phy_apb, addr, out_bv);

    return rc;
}

} // namespace silicon_one
