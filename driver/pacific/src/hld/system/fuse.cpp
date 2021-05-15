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

#include "api_tracer.h"
#include "common/logger.h"
#include "cpu2jtag/cpu2jtag.h"
#include "la_device_impl.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

#include <chrono>
#include <thread>

using namespace std;

namespace silicon_one
{

static const char* DEFAULT_TEST_REG_VALUE
    = "0x83e06c0c5fffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000001fff"
      "fffffffffffffffffffffe047fffffffffffe0000000000000000005b689281ffffffffffffffffffffffffff"
      "fffffe0000000000001e7ffffffffffffffffffffffff9401c0000b82000000000000000000000001";

enum {
    // fuse value bit fields
    FUSE_DEVICE_ID_MSB = 62,
    FUSE_USERBITS_MSB = 127,

    FUSE_WIDTH_BITS = 4096,

    // TEST_REG bit fields
    TR_FUSE_CTRL_SEL_AS_0 = 439,
    TR_FUSE_CTRL_TAP_CTRL = 444,
    TR_FUSE_CTRL_DISABLE_RESET = 446,
    TR_FUSE_CTRL_CORE_REQ_EN = 443,
    TR_FUSE_CTRL_RESET_L = 445,
    TR_FUSE_CTRL_SPEED_2 = 482,

    TR_WIDTH_BITS = 1028,
};

la_status
la_device_impl::read_fuse(bit_vector& out_bv)
{
    if (is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    la_status rc = do_read_fuse(true, out_bv);

    log_debug(HLD, "%s: fuse_data=0x%s", __func__, out_bv.to_string().c_str());
    log_debug(HLD, "%s: device_id=0x%s", __func__, out_bv.bits(FUSE_DEVICE_ID_MSB, 0).to_string().c_str());
    log_debug(HLD, "%s: fuse_userbits=0x%s", __func__, out_bv.bits(FUSE_USERBITS_MSB, 0).to_string().c_str());

    bit_vector fuse_userbits;
    read_fuse_userbits(fuse_userbits);
    if (fuse_userbits != out_bv.bits(FUSE_USERBITS_MSB, 0)) {
        log_warning(HLD, "%s: fuse_userbits were not reloaded correctly", __func__);
    }

    return rc;
}

la_status
la_device_impl::read_fuse_no_reload(bit_vector& out_bv)
{
    if (is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    la_status rc = do_read_fuse(false, out_bv);

    log_debug(HLD, "%s: fuse_data=0x%s", __func__, out_bv.to_string().c_str());
    log_debug(HLD, "%s: device_id=0x%s", __func__, out_bv.bits(FUSE_DEVICE_ID_MSB, 0).to_string().c_str());
    log_debug(HLD, "%s: fuse_userbits=0x%s", __func__, out_bv.bits(FUSE_USERBITS_MSB, 0).to_string().c_str());

    return rc;
}

la_status
la_device_impl::do_read_fuse(bool reload, bit_vector& out_bv)
{
    bit_vector default_test_reg_value(DEFAULT_TEST_REG_VALUE);
    bit_vector test_reg_value;
    bit_vector fuse_data;

    la_status rc = setup_tap_for_fuse_access(default_test_reg_value, test_reg_value);
    return_on_error(rc);
    rc = configure_tck_on_fuse_read(test_reg_value, 0);
    return_on_error(rc);
    rc = read_fuse_into_4k_bit_buffer();
    return_on_error(rc);
    rc = configure_tck_on_fuse_read(test_reg_value, 1);
    return_on_error(rc);

    // Read the fuse value from 4k-bit buffer to CPU, the 4k-bit buffer is invalidated.
    rc = read_fuse_4k_bit_buffer(0, fuse_data);
    return_on_error(rc);

    if (reload) {
        // Read the fuse value into the 4k-bit buffer again.
        // This enables fetching the lower 4 dwords of fuse value from sbif.efuse_userbits_reg0,1,2,3.
        rc = read_fuse_into_4k_bit_buffer();
        return_on_error(rc);

        // Set TAP_CTRL=0 before setting TESTREG to the default value.
        // As a result, the 4k-bit-buffer is not cleared.
        log_debug(HLD, "configuring TR_FUSE_CTRL_TAP_CTRL=0");
        test_reg_value.set_bit(TR_FUSE_CTRL_TAP_CTRL, 0);
        rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
            (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, TR_WIDTH_BITS, test_reg_value);
        return_on_error(rc);
    }

    log_debug(HLD, "configuring the TAP's TESTREG to its default value");
    rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, TR_WIDTH_BITS, default_test_reg_value);
    return_on_error(rc);

    out_bv = fuse_data;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::reload_fuse_userbits(bit_vector& out_bv)
{
    if (is_simulated_or_emulated_device()) {
        return LA_STATUS_SUCCESS;
    }

    bit_vector default_test_reg_value(DEFAULT_TEST_REG_VALUE);
    bit_vector test_reg_value;

    la_status rc = setup_tap_for_fuse_access(default_test_reg_value, test_reg_value);
    return_on_error(rc);
    rc = configure_tck_on_fuse_read(test_reg_value, 0);
    return_on_error(rc);
    rc = read_fuse_into_4k_bit_buffer();
    return_on_error(rc);
    rc = configure_tck_on_fuse_read(test_reg_value, 1);
    return_on_error(rc);

    log_debug(HLD, "configuring TR_FUSE_CTRL_TAP_CTRL=0");
    test_reg_value.set_bit(TR_FUSE_CTRL_TAP_CTRL, 0);
    rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, TR_WIDTH_BITS, test_reg_value);
    return_on_error(rc);

    log_debug(HLD, "configuring the TAP's TESTREG to its default value");
    rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, TR_WIDTH_BITS, default_test_reg_value);
    return_on_error(rc);

    // efuse value is loaded into 4kbit buffer.
    // A "read" from efuse_userbits fetches the first 128bits of efuse value.
    read_fuse_userbits(out_bv);

    log_debug(HLD, "%s: efuse_userbits=0x%s", __func__, out_bv.to_string().c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::read_fuse_userbits(bit_vector& out_bv)
{
    bit_vector dword[4];

    la_status rc = m_ll_device->read_register(*m_pacific_tree->sbif->efuse_userbits_reg0, dword[0]);
    rc = m_ll_device->read_register(*m_pacific_tree->sbif->efuse_userbits_reg1, dword[1]);
    return_on_error(rc);
    rc = m_ll_device->read_register(*m_pacific_tree->sbif->efuse_userbits_reg2, dword[2]);
    return_on_error(rc);
    rc = m_ll_device->read_register(*m_pacific_tree->sbif->efuse_userbits_reg3, dword[3]);
    return_on_error(rc);

    out_bv = (dword[3] << 96) | (dword[2] << 64) | (dword[1] << 32) | dword[0];

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::setup_tap_for_fuse_access(const bit_vector& test_reg_value_in, bit_vector& test_reg_value_out)
{
    bit_vector test_reg_value = test_reg_value_in;

    log_debug(HLD,
              "configure TR_FUSE_CTRL_SEL_AS_0=1, TR_FUSE_CTRL_TAP_CTRL=1, TR_FUSE_CTRL_DISABLE_RESET=1, "
              "TR_FUSE_CTRL_CORE_REQ_EN=0, TR_FUSE_CTRL_RESET_L=0, TR_FUSE_CTRL_SPEED_2=1");
    test_reg_value.set_bit(TR_FUSE_CTRL_SEL_AS_0, 1);
    test_reg_value.set_bit(TR_FUSE_CTRL_TAP_CTRL, 1);
    test_reg_value.set_bit(TR_FUSE_CTRL_DISABLE_RESET, 1);
    test_reg_value.set_bit(TR_FUSE_CTRL_CORE_REQ_EN, 0);
    test_reg_value.set_bit(TR_FUSE_CTRL_RESET_L, 0);
    test_reg_value.set_bit(TR_FUSE_CTRL_SPEED_2, 1);
    la_status rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, TR_WIDTH_BITS, test_reg_value);
    return_on_error(rc);

    log_debug(HLD, "configure TR_FUSE_CTRL_RESET_L=1");
    test_reg_value.set_bit(TR_FUSE_CTRL_RESET_L, 1);
    rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, TR_WIDTH_BITS, test_reg_value);
    return_on_error(rc);

    test_reg_value_out = test_reg_value;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::configure_tck_on_fuse_read(bit_vector& test_reg_value, bool enable_tck)
{
    bool disable_tck = !enable_tck;
    log_debug(HLD, "configuring TR_DFT_CLK_IS_DFT_CLK_IN=%d", disable_tck);
    test_reg_value.set_bit(1001, disable_tck);

    la_status rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, TR_WIDTH_BITS, test_reg_value);

    return rc;
}

la_status
la_device_impl::write_fuse_4k_bit_buffer(const bit_vector& write_data_in)
{
    bit_vector tdo;
    log_debug(HLD, "writing 0x%s to the 4k-bit-buffer of the fuse", write_data_in.to_string().c_str());
    la_status rc = m_cpu2jtag_handler->load_ir_dr_no_tdo(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_WRITE_TO_BUFFER, FUSE_WIDTH_BITS, write_data_in);
    return rc;
}

la_status
la_device_impl::read_fuse_into_4k_bit_buffer()
{
    log_debug(HLD, "reading the fuse into its 4k-bit-buffer");
    la_status rc = m_cpu2jtag_handler->load_ir((uint16_t)cpu2jtag::jtag_ir_e::FUSE_READ_TO_BUFFER);
    return_on_error(rc);

    this_thread::sleep_for(chrono::seconds(1));
    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::read_fuse_4k_bit_buffer(const bit_vector& write_data_in, bit_vector& fuse_data_out)
{
    log_debug(HLD, "reading the 4k-bit-buffer of the fuse while writing 0x%s", write_data_in.to_string().c_str());
    la_status rc = m_cpu2jtag_handler->load_ir_dr(
        (uint16_t)cpu2jtag::jtag_ir_e::FUSE_CONFIGURE_TEST_REG, FUSE_WIDTH_BITS, write_data_in, fuse_data_out);

    return rc;
}

int
la_device_impl::get_refclk_from_fuse(bit_vector& bv) const
{
    // refclk configuration in fuse[107,110], one bit group pf consecutive 3 IFGs.
    // fuse[111] indicates that the configuration is valid.
    int refclk = bv.bits(111, 107).get_value();
    return refclk;
}

} // namespace silicon_one
