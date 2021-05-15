// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <list>
#include <vector>

#include "api_tracer.h"
#include "la_device_impl.h"
#include "la_hbm_handler_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

#include "api/system/la_hbm_handler.h"

namespace silicon_one
{

enum {
    MBIST_PASS_REG_ADDR = 0x39,
    MBIST_FAIL_REG_ADDR = 0x3A,
    MBIST_STAT_REG_ADDR = 0x3B,
    MBIST_CFG_REG_ADDR = 0x46,
};

la_status
la_device_impl::diagnostics_test(test_feature_e feature)
{
    start_api_call("feature=", feature);

    if (m_init_phase != init_phase_e::DEVICE) {
        return LA_STATUS_EINVAL;
    }

    bool ignore_mbist_errors = false;
    get_bool_property(la_device_property_e::IGNORE_MBIST_ERRORS, ignore_mbist_errors);

    la_status rc = do_diagnostics_test(feature);
    if (rc) {
        log_warning(HLD, "%s: Device diagnostics failed, ignore=%d", __func__, ignore_mbist_errors);
        if (!ignore_mbist_errors) {
            return_on_error(rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::do_diagnostics_test(test_feature_e feature)
{
    if (is_simulated_or_emulated_device()) {
        // Not real device - no diagnostics should be executed.
        return LA_STATUS_SUCCESS;
    }

    switch (feature) {
    case test_feature_e::MEM_BIST:
        return mbist_run();

    case test_feature_e::HBM:
        return mbist_hbm_run();

    case test_feature_e::MEM_BIST_CHIPLETS:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return LA_STATUS_EUNKNOWN;
}

static bool
is_hbm_mmu_block(lld_block_scptr block)
{
    std::string name = block->get_name();

    // Look for partial match (substring)
    return (name.find("hbm") != std::string::npos || name.find("mmu") != std::string::npos);
}

la_status
la_device_impl::mbist_activate_write(bit_vector block_mbist_val, bit_vector sbm_mbist_val, bit_vector sms_mbist_val)
{
    bool does_hbm_exist;
    la_status status = hbm_exists(does_hbm_exist);
    return_on_error(status);

    pacific_tree::lld_block_vec_t blocks = m_pacific_tree->get_leaf_blocks();

    lld_register_value_list_t reg_val_list;

    for (auto block : blocks) {
        if (!does_hbm_exist && is_hbm_mmu_block(block)) {
            continue;
        }
        lld_register_scptr mbist_cfg_reg = block->get_register(MBIST_CFG_REG_ADDR);
        if (mbist_cfg_reg != nullptr) {
            reg_val_list.push_back({mbist_cfg_reg, block_mbist_val});
        }
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->sms_quad); i++) {
        reg_val_list.push_back({m_pacific_tree->sms_quad[i]->sms_bist_bank_config_reg, sms_mbist_val});
    }

    reg_val_list.push_back({m_pacific_tree->cdb->top->arc_mems_bist_config, block_mbist_val});
    if (does_hbm_exist) {
        reg_val_list.push_back({m_pacific_tree->hbm->hi->sbm_bist_control_reg, sbm_mbist_val});
        reg_val_list.push_back({m_pacific_tree->hbm->lo->sbm_bist_control_reg, sbm_mbist_val});
    }

    // There are two SBus rings - one connected through slice2/ifg0 and the second through slice3/ifg1
    reg_val_list.push_back(
        {m_pacific_tree->slice[SBUS_RING1_SLICE]->ifg[SBUS_RING1_IFG]->serdes_pool->sbm_bist_control_reg, sbm_mbist_val});
    reg_val_list.push_back(
        {m_pacific_tree->slice[SBUS_RING2_SLICE]->ifg[SBUS_RING2_IFG]->serdes_pool->sbm_bist_control_reg, sbm_mbist_val});

    status = lld_write_register_list(m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_activate(bool repair)
{
    if (m_serdes_device_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    la_status status = m_serdes_device_handler->mbist_activate(repair);
    return_on_error(status);

    // Have to set the configuration register twice, it activates the MBIST when "run" bit changes from 0 to 1.
    // The other bits must be correct before changing the "run" bit from 0 to 1.
    bit_vector block_mbist_val(repair, 3);    // bit0 - repair, bit1 - run, bit2 - fill
    bit_vector sbm_mbist_val(repair, 3);      // bit0 - repair, bit1 - fill, bit2 - run
    bit_vector sms_mbist_val(repair << 2, 3); // bit0 - fill, bit1 - run, bit2 - repair

    if (repair) {
        // Write the repair without running
        status = mbist_activate_write(block_mbist_val, sbm_mbist_val, sms_mbist_val);
        return_on_error(status);
    }

    // Adding the "run"
    block_mbist_val.set_bit(1, 1);
    sbm_mbist_val.set_bit(2, 1);
    sms_mbist_val.set_bit(1, 1);

    status = mbist_activate_write(block_mbist_val, sbm_mbist_val, sms_mbist_val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_clear()
{
    if (m_serdes_device_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    la_status status = m_serdes_device_handler->mbist_clear();
    return_on_error(status);

    // Have to set the configuration register twice, it activates the MBIST when "run" bit changes from 0 to 1.
    // The other bits must be correct before changing the "run" bit from 0 to 1.
    bit_vector block_mbist_val(0, 3); // bit0 - repair, bit1 - run, bit2 - pattern fill
    bit_vector sbm_mbist_val(0, 3);   // bit0 - repair, bit1 - pattern fill, bit2 - run
    bit_vector sms_mbist_val(0, 3);   // bit0 - fill, bit1 - run, bit2 - repair

    status = mbist_activate_write(block_mbist_val, sbm_mbist_val, sms_mbist_val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_check_pass_fail_registers(bool report_failures,
                                                lld_register_scptr pass_reg,
                                                lld_register_scptr fail_reg,
                                                size_t& pass,
                                                size_t& fail)
{
    bit_vector pass_val;
    bit_vector fail_val;

    la_status status = m_ll_device->read_register(*pass_reg, pass_val);
    return_on_error(status);
    if (pass_val.get_value()) {
        pass++;
    }

    status = m_ll_device->read_register(*fail_reg, fail_val);
    return_on_error(status);
    if (fail_val.get_value()) {
        if (report_failures) {
            log_err(HLD,
                    "MBIST failed: %d:0x%X(%s) - pass=0x%lx, fail=0x%lx",
                    fail_reg->get_block_id(),
                    fail_reg->get_desc()->addr,
                    fail_reg->get_desc()->name.c_str(),
                    pass_val.get_value(),
                    fail_val.get_value());
        } else {
            log_debug(HLD,
                      "MBIST failed: %d:0x%X(%s) - pass=0x%lx, fail=0x%lx",
                      fail_reg->get_block_id(),
                      fail_reg->get_desc()->addr,
                      fail_reg->get_desc()->name.c_str(),
                      pass_val.get_value(),
                      fail_val.get_value());
        }
        fail++;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_check_status_register(bool report_failures, lld_register_scptr stat_reg, size_t& pass, size_t& fail)
{
    // BIST status register has two fields - bit[0]=pass, bit[1]=fail
    bit_vector stat_val;

    la_status status = m_ll_device->read_register(*stat_reg, stat_val);
    return_on_error(status);
    pass += stat_val.bit(0);
    fail += stat_val.bit(1);

    if (stat_val.bit(1)) {
        if (report_failures) {
            log_err(HLD,
                    "MBIST failed: %d:0x%X(%s) - status=0x%lx",
                    stat_reg->get_block_id(),
                    stat_reg->get_desc()->addr,
                    stat_reg->get_desc()->name.c_str(),
                    stat_val.get_value());
        } else {
            log_debug(HLD,
                      "MBIST failed: %d:0x%X(%s) - status=0x%lx",
                      stat_reg->get_block_id(),
                      stat_reg->get_desc()->addr,
                      stat_reg->get_desc()->name.c_str(),
                      stat_val.get_value());
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_read_result(bool report_failures, size_t& total_tested, size_t& total_failed)
{
    total_tested = 0;
    total_failed = 0;

    size_t pass = 0;

    bool does_hbm_exist;
    la_status status = hbm_exists(does_hbm_exist);
    return_on_error(status);

    if (m_serdes_device_handler == nullptr) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    status = m_serdes_device_handler->mbist_read(report_failures, total_tested, pass, total_failed);
    return_on_error(status);

    pacific_tree::lld_block_vec_t blocks = m_pacific_tree->get_leaf_blocks();

    for (auto block : blocks) {
        if (!does_hbm_exist && is_hbm_mmu_block(block)) {
            continue;
        }
        lld_register_scptr mbist_pass_reg = block->get_register(MBIST_PASS_REG_ADDR);
        lld_register_scptr mbist_fail_reg = block->get_register(MBIST_FAIL_REG_ADDR);
        if ((mbist_pass_reg != nullptr) && (mbist_fail_reg != nullptr)) {
            status = mbist_check_pass_fail_registers(report_failures, mbist_pass_reg, mbist_fail_reg, pass, total_failed);
            return_on_error(status);
            total_tested++;
        }
    }

    for (size_t i = 0; i < array_size(m_pacific_tree->sms_quad); i++) {
        status = mbist_check_pass_fail_registers(report_failures,
                                                 m_pacific_tree->sms_quad[i]->sms_bank_bist_done_pass_reg,
                                                 m_pacific_tree->sms_quad[i]->sms_bank_bist_done_fail_reg,
                                                 pass,
                                                 total_failed);
        return_on_error(status);
        total_tested++;
    }

    status = mbist_check_pass_fail_registers(report_failures,
                                             m_pacific_tree->cdb->top->arc_mems_bist_pass,
                                             m_pacific_tree->cdb->top->arc_mems_bist_fail,
                                             pass,
                                             total_failed);
    return_on_error(status);
    total_tested++;

    if (does_hbm_exist) {
        status = mbist_check_status_register(report_failures, m_pacific_tree->hbm->hi->sbm_bist_status_reg, pass, total_failed);
        return_on_error(status);
        total_tested++;

        status = mbist_check_status_register(report_failures, m_pacific_tree->hbm->lo->sbm_bist_status_reg, pass, total_failed);
        return_on_error(status);
        total_tested++;
    }

    status = mbist_check_status_register(
        report_failures,
        m_pacific_tree->slice[SBUS_RING1_SLICE]->ifg[SBUS_RING1_IFG]->serdes_pool->sbm_bist_status_reg,
        pass,
        total_failed);
    return_on_error(status);
    total_tested++;

    status = mbist_check_status_register(
        report_failures,
        m_pacific_tree->slice[SBUS_RING2_SLICE]->ifg[SBUS_RING2_IFG]->serdes_pool->sbm_bist_status_reg,
        pass,
        total_failed);
    return_on_error(status);
    total_tested++;

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_run_cycle(bool repair, bool report_failures, bool& mbist_result)
{
    log_debug(HLD, "%s: repair=%d, report_failures=%d", __func__, (int)repair, (int)report_failures);

    la_status status = mbist_activate(repair);
    return_on_error(status);

    size_t total_tested = 0;
    size_t total_failed = 0;
    status = mbist_read_result(report_failures, total_tested, total_failed);
    return_on_error(status);

    status = mbist_clear();
    return_on_error(status);

    if (report_failures && (total_failed > 0)) {
        log_err(HLD, "%s: MBIST result: tested %zd, failed %zd", __func__, total_tested, total_failed);
    } else {
        log_debug(HLD, "%s: MBIST result: tested %zd, failed %zd", __func__, total_tested, total_failed);
    }

    mbist_result = (total_failed == 0);

    return LA_STATUS_SUCCESS;
}

la_status
la_device_impl::mbist_run()
{
    bool repair = false;
    bool mbist_result = false;

    bool enable_mbist_repair = false;
    get_bool_property(la_device_property_e::ENABLE_MBIST_REPAIR, enable_mbist_repair);

    log_debug(HLD, "%s: property enable_mbist_repair=%d", __func__, (int)enable_mbist_repair);

    // If we're going to run repair the first run which is without repair shouldn't log errors.
    bool report_failures = !enable_mbist_repair;

    la_status status = mbist_run_cycle(repair, report_failures, mbist_result);
    return_on_error(status);

    if (mbist_result) {
        log_debug(HLD, "%s: PASS", __func__);
        return LA_STATUS_SUCCESS;
    }

    // Failed
    if (!enable_mbist_repair) {
        log_debug(HLD, "%s: mbist_repair is disabled --> MBIST failed", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    // Fix and check again
    repair = true;
    report_failures = true;
    status = mbist_run_cycle(repair, report_failures, mbist_result);
    return_on_error(status);

    if (mbist_result) {
        log_debug(HLD, "%s: PASS after fix", __func__);
        return LA_STATUS_SUCCESS;
    }

    log_debug(HLD, "%s: Failed to fix", __func__);

    return LA_STATUS_EUNKNOWN;
}

la_status
la_device_impl::mbist_hbm_run()
{
    bool mbist_repair = false;
    get_bool_property(la_device_property_e::ENABLE_MBIST_REPAIR, mbist_repair);

    la_status status = m_hbm_handler->run_mbist(mbist_repair);

    return status;
}
}
