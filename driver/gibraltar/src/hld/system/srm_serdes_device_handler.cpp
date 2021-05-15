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

#include "common/defines.h"
#include "hld_types.h"
#include <common/la_status.h>
#include <sys/stat.h>

#include "srm/srm_serdes_address.h"
#include "srm_serdes_device_handler.h"
#include "srm_serdes_handler.h"

#include "system/ifg_handler.h"
#include "system/la_device_impl.h"
#include "system/reconnect_handler.h"
#include "system/slice_id_manager_base.h"

// SRM headers
#include "srm/srm_api.h"
#include "srm/srm_rules.h"

#include <cstdio>

namespace silicon_one
{

enum {
    FW_VERSION_MAJOR = 0,
    FW_VERSION_MINOR = 10,
    FW_VERSION_BUILD = 572,

    SRM_FW_IMAGE_SIZE = 35000,
    SRM_RX_REF_CLOCK_CFG_ADDR = 0x2c16, ///< The address of the reference clock mux register.

    // SRM Register offset & definitions
    SRM_ERU_NO_CONNECTED = 0xBADA,
    SRM_MCU_CFG_RUN = 0x1000,
    SRM_MCU_CFG_STALL = 0x1001,

    SRM_BIAS_TO_ERU_OFFSET = 0x100,
    SRM_REFEGEN_CNTL5_REG = SRM_BIAS_REFEGEN_CNTL5__ADDRESS,
    SRM_REFGEN_STATUS3_REG = SRM_BIAS_REFGEN_STATUS3__ADDRESS,
    SRM_STATUS_RCAL_REG = 0x6171,
    SRM_STATUS_REXT_CODE_LOW_REG = 0x6172,
    SRM_STATUS_REXT_CODE_HIGH_REG = 0x6173,
    SRM_STATUS_REXT_VSS_CODE_LOW_REG = 0x6174,
    SRM_STATUS_REXT_VSS_CODE_HIGH_REG = 0x6175,
    SRM_NUM_DIES = 128,
};
struct rcal_average_struct {
    uint32_t average_val;
    uint32_t cnt;
};

srm_serdes_device_handler::srm_serdes_device_handler(const la_device_impl_wptr& device)
    : m_device(device), m_fw_version_major(FW_VERSION_MAJOR), m_handler_initilized(false)
{
    m_die_health.resize(SRM_NUM_DIES);
    uint32_t die_addr;
    uint32_t die_no = 0;
    for (la_slice_ifg s_ifg : m_device->get_used_ifgs()) {

        size_t max_die = m_device->m_ifg_handlers[s_ifg.slice][s_ifg.ifg]->get_num_total_existing_serdes() / 2;
        for (size_t die = 0; die < max_die; die++) {
            get_serdes_addr(s_ifg.slice, s_ifg.ifg, die * 2, la_serdes_direction_e::TX, die_addr);

            // Default to bad die until we check the firmware is installed properly.
            m_die_health[die_no].addr = die_addr;
            m_die_health[die_no].status = false;
            m_die_health[die_no].type = la_component_type_e::SERDES;
            die_no++;
        }
    }
}

la_status
srm_serdes_device_handler::verify_new_firmware(bool& new_fw)
{
    la_uint_t tx_die;
    la_slice_id_t slice = m_device->get_used_slices().front();
    la_status stat = get_serdes_addr(slice, 0, 0, la_serdes_direction_e::TX, tx_die);
    return_on_error(stat);

    bool fw_ok;
    stat = check_firmware(tx_die, fw_ok);
    return_on_error(stat);

    new_fw = !fw_ok;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::init(bool reconnect)
{
    bool fw_ready;
    bool ignore_failures;
    la_status stat = LA_STATUS_SUCCESS;

    m_device->get_int_property(la_device_property_e::SERDES_FW_REVISION, m_fw_version_minor);
    m_device->get_int_property(la_device_property_e::SERDES_FW_BUILD, m_fw_version_build);
    m_device->get_bool_property(la_device_property_e::IGNORE_COMPONENT_INIT_FAILURES, ignore_failures);

    if (reconnect) {
        m_handler_initilized = true;
        return LA_STATUS_SUCCESS;
    }

    if (m_device->m_init_performance_helper->is_optimization_enabled()) {
        bool new_fw;
        stat = verify_new_firmware(new_fw);
        return_on_error(stat);
        if (!new_fw) {
            m_handler_initilized = true;
            log_debug(HLD, "%s : Skipping SerDes init. Optimization ENABLED.", __func__);
            return LA_STATUS_SUCCESS;
        }
    }

    stat = clobber_resets();
    return_on_error(stat);

    stat = reference_clock_propagation();
    return_on_error(stat);

    stat = powerup_activate();
    return_on_error(stat);

    stat = powerup_check();
    return_on_error(stat);

    stat = rcal_fail_check();
    return_on_error(stat);

    // Do not stop the init sequence when a die fails during firmware sequence.
    // Die failure is noted, and can be fetched via la_device::get_component_health API.
    stat = upload_firmware();
    if (!ignore_failures) {
        return_on_error(stat);
    }

    stat = init_all_firmware();
    if (!ignore_failures) {
        return_on_error(stat);
    }

    stat = check_all_firmware(fw_ready);
    if (!fw_ready) {
        log_err(SERDES, "%s: FW ready -> %d", __func__, fw_ready);
    }
    m_handler_initilized = true;
    return (stat);
}

la_status
srm_serdes_device_handler::check_firmware(uint32_t die, bool& out_fw_ok)
{
    srm_mcu_status_t mcu_status{};

    // Query the firmware mode
    ip_status_t status = srm_mcu_fw_mode_query(die, &mcu_status.fw_mode);
    if (status != IP_OK) {
        return LA_STATUS_EUNKNOWN;
    }

    // Query the application version information
    // The information can be retrieved using the following API but this API also check MCU speed and do sleep of 2 sec!!!
    // ip_status_t status = srm_mcu_status_query(die, &mcu_status);
    // Retrieve only the required information quickly.

    mcu_status.app_version = (SRM_MCU_FIRMWARE_REV1_OVL__READ(die) << 16) | SRM_MCU_FIRMWARE_REV0_OVL__READ(die);
    mcu_status.app_version_build = SRM_MCU_FIRMWARE_REV0_OVL__BUILD__READ(die);
    mcu_status.app_version_major = SRM_MCU_FIRMWARE_REV1_OVL__MAJOR__READ(die);
    mcu_status.app_version_minor = SRM_MCU_FIRMWARE_REV1_OVL__MINOR__READ(die);

    out_fw_ok = ((mcu_status.fw_mode == SRM_FW_MODE_APPLICATION) && (mcu_status.app_version_major == m_fw_version_major)
                 && (mcu_status.app_version_minor == m_fw_version_minor)
                 && (mcu_status.app_version_build == m_fw_version_build));

    if (!out_fw_ok) {
        log_err(SERDES,
                "%s: die 0x%X : mode %d, %d(%d).%d(%d).%d(%d) -> %d",
                __func__,
                die,
                mcu_status.fw_mode,
                mcu_status.app_version_major,
                m_fw_version_major,
                mcu_status.app_version_minor,
                m_fw_version_minor,
                mcu_status.app_version_build,
                m_fw_version_build,
                out_fw_ok);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::upload_firmware_from_file(uint32_t address, uint32_t fw_crcs[2], std::string filename)
{
    std::string filepath = find_resource_file(SERDES_FILE_ENVVAR.c_str(), filename.c_str());
    if (filepath.empty()) {
        log_err(SERDES, "Failed to locate SerDes firmware file (%s)", filename.c_str());
        return LA_STATUS_EUNKNOWN;
    }

    FILE* handle = fopen(filepath.c_str(), "r");
    if (!handle) {
        log_err(SERDES, "Failed to open SerDes firmware file (%s)", filepath.c_str());
        return LA_STATUS_EUNKNOWN;
    }

    rewind(handle);
    char buffer[256];
    uint32_t block_data[SRM_FW_IMAGE_SIZE];
    uint32_t block_index = 0;
    uint32_t addr_index = 0;
    uint32_t block_size = 0;

    // Load file
    while (0 == feof(handle)) {
        if (fgets(buffer, 255, handle) == NULL) {
            break;
        }

        if (!strlen(buffer) || buffer[0] == '#' || buffer[0] == '/') {
            // Skip comments
            continue;
        }

        if (buffer[0] == '@') {
            // Special lines - block definitions
            block_data[block_index + 1] = block_size;
            block_size = 0;
            uint32_t word_to_write = strtoul(&buffer[1], NULL, 16);
            block_index = addr_index;
            block_data[addr_index++] = word_to_write;
            block_data[addr_index++] = 0; // set size place holder
        } else {
            // regular FW data
            uint32_t word_to_write = strtoul(buffer, NULL, 16);
            block_data[addr_index++] = word_to_write;
            block_size++;
        }
    }

    block_data[block_index + 1] = block_size;
    fclose(handle);

    // Download FW to device
    ip_status_t status = srm_mcu_direct_download_image_bcast_buffer(address, block_data, addr_index);
    if (status != IP_OK) {
        log_err(SERDES, "Uploading SerDes image from File failed");
        return LA_STATUS_EUNKNOWN;
    }

    fw_crcs[0] = block_data[2];
    fw_crcs[1] = block_data[3];

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::upload_firmware_from_integrated(uint32_t address, uint32_t fw_crcs[2])
{
    ip_status_t status = srm_mcu_direct_download_image_bcast_inline(address);
    if (status != IP_OK) {
        return LA_STATUS_EUNKNOWN;
    }

    const uint32_t* fw_ptr = 0;
    uint32_t fw_len = 0;

    srm_mcu_get_inline_firmware(&fw_ptr, &fw_len);

    fw_crcs[0] = fw_ptr[2];
    fw_crcs[1] = fw_ptr[3];
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::clobber_resets()
{

    srm_serdes_address addr_device{};

    addr_device.fields.addressing_mode = (uint32_t)srm_serdes_addressing_mode_e::DEVICE;
    addr_device.fields.device_id = m_device->get_id();
    addr_device.fields.slice = 0;
    addr_device.fields.ifg = 0;
    addr_device.fields.serdes_package = 0;
    addr_device.fields.serdes_index = 0;

    // Put MCU, ERU, BIAS, PLL, TX and RX in reset
    unsigned int reset_cfg = 0x0;
    unsigned int val = 1;
    reset_cfg = SRM_MMD30_RESET_CFG__MCU_SR__SET(reset_cfg, val);
    reset_cfg = SRM_MMD30_RESET_CFG__ERU_SR__SET(reset_cfg, val);
    reset_cfg = SRM_MMD30_RESET_CFG__BIAS_SR__SET(reset_cfg, val);
    reset_cfg = SRM_MMD30_RESET_CFG__PLL_SR__SET(reset_cfg, val);
    reset_cfg = SRM_MMD30_RESET_CFG__TX_SR__SET(reset_cfg, val);
    reset_cfg = SRM_MMD30_RESET_CFG__RX_SR__SET(reset_cfg, val);
    SRM_MMD30_RESET_CFG__WRITE(addr_device.u32, reset_cfg);
    log_debug(SERDES, "reset_cfg_write die 0x%X -> 0x%x.", addr_device.u32, reset_cfg);
    usleep(10);

    // Unreset MCU
    val = 0;
    reset_cfg = SRM_MMD30_RESET_CFG__MCU_SR__SET(reset_cfg, val);
    SRM_MMD30_RESET_CFG__WRITE(addr_device.u32, reset_cfg);

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::upload_firmware()
{
    srm_serdes_address addr_device{};

    addr_device.fields.addressing_mode = (uint32_t)srm_serdes_addressing_mode_e::DEVICE;
    addr_device.fields.device_id = m_device->get_id();
    addr_device.fields.slice = 0;
    addr_device.fields.ifg = 0;
    addr_device.fields.serdes_package = 0;
    addr_device.fields.serdes_index = 0;

    srm_serdes_address addr_serdes = addr_device;
    addr_serdes.fields.addressing_mode = (uint32_t)srm_serdes_addressing_mode_e::SERDES;

    // take part out of global reset
    SRM_MMD30_RESET_CFG__WRITE(addr_device.u32, 0x0);

    uint32_t fw_crcs[2] = {};

    m_fw_version_major = FW_VERSION_MAJOR;
    m_device->get_int_property(la_device_property_e::SERDES_FW_REVISION, m_fw_version_minor);
    m_device->get_int_property(la_device_property_e::SERDES_FW_BUILD, m_fw_version_build);

    std::string filename;
    m_device->get_string_property(la_device_property_e::SERDES_FW_FILE_NAME, filename);
    if (!filename.empty()) {
        la_status stat = upload_firmware_from_file(addr_device.u32, fw_crcs, filename);
        return_on_error(stat);
    } else {
        la_status stat = upload_firmware_from_integrated(addr_device.u32, fw_crcs);
        return_on_error(stat);
    }

    // The following flow is taken from srm_mcu_download_firmware.
    // Since we want to broadcast all writes, we do RMW by reading from one and writing to all.
    // On write, addressing_mode == srm_serdes_addressing_mode_e::DEVICE.
    // On read, addressing_mode == srm_serdes_addressing_mode_e::SERDES.
    // We assume all dies are in same state since this is done on device initialization.

    // Switch to the application bank
    // SRM_MCU_GEN_CFG__STATVECTOR_SEL__RMW(die, 0x1);
    uint32_t mcu_gen_cfg = SRM_MCU_GEN_CFG__READ(addr_serdes.u32);
    SRM_MCU_GEN_CFG__WRITE(addr_device.u32, SRM_MCU_GEN_CFG__STATVECTOR_SEL__SET(mcu_gen_cfg, 0x1));

    // Reset the MCU
    // SRM_MCU_RESET__PROCRST__RMW(die, 0x1);
    uint32_t mcu_reset = SRM_MCU_RESET__READ(addr_serdes.u32);
    SRM_MCU_RESET__WRITE(addr_device.u32, SRM_MCU_RESET__PROCRST__SET(mcu_reset, 0x1));

    la_status stat = verify_firmware_upload(addr_device.u32, fw_crcs);
    return_on_error(stat);

    // Now bring it out of runstall
    // SRM_MCU_GEN_CFG__RUNSTALL__RMW(die, 0x0);
    mcu_gen_cfg = SRM_MCU_GEN_CFG__READ(addr_serdes.u32);
    SRM_MCU_GEN_CFG__WRITE(addr_device.u32, SRM_MCU_GEN_CFG__RUNSTALL__SET(mcu_gen_cfg, 0));

    // Finally wait for it to jump into application mode
    // status = srm_mcu_block_application_mode(die, 2000);
    // TODO: currently, wait for one die per slice, need to change for all
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        addr_serdes.fields.slice = slice;
        ip_status_t status = srm_mcu_block_application_mode(addr_serdes.u32, 2000);
        log_debug(SERDES, "Die 0x%X -> %d.", addr_serdes.u32, status);
        if (status != IP_OK) {
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::verify_firmware_upload(uint32_t broadcast_die, const uint32_t crcs[2])
{
    uint32_t ram_addr[2] = {SRM_MCU_IRAM_BASE_ADDR, SRM_MCU_DRAM_BASE_ADDR};
    uint32_t ram_size[2] = {SRM_MCU_IRAM_SIZE, SRM_MCU_DRAM_SIZE};

    for (int ram = 0; ram < 2; ram++) {
        // Turn on the checksum calculator on all IPs
        SRM_MCU_CHKSUM_CFG__WRITE(broadcast_die, 0x0001);

        // define the IRAM/DRAM start address
        SRM_MCU_CHKSUM_ADDR_CFG1__WRITE(broadcast_die, (uint16_t)(ram_addr[ram] >> 16));
        SRM_MCU_CHKSUM_ADDR_CFG0__WRITE(broadcast_die, (uint16_t)ram_addr[ram]);

        // number of IRAM/DRAM locations
        SRM_MCU_CHKSUM_CNT_CFG__WRITE(broadcast_die, ram_size[ram]);

        // start the CRC_32 engine
        SRM_MCU_CHKSUM_CFG__WRITE(broadcast_die, 0x8001);

        int guard = 300;
        // Now manually verify the checksum on each die
        for (la_slice_ifg id : m_device->get_used_ifgs()) {
            size_t max_die = m_device->m_ifg_handlers[id.slice][id.ifg]->get_serdes_count() / 2;
            for (size_t die = 0; die < max_die; die++) {
                uint32_t die_addr;
                get_serdes_addr(id.slice, id.ifg, die * 2, la_serdes_direction_e::TX, die_addr);

                while (SRM_MCU_CHKSUM_STATUS__READ(die_addr) == 0 && (guard-- > 0)) {
                    usleep(100);
                }

                if (guard <= 0) {
                    log_err(SERDES, "Serdes %d/%d/%zd Timed out verifying the CRC on the IRAM/DRAM", id.slice, id.ifg, die * 2);
                    return LA_STATUS_EUNKNOWN;
                }

                // get the results
                uint32_t calc_crc = SRM_MCU_CHKSUM_RESULT_STATUS0__READ(die_addr);
                calc_crc |= (SRM_MCU_CHKSUM_RESULT_STATUS1__READ(die_addr) << 16);

                if (calc_crc != crcs[ram]) {
                    log_err(SERDES,
                            "SerDes %d/%d/%zd init die 0x%X has bad CRC in RAM=%d -> calculated=%x expected=%x.",
                            id.slice,
                            id.ifg,
                            die * 2,
                            die_addr,
                            ram,
                            calc_crc,
                            crcs[ram]);
                    return LA_STATUS_EUNKNOWN;
                }
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::init_all_firmware()
{
    uint32_t die_addr;
    la_status result = LA_STATUS_SUCCESS;

    for (la_slice_ifg id : m_device->get_used_ifgs()) {
        size_t max_die = m_device->m_ifg_handlers[id.slice][id.ifg]->get_serdes_count() / 2;
        for (size_t die = 0; die < max_die; die++) {
            get_serdes_addr(id.slice, id.ifg, die * 2, la_serdes_direction_e::TX, die_addr);
            ip_status_t status = srm_init(die_addr);
            log_debug(SERDES, "SerDes %d/%d/%zd init die 0x%X -> %d.", id.slice, id.ifg, die * 2, die_addr, status);
            if (status != IP_OK) {
                result = LA_STATUS_EUNKNOWN;
            }
        }
    }

    return result;
}

la_status
srm_serdes_device_handler::get_component_health(la_component_health_vec_t& out_component_health) const
{
    la_status stat = LA_STATUS_SUCCESS;

    out_component_health = m_die_health;

    return stat;
}

la_status
srm_serdes_device_handler::check_all_firmware(bool& out_ready)
{
    out_ready = true;
    uint32_t die_addr;
    uint32_t die_no = 0;

    for (la_slice_ifg id : m_device->get_used_ifgs()) {
        size_t max_die = m_device->m_ifg_handlers[id.slice][id.ifg]->get_serdes_count() / 2;
        for (size_t die = 0; die < max_die; die++) {
            get_serdes_addr(id.slice, id.ifg, die * 2, la_serdes_direction_e::TX, die_addr);

            int loop_count = 20;
            bool fw_ok = srm_is_fw_running_ok(die_addr);
            while (!fw_ok && loop_count) {
                usleep(300);
                fw_ok = srm_is_fw_running_ok(die_addr);
                loop_count--;
            }

            if (loop_count == 0) {
                log_err(SERDES,
                        "SerDes %d/%d/%zd init die 0x%X -> is_fw_running_ok %d. NOT READY!!!.",
                        id.slice,
                        id.ifg,
                        die * 2,
                        die_addr,
                        fw_ok);
                out_ready = false;
            }

            bool die_is_ok = out_ready && fw_ok;
            if (die_no < SRM_NUM_DIES) {
                m_die_health[die_no].status = die_is_ok;
            } else {
                log_err(SERDES, "Invalid die number %d\n", die_no);
            }
            die_no++;
        }
    }

    return LA_STATUS_SUCCESS;
}

uint32_t
srm_serdes_device_handler::get_die_no(uint32_t die_addr)
{
    srm_serdes_address die_addr_obj{};
    die_addr_obj.u32 = die_addr;
    la_uint_t slice = die_addr_obj.fields.slice;
    la_uint_t ifg = die_addr_obj.fields.ifg;
    la_uint_t serdes_package = die_addr_obj.fields.serdes_package;
    uint32_t die_no = 0;

    // slice_ifg is 0-11
    uint32_t slice_ifg = slice * 2 + ifg;
    if (slice_ifg < 3) {
        // first 3 IFG are all 12 dies
        die_no = (slice_ifg * 12) + serdes_package;
    } else if (slice_ifg == 3 or slice_ifg == 4) {
        // offset from 36, 8 dies, slice is 1 or 2
        die_no = 36 + ((slice_ifg - 3) * 8) + serdes_package;
    } else if (slice_ifg > 4 && slice_ifg < 7) {
        // same calculation as first except offset
        die_no = 52 + ((slice_ifg - 5) * 12) + serdes_package;
    } else if (slice_ifg == 7 or slice_ifg == 8) {
        // offset from 37
        die_no = 76 + ((slice_ifg - 7) * 8) + serdes_package;
    } else {
        // same calculation as first except offset
        die_no = 92 + ((slice_ifg - 9) * 12) + serdes_package;
    }

    return die_no;
}

struct eru_die_t {
    la_ifg_id_t ifg;
    la_uint_t serdes_idx;
};

const static eru_die_t eru_dies[ASIC_MAX_SLICES_PER_DEVICE_NUM] = {{0, 0}, {1, 0}, {0, 0}, {1, 0}, {0, 0}, {1, 0}};

la_status
srm_serdes_device_handler::populate_pwrup_rules(size_t chain_idx, srm_pwrup_rules_t& pwrup_rules)
{
    srm_pwrup_rules_set_default(&pwrup_rules);
    pwrup_rules.cal_mode = SRM_PWRUP_USE_MODE_RULE;

    bool en_serdes_ldo;
    m_device->get_bool_property(la_device_property_e::ENABLE_SERDES_LDO_VOLTAGE_REGULATOR, en_serdes_ldo);
    if (en_serdes_ldo)
        pwrup_rules.mode = SRM_PWRUP_BYPASS_NONE;
    else
        pwrup_rules.mode = SRM_PWRUP_BYPASS_TXRX;

    pwrup_rules.max_ldo_count = 10;
    pwrup_rules.num_srm_in_chain = 0;

    pwrup_rules.show_debug_info = false;
    pwrup_rules.enable_rcal = true;

    get_serdes_addr(
        chain_idx, eru_dies[chain_idx].ifg, eru_dies[chain_idx].serdes_idx, la_serdes_direction_e::TX, pwrup_rules.eru_die);

    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        size_t max_die = m_device->m_ifg_handlers[chain_idx][ifg]->get_num_total_existing_serdes() / 2;
        for (size_t die = 0; die < max_die; die++) {
            get_serdes_addr(chain_idx, ifg, die * 2, la_serdes_direction_e::TX, pwrup_rules.srm_dies[pwrup_rules.num_srm_in_chain]);
            pwrup_rules.num_srm_in_chain++;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::powerup_activate()
{
    srm_pwrup_rules_t pwrup_rules;
    for (la_slice_id_t i : m_device->get_used_slices()) {
        la_status stat = populate_pwrup_rules(i, pwrup_rules);
        return_on_error(stat);

        if (pwrup_rules.num_srm_in_chain > 0) {
            ip_status_t i_status = srm_pwrup_start(&pwrup_rules);
            if (i_status != IP_OK) {
                log_err(SERDES, "%s: srm_pwrup_start [%d] => %d", __func__, i, i_status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::powerup_check_eru()
{
    la_status stat = LA_STATUS_SUCCESS;
    for (la_slice_id_t i : m_device->get_used_slices()) {
        uint32_t die_id;
        get_serdes_addr(i, eru_dies[i].ifg, eru_dies[i].serdes_idx, la_serdes_direction_e::TX, die_id);
        uint32_t retry = 100;
        do {
            uint32_t pu_done = SRM_ERU_REFGEN_STATUS3__STRT_PU_DONE__READ(die_id);
            if (pu_done)
                break;
            usleep(1000);
        } while (--retry);
        if (!retry) {
            log_err(SERDES,
                    "%d/%d/%d : Timeout checking ERU REFGEN_STATUS3 PU_DONE not set.",
                    (int)i,
                    eru_dies[i].ifg,
                    eru_dies[i].serdes_idx);
            stat = LA_STATUS_EUNKNOWN;
        }
    }
    return stat;
}

la_status
srm_serdes_device_handler::powerup_check_bias()
{
    la_status stat = LA_STATUS_SUCCESS;
    uint32_t die_id;

    for (la_slice_ifg id : m_device->get_used_ifgs()) {
        size_t max_die = m_device->m_ifg_handlers[id.slice][id.ifg]->get_num_total_existing_serdes() / 2;
        for (size_t die = 0; die < max_die; die++) {
            get_serdes_addr(id.slice, id.ifg, die * 2, la_serdes_direction_e::TX, die_id);
            uint32_t retry = 100;
            do {
                uint32_t pu_done = SRM_BIAS_REFGEN_STATUS3__STRT_PU_DONE__READ(die_id);
                if (pu_done)
                    break;
                usleep(1000);
            } while (--retry);
            if (!retry) {
                log_err(SERDES,
                        "%d/%d/%d : Timeout checking BIAS REFGEN_STATUS3 PU_DONE not set.",
                        (int)id.slice,
                        (int)id.ifg,
                        (int)(die * 2));
                stat = LA_STATUS_EUNKNOWN;
            }
        }
    }
    return stat;
}

la_status
srm_serdes_device_handler::powerup_check()
{
    /*
     * Current SRM call srm_pwrup_is_ready needs a fix to check the right PU_DONE state.
     * Check ERU & BIAS PU_DONE status in SDK
     */
    la_status stat = powerup_check_bias();
    return_on_error(stat);

    stat = powerup_check_eru();

    return stat;
}

la_status
srm_serdes_device_handler::set_reference_clock(la_slice_id_t slice, la_ifg_id_t ifg, uint32_t die, uint32_t direction)
{
    uint32_t die_addr = 0;

    if (m_device->get_slice_id_manager()->is_slice_ifg_valid(slice, ifg) != LA_STATUS_SUCCESS) {
        return LA_STATUS_SUCCESS;
    }

    // Propagate the analog reference clocks
    get_serdes_addr(slice, ifg, die * 2, la_serdes_direction_e::TX, die_addr);

    // Bring the RX registers out of reset
    SRM_MMD30_RESET_CFG__RX_SR__RMW(die_addr, 0);

    // Propagate the clock
    srm_reg_write(die_addr, SRM_RX_REF_CLOCK_CFG_ADDR, direction);

    return LA_STATUS_SUCCESS;
}

// SerDes direction of reference clock propagation.
// Horizontal - 1
// Vertical - 4
// Horizontal and Vertical - 5
// There is also reverse option which is not used in our design.
// Each vector is used on two IFGs
const uint32_t serdes_pool16_direction[2][8] = {
    {1, 1, 5, 1, 1, 1, 5, 1}, // Slice/IFG 1/1, 4/0
    {5, 1, 5, 1, 1, 5, 1, 1}, // Slice/IFG 2/0, 3/1
};

const uint32_t serdes_pool24_direction[4][12] = {
    {1, 1, 1, 1, 1, 1, 5, 1, 1, 1, 1, 1}, // Slice/IFG 0/0, 5/1
    {1, 1, 1, 1, 5, 1, 1, 1, 1, 1, 1, 1}, // Slice/IFG 0/1, 5/0
    {1, 1, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1}, // Slice/IFG 1/0, 4/1
    {5, 1, 1, 5, 1, 1, 5, 1, 1, 1, 1, 1}, // Slice/IFG 2/1, 3/0
};

la_status
srm_serdes_device_handler::reference_clock_propagation()
{
    la_status status;

    // There are total of 6 chains of reference clock propagation - one per slice.
    // It's two sets of three unique chains.
    // TODO: further clean and validate.
    for (uint32_t die = 0; die < 8; die++) {
        status = set_reference_clock(1, 1, die, serdes_pool16_direction[0][die]);
        status = set_reference_clock(4, 0, die, serdes_pool16_direction[0][die]);

        status = set_reference_clock(2, 0, die, serdes_pool16_direction[1][die]);
        status = set_reference_clock(3, 1, die, serdes_pool16_direction[1][die]);
    }

    for (uint32_t die = 0; die < 12; die++) {
        status = set_reference_clock(0, 0, die, serdes_pool24_direction[0][die]);
        status = set_reference_clock(5, 1, die, serdes_pool24_direction[0][die]);

        status = set_reference_clock(0, 1, die, serdes_pool24_direction[1][die]);
        status = set_reference_clock(5, 0, die, serdes_pool24_direction[1][die]);

        status = set_reference_clock(1, 0, die, serdes_pool24_direction[2][die]);
        status = set_reference_clock(4, 1, die, serdes_pool24_direction[2][die]);

        status = set_reference_clock(2, 1, die, serdes_pool24_direction[3][die]);
        status = set_reference_clock(3, 0, die, serdes_pool24_direction[3][die]);
    }

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::create_serdes_group_handler(la_slice_id_t slice_id,
                                                       la_ifg_id_t ifg_id,
                                                       la_uint_t serdes_base_id,
                                                       size_t serdes_count,
                                                       la_mac_port::port_speed_e speed,
                                                       la_mac_port::port_speed_e serdes_speed,
                                                       la_slice_mode_e serdes_slice_mode,
                                                       serdes_handler*& out_serdes_handler)
{
    out_serdes_handler = new srm_serdes_handler(
        m_device, shared_from_this(), slice_id, ifg_id, serdes_base_id, serdes_count, speed, serdes_speed, serdes_slice_mode);
    bool reconnect_in_progress = m_device->m_reconnect_handler->is_reconnect_in_progress();
    if (m_handler_initilized) {
        if (reconnect_in_progress) {
            (static_cast<srm_serdes_handler*>(out_serdes_handler))->set_serdes_initialized(true);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(stat);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_device_handler::get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(stat);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
srm_serdes_device_handler::mbist_activate(bool repair)
{
    // TODO: GB implement
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::mbist_clear()
{
    // TODO: GB implement
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::mbist_read(bool report_failures, size_t& total_tested, size_t& total_pass, size_t& total_failed)
{
    // TODO: GB implement
    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::get_serdes_addr(la_slice_id_t slice,
                                           la_ifg_id_t ifg,
                                           la_uint_t serdes_idx,
                                           la_serdes_direction_e direction,
                                           uint32_t& out_serdes_addr)
{
    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(slice, ifg);
    if (stat != LA_STATUS_SUCCESS) {
        log_err(SERDES, "%s: slice=%d, ifg_id=%d is out of range. status=%d", __func__, slice, ifg, stat.value());
        return stat;
    }

    size_t dev_id = m_device->get_id();

    la_uint_t serdes_lane;
    if (direction == la_serdes_direction_e::RX) {
        serdes_lane = m_device->m_serdes_info[slice][ifg][serdes_idx].rx_source;
    } else {
        serdes_lane = serdes_idx;
    }

    srm_serdes_address addr{};
    addr.fields.addressing_mode = (uint32_t)srm_serdes_addressing_mode_e::SERDES;
    addr.fields.device_id = dev_id;
    addr.fields.slice = slice;
    addr.fields.ifg = ifg;
    addr.fields.serdes_package = serdes_lane / 2;
    addr.fields.serdes_index = 0;

    out_serdes_addr = addr.u32;

    return LA_STATUS_SUCCESS;
}

la_status
srm_serdes_device_handler::rcal_fail_check()
{
    la_status rtn_status = LA_STATUS_SUCCESS;
    std::vector<uint32_t> rcal_avg;

    for (la_slice_id_t slice_ord : m_device->get_used_slices()) {
        // Check Rcal result per Chain
        uint32_t rcal_average = 0;
        uint32_t rcal_pass_cnt = 0;
        la_status stat = srm_serdes_rcal_average_calc(slice_ord, 0, rcal_average, rcal_pass_cnt);
        rcal_avg.push_back(rcal_average);

        if (stat != LA_STATUS_SUCCESS) {
            // Some Dies fail Rcal
            log_info(SERDES, "Check rcal on Chain %d, average %d, pass_cnt %d", (int)slice_ord, rcal_average, rcal_pass_cnt);
            la_status status = rcal_override(slice_ord, rcal_average, rcal_pass_cnt);
            if (status != LA_STATUS_SUCCESS)
                // Override failed
                rtn_status = status;
        } else {
            log_info(SERDES, "Nothing to override on Chain %d.", (int)slice_ord);
        }
    }

    auto max_rcal_avg = std::max_element(rcal_avg.begin(), rcal_avg.end());
    auto min_rcal_avg = std::min_element(rcal_avg.begin(), rcal_avg.end());

    log_info(SERDES, "Rcal average per chain Max %d, Min %d", *max_rcal_avg, *min_rcal_avg);
    if ((*max_rcal_avg - *min_rcal_avg) > RCAL_AVERAGE_RANGE) {
        log_info(SERDES, "Difference of Rcal average value per chain is too big. Max : %d. Min : %d", *max_rcal_avg, *min_rcal_avg);
    }

    return rtn_status;
}

la_status
srm_serdes_device_handler::srm_serdes_rcal_average_calc(la_slice_id_t slice,
                                                        int is_eru,
                                                        uint32_t& rcal_average,
                                                        uint32_t& rcal_pass_cnt)
{
    size_t serdes_cnt = 0;
    la_uint_t die;
    uint32_t rcal_total_cnt = 0;
    uint32_t rcal_pass_total = 0;
    uint32_t rcal_total = 0;
    uint32_t rcal_min = 0x7F;
    uint32_t rcal_max = 0;
    uint32_t rcal_val = 0;

    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        serdes_cnt = is_eru ? 1 : m_device->m_ifg_handlers[slice][ifg]->get_num_total_existing_serdes();

        for (la_uint_t serdes_idx = 0; serdes_idx < serdes_cnt; serdes_idx += 2) {
            la_status stat = get_serdes_addr(slice, ifg, serdes_idx, la_serdes_direction_e::TX, die);
            return_on_error(stat);

            uint32_t data_r = srm_reg_read(die, SRM_STATUS_RCAL_REG + is_eru * SRM_BIAS_TO_ERU_OFFSET);
            rcal_val = data_r & 0x7F;
            if ((data_r & 0x80) == 0x80) {
                rcal_pass_cnt += 1;
                rcal_pass_total += rcal_val;
                rcal_min = rcal_val < rcal_min ? rcal_val : rcal_min;
                rcal_max = rcal_val > rcal_max ? rcal_val : rcal_max;
            }
            // Add up Rcal value of all Dies
            rcal_total += rcal_val;
        }
        rcal_total_cnt += serdes_cnt >> 1;
    }

    if (rcal_pass_cnt) {
        rcal_average = rcal_pass_total / rcal_pass_cnt;
        log_info(SERDES,
                 "Chain %d Rcal success %d, average value %d (range %d ~ %d)\n",
                 slice,
                 rcal_pass_cnt,
                 rcal_average,
                 rcal_min,
                 rcal_max);
    } else {
        rcal_average = rcal_total / rcal_total_cnt;
        log_info(SERDES, "Chain %d Rcal all failed. Average value %d.\n", slice, rcal_average);
    }

    return (rcal_total_cnt == rcal_pass_cnt ? LA_STATUS_SUCCESS : LA_STATUS_EINVAL);
}

la_status
srm_serdes_device_handler::rcal_override(la_slice_id_t slice, uint32_t rcal_average, uint32_t rcal_pass_cnt)
{
    uint32_t override_rcal = 0;
    la_uint_t die;
    la_status rtn_code = LA_STATUS_SUCCESS;

    uint32_t rcal_die_num = 0;
    for (size_t i = 0; i < NUM_IFGS_PER_SLICE; i++) {
        rcal_die_num += m_device->m_ifg_handlers[slice][i]->get_num_total_existing_serdes();
    }
    rcal_die_num = rcal_die_num / 2;

    if (rcal_pass_cnt >= (rcal_die_num - RCAL_FAIL_NUM_ALLOW_PER_CHAIN)) {
        // Less than 5 Dies fail Rcal on the Chain
        // Override value calculate based on passing Dies.
        if (rcal_average <= RCAL_AVERAGE_VALUE_THRES) {
            override_rcal = rcal_average;
            log_debug(SERDES, "Chain %d: override Rcal value %d", slice, override_rcal);
        } else {
            log_info(SERDES, "Chain %d : success Rcal average value %d > 5\n", slice, rcal_average);
            return LA_STATUS_EINVAL;
        }
    } else {
        log_info(SERDES, "Chain %d : failed Rcal Die number %d > 5\n", slice, (rcal_die_num - rcal_pass_cnt));
        return LA_STATUS_EINVAL;
    }

    // Override Rcal
    // Same value per Chain
    uint32_t rcal_data = 0;
    rcal_data = SRM_BIAS_SET_RCAL__OVWR_R__SET(rcal_data, 1);
    rcal_data = SRM_BIAS_SET_RCAL__RSET__SET(rcal_data, override_rcal);

    // Override BIAS Rcal
    for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
        size_t serdes_cnt = m_device->m_ifg_handlers[slice][ifg]->get_num_total_existing_serdes();

        for (la_uint_t serdes_idx = 0; serdes_idx < serdes_cnt; serdes_idx += 2) {
            get_serdes_addr(slice, ifg, serdes_idx, la_serdes_direction_e::TX, die);

            // Check Rcal tune status, override failed Dies.
            uint32_t data_r = srm_reg_read(die, SRM_STATUS_RCAL_REG);
            if ((data_r & 0x80) != 0x80) {
                if (data_r == RCAL_OVERRIDE_LO || data_r == RCAL_OVERRIDE_HI) {
                    log_info(SERDES, "Override %d/%d/%d <- %d", slice, ifg, serdes_idx, rcal_data);
                    // Override Rcal data
                    srm_reg_write(die, SRM_BIAS_SET_RCAL__ADDRESS, rcal_data);
                } else {
                    log_info(SERDES, "Die %d/%d/%d : Rcal result 0x%x. Skip override.", slice, ifg, serdes_idx, data_r);
                    rtn_code = LA_STATUS_EINVAL;
                }
            }
        }
    }
    // Override ERU Rcal
    get_serdes_addr(slice, eru_dies[slice].ifg, eru_dies[slice].serdes_idx, la_serdes_direction_e::TX, die);

    uint32_t data_r = srm_reg_read(die, SRM_STATUS_RCAL_REG + SRM_BIAS_TO_ERU_OFFSET);
    if ((data_r & 0x80) != 0x80) {
        if (data_r == RCAL_OVERRIDE_LO || data_r == RCAL_OVERRIDE_HI) {
            log_info(SERDES, "Override ERU %d/%d/%d <- %d", slice, eru_dies[slice].ifg, eru_dies[slice].serdes_idx, rcal_data);
            // Override Rcal data
            srm_reg_write(die, SRM_BIAS_SET_RCAL__ADDRESS + SRM_BIAS_TO_ERU_OFFSET, rcal_data);
        } else {
            log_info(SERDES,
                     "ERU Die %d/%d/%d : Rcal result 0x%x. Skip override.",
                     slice,
                     eru_dies[slice].ifg,
                     eru_dies[slice].serdes_idx,
                     data_r);
            rtn_code = LA_STATUS_EINVAL;
        }
    }

    return rtn_code;
}
}
