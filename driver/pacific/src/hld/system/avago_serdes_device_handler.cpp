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

#include "avago_serdes_device_handler.h"
#include "avago_serdes_handler.h"
#include "system/la_device_impl.h"
#include "system/reconnect_handler.h"
#include "system/slice_id_manager_base.h"

#include "aapl/aapl.h"
#include "aapl_impl.h"

namespace silicon_one
{

static const char SBUS_MASTER_FILE_ENVVAR[] = "SBUS_MASTER_FIRMWARE";

enum {
    SERDES_REV = 0x1097,
    SERDES_BUILD = 0x208d,
    AAPL_PACIFIC_IDCODE = 0x4510100f, ///< ID Code for Pacific device configured in AAPL

    AVAGO_HAL_INT = 0x2C,
    AVAGO_ALL_SERDES = 0xEE,
    // There are two SBus rings - one connected through slice2/ifg0 and the second through slice3/ifg1
    SBUS_RING1_SLICE = 2,
    SBUS_RING1_IFG = 0,
    SBUS_RING2_SLICE = 3,
    SBUS_RING2_IFG = 1,

    AVAGO_MBIST_REG = 9,
    AVAGO_MBIST_RUN_WO_REPAIR = 1,
    AVAGO_MBIST_RUN_W_REPAIR = 3,

};

avago_serdes_device_handler::avago_serdes_device_handler(const la_device_impl_wptr& device)
    : m_device(device), m_handler_initilized(false)
{
    m_ifg_aapl_handlers.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    m_ifg_aapl_native_handlers.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    for (la_slice_id_t sid : m_device->get_used_slices()) {
        m_ifg_aapl_handlers[sid].resize(NUM_IFGS_PER_SLICE, nullptr);
        m_ifg_aapl_native_handlers[sid].resize(NUM_IFGS_PER_SLICE, nullptr);
    }
}

la_status
avago_serdes_device_handler::init(bool reconnect)
{
    log_debug(AAPL, "%s: reconnect=%d", __PRETTY_FUNCTION__, reconnect);

    // Initialize some vars
    m_device->get_int_property(la_device_property_e::SERDES_FW_REVISION, m_ifg_serdes_fw_info.revision);
    m_device->get_int_property(la_device_property_e::SERDES_FW_BUILD, m_ifg_serdes_fw_info.build_id);
    m_device->get_string_property(la_device_property_e::SERDES_FW_FILE_NAME, m_ifg_serdes_fw_info.filename);
    m_ifg_serdes_fw_info.filepath = find_resource_file(SERDES_FILE_ENVVAR.c_str(), m_ifg_serdes_fw_info.filename.c_str());
    m_device->get_int_property(la_device_property_e::SBUS_MASTER_FW_REVISION, m_ifg_sbus_master_fw_info.revision);
    m_device->get_int_property(la_device_property_e::SBUS_MASTER_FW_BUILD, m_ifg_sbus_master_fw_info.build_id);
    m_device->get_string_property(la_device_property_e::SBUS_MASTER_FW_FILE_NAME, m_ifg_sbus_master_fw_info.filename);
    m_ifg_sbus_master_fw_info.filepath = find_resource_file(SBUS_MASTER_FILE_ENVVAR, m_ifg_sbus_master_fw_info.filename.c_str());

    if (reconnect) {
        m_handler_initilized = true;

        return LA_STATUS_SUCCESS;
    }

    Aapl_t* aapl_ring1 = nullptr;
    Aapl_t* aapl_ring2 = nullptr;

    la_status status = get_native_sbus_aapl_handler(SBUS_RING1_SLICE, SBUS_RING1_IFG, aapl_ring1);
    return_on_error(status);

    status = get_native_sbus_aapl_handler(SBUS_RING2_SLICE, SBUS_RING2_IFG, aapl_ring2);
    return_on_error(status);

    avago_sbus_reset(aapl_ring1, AVAGO_ALL_SERDES, 0);
    avago_sbus_reset(aapl_ring2, AVAGO_ALL_SERDES, 0);

    std::shared_ptr<void> get_client_data_ptr_1
        = silicon_one::aapl_bind_get_wrapper(aapl_ring1, silicon_one::client_data_label::CLIENT_DATA_DEFAULT_PTR);
    std::shared_ptr<void> get_client_data_ptr_2
        = silicon_one::aapl_bind_get_wrapper(aapl_ring2, silicon_one::client_data_label::CLIENT_DATA_DEFAULT_PTR);

    std::list<uint32_t> serdes_list_ring1
        = std::static_pointer_cast<la_aapl_user_ifg_native>(get_client_data_ptr_1)->get_all_serdes_address_list();
    std::list<uint32_t> serdes_list_ring2
        = std::static_pointer_cast<la_aapl_user_ifg_native>(get_client_data_ptr_2)->get_all_serdes_address_list();

    for (auto addr : serdes_list_ring1) {
        int ret = avago_spico_reset(aapl_ring1, addr);
        if (ret < 0) {
            log_err(HLD, "Failed avago_spico_reset ring1 serdes_addr %d -> %d", addr, ret);
            return LA_STATUS_EUNKNOWN;
        }
    }

    for (auto addr : serdes_list_ring2) {
        int ret = avago_spico_reset(aapl_ring2, addr);
        if (ret < 0) {
            log_err(HLD, "Failed avago_spico_reset ring2 serdes_addr %d -> %d", addr, ret);
            return LA_STATUS_EUNKNOWN;
        }
    }

    status = ring_firmware_upload(aapl_ring1);
    return_on_error(status, HLD, ERROR, "Failed ring_firmware_upload to ring1");

    status = ring_firmware_upload(aapl_ring2);
    return_on_error(status, HLD, ERROR, "Failed ring_firmware_upload to ring2");

    m_handler_initilized = true;

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::stop_sbm_temperature_distribution()
{
    // called from device dtor. need to be carefull
    auto device_sptr = m_device.lock();
    bool is_device_disconnected = (device_sptr != nullptr) && (device_sptr->m_disconnected);

    if (!m_handler_initilized || !is_device_disconnected) {
        // Not a physical device or 'la_device' is disconnected from the physical device.
        return LA_STATUS_SUCCESS;
    }

    Aapl_t* aapl_ring1 = nullptr;
    Aapl_t* aapl_ring2 = nullptr;

    la_status stat = get_native_sbus_aapl_handler(SBUS_RING1_SLICE, SBUS_RING1_IFG, aapl_ring1);
    return_on_error(stat);
    stat = get_native_sbus_aapl_handler(SBUS_RING2_SLICE, SBUS_RING2_IFG, aapl_ring2);
    return_on_error(stat);

    // Disables SBUS master process to broadcast the current temperature to all SerDes's on same Ring
    avago_spico_int(aapl_ring1, AVAGO_SBUS_MASTER_ADDRESS, AVAGO_HAL_INT, 0);
    avago_spico_int(aapl_ring2, AVAGO_SBUS_MASTER_ADDRESS, AVAGO_HAL_INT, 0);
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::destroy()
{
    stop_sbm_temperature_distribution();
    for (la_slice_id_t sid = 0; sid < m_ifg_aapl_handlers.size(); sid++) {
        std::vector<Aapl_t*>& vect = m_ifg_aapl_handlers[sid];
        for (la_slice_id_t ifg_id = 0; ifg_id < vect.size(); ifg_id++) {
            if (m_ifg_aapl_handlers[sid][ifg_id] != nullptr) {
                aapl_close_connection(m_ifg_aapl_handlers[sid][ifg_id]);

                silicon_one::aapl_client_data_struct<la_aapl_user>* get_client_data_ptr
                    = static_cast<silicon_one::aapl_client_data_struct<la_aapl_user>*>(
                        aapl_bind_get(m_ifg_aapl_handlers[sid][ifg_id]));
                get_client_data_ptr->default_ptr.reset();
                get_client_data_ptr->log_buffer.reset();
                delete static_cast<silicon_one::aapl_client_data_struct<la_aapl_user>*>(
                    aapl_bind_get(m_ifg_aapl_handlers[sid][ifg_id]));
                aapl_bind_set(m_ifg_aapl_handlers[sid][ifg_id], nullptr);
                aapl_destruct(m_ifg_aapl_handlers[sid][ifg_id]);
            }
            if (m_ifg_aapl_native_handlers[sid][ifg_id] != nullptr) {
                aapl_close_connection(m_ifg_aapl_native_handlers[sid][ifg_id]);
                silicon_one::aapl_client_data_struct<la_aapl_user>* get_client_data_ptr
                    = static_cast<silicon_one::aapl_client_data_struct<la_aapl_user>*>(
                        aapl_bind_get(m_ifg_aapl_native_handlers[sid][ifg_id]));
                get_client_data_ptr->default_ptr.reset();
                get_client_data_ptr->log_buffer.reset();
                delete static_cast<silicon_one::aapl_client_data_struct<la_aapl_user>*>(
                    aapl_bind_get(m_ifg_aapl_native_handlers[sid][ifg_id]));
                aapl_bind_set(m_ifg_aapl_native_handlers[sid][ifg_id], nullptr);
                aapl_destruct(m_ifg_aapl_native_handlers[sid][ifg_id]);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::create_serdes_group_handler(la_slice_id_t slice_id,
                                                         la_ifg_id_t ifg_id,
                                                         la_uint_t serdes_base_id,
                                                         size_t serdes_count,
                                                         la_mac_port::port_speed_e speed,
                                                         la_mac_port::port_speed_e serdes_speed,
                                                         la_slice_mode_e serdes_slice_mode,
                                                         serdes_handler*& out_serdes_handler)
{
    bool reconnect_in_progress = m_device->m_reconnect_handler->is_reconnect_in_progress();

    Aapl_t* aapl_handler = nullptr;
    if (m_handler_initilized) {
        if (reconnect_in_progress) {
            m_device->m_ll_device->set_write_to_device(true);
        }

        // Aapl needs HW access for its initialization sequence
        la_status stat = get_ifg_aapl_handler(slice_id, ifg_id, aapl_handler);

        if (reconnect_in_progress) {
            m_device->m_ll_device->set_write_to_device(false);
        }
        return_on_error(stat);
    }

    out_serdes_handler = new avago_serdes_handler(
        m_device, aapl_handler, slice_id, ifg_id, serdes_base_id, serdes_count, speed, serdes_speed, serdes_slice_mode);
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::ring_firmware_upload(Aapl_t* aapl_handler)
{
    bool ignore_failure;
    m_device->get_bool_property(la_device_property_e::IGNORE_SBUS_MASTER_MBIST_FAILURE, ignore_failure);

    int ret = avago_spico_upload_file(aapl_handler,
                                      AVAGO_SBUS_MASTER_ADDRESS,
                                      la_device_impl::SERDES_PERFORM_SPICO_RAM_BIST,
                                      m_ifg_sbus_master_fw_info.filepath.c_str());
    if (ret < 0) {
        if (!ignore_failure) {
            log_err(HLD, "Failed avago_spico_upload_file for SBUS master -> %d", ret);
            return LA_STATUS_EUNKNOWN;
        } else {
            log_warning(HLD, "Failed avago_spico_upload_file for SBUS master -> %d, ignoring due to configuration.", ret);
        }
    }

    bool res = avago_serdes_handler::serdes_firmware_check(
        aapl_handler, AVAGO_SBUS_MASTER_ADDRESS, m_ifg_sbus_master_fw_info.revision, m_ifg_sbus_master_fw_info.build_id);
    if (!res && ignore_failure) {
        // Firmware check failed, need to retry upload without running MBIST
        ret = avago_spico_upload_file(
            aapl_handler, AVAGO_SBUS_MASTER_ADDRESS, 0 /* no MBIST */, m_ifg_sbus_master_fw_info.filepath.c_str());
        if (ret < 0) {
            log_err(HLD, "Failed avago_spico_upload_file for SBUS master (w/o MBIST) -> %d", ret);
            return LA_STATUS_EUNKNOWN;
        }

        // FW uploaded successfully, check again
        res = avago_serdes_handler::serdes_firmware_check(
            aapl_handler, AVAGO_SBUS_MASTER_ADDRESS, m_ifg_sbus_master_fw_info.revision, m_ifg_sbus_master_fw_info.build_id);
    }
    if (!res) {
        log_err(HLD, "Failed serdes_firmware_check for SBUS master %d -> %d", AVAGO_SBUS_MASTER_ADDRESS, ret);
        return LA_STATUS_EUNKNOWN;
    }

    // Enables SBUS master process to broadcast the current temperature to all SerDes's on same Ring
    avago_spico_int(aapl_handler, AVAGO_SBUS_MASTER_ADDRESS, AVAGO_HAL_INT, 1);

    ret = avago_spico_upload_file(aapl_handler,
                                  AVAGO_SERDES_M4_BROADCAST,
                                  la_device_impl::SERDES_PERFORM_SPICO_RAM_BIST,
                                  m_ifg_serdes_fw_info.filepath.c_str());
    if (ret < 0) {
        log_err(HLD, "Failed avago_spico_upload_file for All SerDes -> %d", ret);
        return LA_STATUS_EUNKNOWN;
    }

    Avago_addr_t addr_struct_head;
    Avago_addr_t* addr_struct_cur = &addr_struct_head;
    addr_struct_cur->next = nullptr;
    std::shared_ptr<void> get_client_data_ptr
        = silicon_one::aapl_bind_get_wrapper(aapl_handler, silicon_one::client_data_label::CLIENT_DATA_DEFAULT_PTR);
    std::list<uint32_t> serdes_list
        = std::static_pointer_cast<la_aapl_user_ifg_native>(get_client_data_ptr)->get_all_serdes_address_list();

    for (auto serdes : serdes_list) {
        addr_struct_cur->next = new Avago_addr_t();
        addr_struct_cur = addr_struct_cur->next;
        addr_struct_cur->next = nullptr;
        bool b_res = avago_addr_to_struct(serdes, addr_struct_cur);
        if (!b_res) {
            return LA_STATUS_EUNKNOWN;
        }
        // Invalidate revision cache in AAPL structure
        aapl_set_ip_type(aapl_handler, serdes);
    }

    bool skip_crc = true;
    ret = avago_parallel_serdes_base_init(aapl_handler, addr_struct_head.next, skip_crc);
    if (ret < 0) {
        log_err(HLD, "Failed avago_parallel_serdes_base_init for All SerDes -> %d", ret);
        return LA_STATUS_EUNKNOWN;
    }

    for (addr_struct_cur = addr_struct_head.next; addr_struct_cur != nullptr;) {
        Avago_addr_t* tmp = addr_struct_cur;
        addr_struct_cur = addr_struct_cur->next;
        delete (tmp);
    }

    for (auto serdes : serdes_list) {
        bool res = avago_serdes_handler::serdes_firmware_check(
            aapl_handler, serdes, m_ifg_serdes_fw_info.revision, m_ifg_serdes_fw_info.build_id);
        if (!res) {
            log_err(HLD, "Failed serdes_firmware_check for SerDes %d -> %d", serdes, ret);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(stat);

    if (m_ifg_aapl_handlers[slice_id][ifg_id] == nullptr) {
        Aapl_t* aapl_handler = aapl_construct(); /* Create AAPL struct */
        auto aapl_user = std::make_shared<la_aapl_user_ifg>(this->m_device, slice_id, ifg_id);

        silicon_one::aapl_client_data_struct<la_aapl_user>* ifg_struct = new silicon_one::aapl_client_data_struct<la_aapl_user>();
        ifg_struct->default_ptr = std::static_pointer_cast<la_aapl_user>(aapl_user);
        aapl_bind_set(aapl_handler, ifg_struct);

        aapl_register_sbus_fn(aapl_handler, &la_aapl_user_sbus_fn, &la_aapl_comm_open_fn, &la_aapl_comm_close_fn);
        aapl_register_logging_fn(aapl_handler, &la_aapl_log_fn, &la_aapl_log_open_fn, &la_aapl_log_close_fn);
        aapl_handler->enable_stream_logging = 0;
        aapl_handler->enable_stream_err_logging = 0;

        // Initialization - connect and retrieve IP information of the connected device
        aapl_connect(aapl_handler, 0, 0);
        if (aapl_get_return_code(aapl_handler) != 0) {
            // Failure
            return LA_STATUS_EUNKNOWN;
        }
        aapl_handler->chips = 1;
        aapl_handler->sbus_rings = 1;
        aapl_handler->jtag_idcode[0] = AAPL_PACIFIC_IDCODE;
        aapl_get_ip_info(aapl_handler, 0);

        m_ifg_aapl_handlers[slice_id][ifg_id] = aapl_handler;
    }

    out_aapl = m_ifg_aapl_handlers[slice_id][ifg_id];
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl)
{
    la_status stat = m_device->get_slice_id_manager()->is_slice_ifg_valid(slice_id, ifg_id);
    return_on_error(stat);

    if (m_ifg_aapl_native_handlers[slice_id][ifg_id] == nullptr) {
        Aapl_t* aapl_handler = aapl_construct(); /* Create AAPL struct */

        auto aapl_user = std::make_shared<la_aapl_user_ifg_native>(this->m_device, slice_id, ifg_id);

        silicon_one::aapl_client_data_struct<la_aapl_user>* sbus_struct = new silicon_one::aapl_client_data_struct<la_aapl_user>();
        sbus_struct->default_ptr = std::static_pointer_cast<la_aapl_user>(aapl_user);
        aapl_bind_set(aapl_handler, sbus_struct);

        aapl_register_sbus_fn(aapl_handler, &la_aapl_user_sbus_fn, &la_aapl_comm_open_fn, &la_aapl_comm_close_fn);
        aapl_register_logging_fn(aapl_handler, &la_aapl_log_fn, &la_aapl_log_open_fn, &la_aapl_log_close_fn);
        aapl_handler->enable_stream_logging = 0;
        aapl_handler->enable_stream_err_logging = 0;

        // Initialization - connect and retrieve IP information of the connected device
        aapl_connect(aapl_handler, 0, 0);
        if (aapl_get_return_code(aapl_handler) != 0) {
            // Failure
            return LA_STATUS_EUNKNOWN;
        }
        aapl_handler->chips = 1;
        aapl_handler->sbus_rings = 1;
        aapl_handler->jtag_idcode[0] = AAPL_PACIFIC_IDCODE;
        aapl_get_ip_info(aapl_handler, 0);

        m_ifg_aapl_native_handlers[slice_id][ifg_id] = aapl_handler;
    }
    out_aapl = m_ifg_aapl_native_handlers[slice_id][ifg_id];

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::mbist_avago_broadcast_value(uint value)
{
    Aapl_t* aapl_ring1 = nullptr;
    Aapl_t* aapl_ring2 = nullptr;
    la_status status = LA_STATUS_SUCCESS;

    status = get_native_sbus_aapl_handler(SBUS_RING1_SLICE, SBUS_RING1_IFG, aapl_ring1);
    return_on_error(status);

    status = get_native_sbus_aapl_handler(SBUS_RING2_SLICE, SBUS_RING2_IFG, aapl_ring2);
    return_on_error(status);

    avago_sbus_reset(aapl_ring1, AVAGO_ALL_SERDES, 0);
    avago_sbus_reset(aapl_ring2, AVAGO_ALL_SERDES, 0);

    avago_sbus_wr(aapl_ring1, AVAGO_ALL_SERDES, AVAGO_MBIST_REG, value);
    avago_sbus_wr(aapl_ring2, AVAGO_ALL_SERDES, AVAGO_MBIST_REG, value);

    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::mbist_activate(bool repair)
{
    uint mbist_control = repair ? AVAGO_MBIST_RUN_W_REPAIR : AVAGO_MBIST_RUN_WO_REPAIR;
    return mbist_avago_broadcast_value(mbist_control);
}

la_status
avago_serdes_device_handler::mbist_clear()
{
    return mbist_avago_broadcast_value(0); // Clear MBIST control - no MBIST
}

la_status
avago_serdes_device_handler::mbist_read(bool report_failures, size_t& total_tested, size_t& total_pass, size_t& total_failed)
{

    for (la_slice_ifg id : m_device->get_used_ifgs()) {
        Aapl_t* aapl_ring = nullptr;
        la_status status = get_ifg_aapl_handler(id.slice, id.ifg, aapl_ring);
        return_on_error(status);

        for (size_t serdes = 0; serdes < NUM_SERDES_PER_IFG; serdes++) {
            uint val = avago_sbus_rd(aapl_ring, serdes + 1, AVAGO_MBIST_REG);
            total_tested++;
            if (val & (1 << 5)) {
                total_pass++;
            }
            if (val & (1 << 6)) {
                if (report_failures) {
                    // Failed after repair
                    log_err(HLD, "SerDes MBIST failed: Slice-%u, IFG-%u, SerDes-%zd", id.slice, id.ifg, serdes);
                } else {
                    // Failed without repair, not really interesting.
                    log_debug(HLD, "SerDes MBIST failed: Slice-%u, IFG-%u, SerDes-%zd", id.slice, id.ifg, serdes);
                }
                total_failed++;
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
avago_serdes_device_handler::get_serdes_addr(la_slice_id_t slice,
                                             la_ifg_id_t ifg,
                                             la_uint_t serdes_idx,
                                             la_serdes_direction_e direction,
                                             uint32_t& out_serdes_addr)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
avago_serdes_device_handler::get_component_health(la_component_health_vec_t& out_component_health) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
}
