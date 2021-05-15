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

#include "aapl_impl.h"
#include "common/defines.h"
#include "la_device_impl.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "system/slice_id_manager_base.h"
#include <sstream>

using namespace silicon_one;

// In Pacific all 12 SerDes pools uses two SBus master rings
// Defines through which SBus master to access
// Note: Avago lowest device ID is "1".
//       So in Pacific we have in each IFG SerDes 1-18 (not 0-17)
struct ifg_sbus_master_interface_t {
    la_slice_id_t slice_id; ///< Slice of the SBus master.
    la_ifg_id_t ifg_id;     ///< IFG of the SBus master.
    uint32_t base_addr;     ///< Base address (SerDes 0 address) on the SBus.
};

ifg_sbus_master_interface_t s_sbus_master_interface[NUM_IFGS_PER_DEVICE] = {{2, 0, 72},
                                                                            {2, 0, 91},
                                                                            {2, 0, 54},
                                                                            {2, 0, 36},
                                                                            {2, 0, 0},
                                                                            {2, 0, 18},
                                                                            {3, 1, 19},
                                                                            {3, 1, 0},
                                                                            {3, 1, 37},
                                                                            {3, 1, 55},
                                                                            {3, 1, 91},
                                                                            {3, 1, 73}};

//--------------------------------------------------------------------------
// SBus defines
//--------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct {
    uint32_t receiver : 8;
    uint32_t address : 8;
    uint32_t command : 8;
} sbm_request_register_t;

typedef struct {
    uint32_t valid : 1;
    uint32_t code : 3;
} sbm_response_register_t;
#pragma pack(pop)

enum {
    SBUS_MASTER_RCVR_CMD_RESET = 0x20,
    SBUS_MASTER_RCVR_CMD_WRITE = 0x21,
    SBUS_MASTER_RCVR_CMD_READ = 0x22,
};

enum {
    SBUS_MASTER_RESULT_RESET = 0,
    SBUS_MASTER_RESULT_WRITE_COMPLETE = 1,
    SBUS_MASTER_RESULT_READ_ALL_COMPLETE = 2,
    SBUS_MASTER_RESULT_WRITE_FAILED = 3,
    SBUS_MASTER_RESULT_READ_COMPLETE = 4,
    SBUS_MASTER_RESULT_MODE_CHNG_COMPLETE = 5,
    SBUS_MASTER_RESULT_READ_FAILED = 6,
    SBUS_MASTER_RESULT_CMD_ISSUE_DONE = 7,
};

enum {
    SBUS_MASTER_POLL_TIMEOUT = 20, // Maximum number to poll SBus master completion
    SBUS_DATA_SIZE_IN_BYTES = 4,   // Data size for read/write on the SBus master
};

enum {
    AAPL_PCI_DELAY_BEFORE_EXEC = 0,
    AAPL_PCI_DELAY_BEFORE_POLL = 0,
};

#define aapl_log_message(severity, ctx, format, ...)                                                                               \
    {                                                                                                                              \
        logger& instance = logger::instance();                                                                                     \
        la_device_id_t device_id = ctx->m_device_impl->get_id();                                                                   \
        if (instance.is_logging(device_id, la_logger_component_e::AAPL, la_logger_level_e::severity))                              \
            instance.log(device_id, la_logger_component_e::AAPL, la_logger_level_e::severity, format, ##__VA_ARGS__);              \
    }

#define start_aapl_call(ctx, ...)                                                                                                  \
    aapl_log_message(DEBUG, ctx, __VA_ARGS__);                                                                                     \
    std::lock_guard<std::recursive_mutex> lock(ctx->m_device_impl->m_aapl_mutex)

//--------------------------------------------------------------------------

la_aapl_user::la_aapl_user(const la_device_impl_wptr& device_impl)
    : m_device_impl(device_impl),
      m_delay_before_exec_cycles(0),
      m_delay_before_poll_cycles(0),
      m_delay_in_poll_cycles(0),
      m_poll_timeout(SBUS_MASTER_POLL_TIMEOUT)
{
}

void
la_aapl_user::delay_before_exec() const
{
    if (m_delay_before_exec_cycles) {
        m_device_impl->m_ll_device->delay(m_delay_before_exec_cycles);
    }
}

void
la_aapl_user::delay_before_poll() const
{
    if (m_delay_before_poll_cycles) {
        m_device_impl->m_ll_device->delay(m_delay_before_poll_cycles);
    }
}

void
la_aapl_user::delay_in_poll() const
{
    if (m_delay_in_poll_cycles) {
        m_device_impl->m_ll_device->delay(m_delay_in_poll_cycles);
    }
}

int
la_aapl_user::get_poll_timeout() const
{
    return m_poll_timeout;
}
//--------------------------------------------------------------------------
la_aapl_user_ifg_native::la_aapl_user_ifg_native(const la_device_impl_wptr& device_impl, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : la_aapl_user(device_impl)
{
    m_slice_id = slice_id;
    m_ifg_id = ifg_id;
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_DELAY_BEFORE_EXEC, m_delay_before_exec_cycles);
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_DELAY_BEFORE_POLL, m_delay_before_poll_cycles);
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_DELAY_IN_POLL, m_delay_in_poll_cycles);
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_POLL_TIMEOUT, m_poll_timeout);

    size_t ifg_idx = m_device_impl->get_slice_id_manager()->slice_ifg_2_global_ifg(m_slice_id, m_ifg_id);
    la_slice_id_t sbm_slice_id = s_sbus_master_interface[ifg_idx].slice_id;
    la_ifg_id_t sbm_ifg_id = s_sbus_master_interface[ifg_idx].ifg_id;

    std::stringstream ss;
    ss << "Native SBus Master (slice=" << sbm_slice_id << ", ifg=" << m_ifg_id << ")";
    m_name = ss.str();

    if ((m_slice_id != sbm_slice_id) || (m_ifg_id != sbm_ifg_id)) {
        aapl_log_message(INFO,
                         this,
                         "AAPL handler for slice/IFG %d/%d translated to slice/IFG %d/%d",
                         m_slice_id,
                         m_ifg_id,
                         sbm_slice_id,
                         sbm_ifg_id);
    }

    m_request_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_req_reg;
    m_request_data_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_req_data_reg;
    m_request_exec_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_req_execute_reg;
    m_response_result_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_rsp_result_reg;
    m_response_data_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_rsp_data_reg;
}

std::list<uint32_t>
la_aapl_user_ifg_native::get_all_serdes_address_list()
{
    std::list<uint32_t> out_list;
    for (int i = 0; i < NUM_IFGS_PER_DEVICE; i++) {
        if (s_sbus_master_interface[i].slice_id != m_slice_id || s_sbus_master_interface[i].ifg_id != m_ifg_id)
            continue;
        for (int j = 1; j <= NUM_SERDES_PER_IFG; j++)
            out_list.push_back(s_sbus_master_interface[i].base_addr + j);
    }
    return out_list;
}

uint32_t
la_aapl_user_ifg_native::receiver_address_translate(uint32_t addr) const
{
    return addr;
}

//--------------------------------------------------------------------------
la_aapl_user_ifg::la_aapl_user_ifg(const la_device_impl_wptr& device_impl, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : la_aapl_user(device_impl)
{
    m_slice_id = slice_id;
    m_ifg_id = ifg_id;
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_DELAY_BEFORE_EXEC, m_delay_before_exec_cycles);
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_DELAY_BEFORE_POLL, m_delay_before_poll_cycles);
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_DELAY_IN_POLL, m_delay_in_poll_cycles);
    m_device_impl->get_int_property(la_device_property_e::AAPL_IFG_POLL_TIMEOUT, m_poll_timeout);

    std::stringstream ss;
    ss << "SBus Master (slice=" << m_slice_id << ", ifg=" << m_ifg_id << ")";
    m_name = ss.str();

    size_t ifg_idx = m_device_impl->get_slice_id_manager()->slice_ifg_2_global_ifg(m_slice_id, m_ifg_id);

    la_slice_id_t sbm_slice_id = s_sbus_master_interface[ifg_idx].slice_id;
    la_ifg_id_t sbm_ifg_id = s_sbus_master_interface[ifg_idx].ifg_id;
    m_base_addr = s_sbus_master_interface[ifg_idx].base_addr;

    m_request_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_req_reg;
    m_request_data_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_req_data_reg;
    m_request_exec_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_req_execute_reg;
    m_response_result_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_rsp_result_reg;
    m_response_data_reg = m_device_impl->m_pacific_tree->slice[sbm_slice_id]->ifg[sbm_ifg_id]->serdes_pool->sbm_rsp_data_reg;
}

uint32_t
la_aapl_user_ifg::receiver_address_translate(uint32_t addr) const
{
    // The SBus contains SerDes's which we translate their address and some Avago components (e.g. Spico) which we don't
    // translate.
    if (addr <= NUM_SERDES_PER_IFG) {
        return (m_base_addr + addr);
    } else {
        return addr;
    }
}

//--------------------------------------------------------------------------
la_aapl_user_pci::la_aapl_user_pci(const la_device_impl_wptr& device_impl) : la_aapl_user(device_impl)
{
    m_name = "PCI";
    m_delay_before_exec_cycles = AAPL_PCI_DELAY_BEFORE_EXEC;
    m_delay_before_poll_cycles = AAPL_PCI_DELAY_BEFORE_POLL;

    m_request_reg = m_device_impl->m_pacific_tree->sbif->sbm_req_reg;
    m_request_data_reg = m_device_impl->m_pacific_tree->sbif->sbm_req_data_reg;
    m_request_exec_reg = m_device_impl->m_pacific_tree->sbif->sbm_req_execute_reg;
    m_response_result_reg = m_device_impl->m_pacific_tree->sbif->sbm_rsp_result_reg;
    m_response_data_reg = m_device_impl->m_pacific_tree->sbif->sbm_rsp_data_reg;
}

uint32_t
la_aapl_user_pci::receiver_address_translate(uint32_t addr) const
{
    return addr;
}

//--------------------------------------------------------------------------
la_aapl_user_hbm::la_aapl_user_hbm(const la_device_impl_wptr& device_impl, size_t hbm_interface) : la_aapl_user(device_impl)
{
    m_hbm_interface = hbm_interface;
    m_device_impl->get_int_property(la_device_property_e::AAPL_HBM_DELAY_BEFORE_EXEC, m_delay_before_exec_cycles);
    m_device_impl->get_int_property(la_device_property_e::AAPL_HBM_DELAY_BEFORE_POLL, m_delay_before_poll_cycles);

    std::stringstream ss;
    ss << "HBM (interface=" << m_hbm_interface << ")";
    m_name = ss.str();

    if (m_hbm_interface == 0) {
        m_request_reg = m_device_impl->m_pacific_tree->hbm->lo->sbm_req_reg;
        m_request_data_reg = m_device_impl->m_pacific_tree->hbm->lo->sbm_req_data_reg;
        m_request_exec_reg = m_device_impl->m_pacific_tree->hbm->lo->sbm_req_execute_reg;
        m_response_result_reg = m_device_impl->m_pacific_tree->hbm->lo->sbm_rsp_result_reg;
        m_response_data_reg = m_device_impl->m_pacific_tree->hbm->lo->sbm_rsp_data_reg;
    } else {
        // m_hbm_interface == 1
        m_request_reg = m_device_impl->m_pacific_tree->hbm->hi->sbm_req_reg;
        m_request_data_reg = m_device_impl->m_pacific_tree->hbm->hi->sbm_req_data_reg;
        m_request_exec_reg = m_device_impl->m_pacific_tree->hbm->hi->sbm_req_execute_reg;
        m_response_result_reg = m_device_impl->m_pacific_tree->hbm->hi->sbm_rsp_result_reg;
        m_response_data_reg = m_device_impl->m_pacific_tree->hbm->hi->sbm_rsp_data_reg;
    }
}

uint32_t
la_aapl_user_hbm::receiver_address_translate(uint32_t addr) const
{
    return addr;
}

//--------------------------------------------------------------------------
la_status
sbus_master_read_register(la_aapl_user* ctx, uint addr, unsigned char reg_addr, uint* sbus_data)
{
    // Set RequestReg - Command, SBM receiver, and Address
    sbm_request_register_t request;
    request.receiver = ctx->receiver_address_translate(addr);
    request.address = reg_addr;
    request.command = SBUS_MASTER_RCVR_CMD_READ;

    sbm_response_register_t response;
    response.valid = 0; // invalid

    start_aapl_call(ctx, "Read register from SBus Master (ADDR 0x%X, Register 0x%X)", request.receiver, reg_addr);

    la_status stat = ctx->m_device_impl->m_ll_device->write_register(*(ctx->m_request_reg), sizeof(request), &request);
    return_on_error(stat);

    // Not doing that results (on some systems) in CRC error at parallel FW upload.
    ctx->delay_before_exec();

    // Trigger RequestExecReg
    bit_vector exec_bit(1, 1);
    stat = ctx->m_device_impl->m_ll_device->write_register(*(ctx->m_request_exec_reg), exec_bit);
    return_on_error(stat);

    // It takes a while for "exec" bit to transition from 0 to 1. Delay before waiting for 1 to 0 transition.
    ctx->delay_before_poll();

    stat = ctx->m_device_impl->m_ll_device->wait_for_value(*(ctx->m_request_exec_reg), true /* equal */, 0 /* val */, 1 /* mask */);
    return_on_error(stat);

    // Poll SBUS master until operation completes or timeout occurs.
    for (int i = 0; !response.valid && (i < ctx->get_poll_timeout()); i++) {
        stat = ctx->m_device_impl->m_ll_device->read_register(*(ctx->m_response_result_reg), sizeof(response), &response);
        return_on_error(stat);
    }

    if (!response.valid) {
        // Response is still invalid (reached timeout)
        aapl_log_message(ERROR, ctx, "Timeout for Valid response on SBus Master read (ADDR 0x%X, Register 0x%X)", addr, reg_addr);
        return LA_STATUS_EUNKNOWN;
    }

    if (response.code != SBUS_MASTER_RESULT_READ_COMPLETE) {
        // Operation completed but read is unsuccessful
        aapl_log_message(ERROR, ctx, "Failed read from SBus Master (%d - ADDR 0x%X, Register 0x%X)", response.code, addr, reg_addr);
        return LA_STATUS_EUNKNOWN;
    }

    // If valid and success -> retrieve ResponseDataReg
    stat = ctx->m_device_impl->m_ll_device->read_register(*(ctx->m_response_data_reg), SBUS_DATA_SIZE_IN_BYTES, sbus_data);

    return stat;
}

la_status
sbus_master_write_register(la_aapl_user* ctx, uint addr, uint command, unsigned char reg_addr, uint* sbus_data)
{
    // Set RequestReg - Command, SBM receiver, and Address
    sbm_request_register_t request;
    request.receiver = ctx->receiver_address_translate(addr);
    request.address = reg_addr;
    request.command = command;

    sbm_response_register_t response;
    response.valid = 0; // invalid

    start_aapl_call(ctx,
                    "%s register to SBus Master (ADDR 0x%X, Register 0x%X, Value 0x%X)",
                    command == SBUS_MASTER_RCVR_CMD_RESET ? "Reset" : "Write",
                    request.receiver,
                    reg_addr,
                    *sbus_data);

    la_status stat = ctx->m_device_impl->m_ll_device->write_register(*(ctx->m_request_reg), sizeof(request), &request);
    return_on_error(stat);

    // Set RequestDataReg
    stat = ctx->m_device_impl->m_ll_device->write_register(*(ctx->m_request_data_reg), SBUS_DATA_SIZE_IN_BYTES, sbus_data);
    return_on_error(stat);

    // Not doing that results (on some systems) in CRC error at parallel FW upload.
    ctx->delay_before_exec();

    // Trigger RequestExecReg
    bit_vector exec_bit(1, 1);
    stat = ctx->m_device_impl->m_ll_device->write_register(*(ctx->m_request_exec_reg), exec_bit);
    return_on_error(stat);

    // It takes a while for "exec" bit to transition from 0 to 1. Delay before waiting for 1 to 0 transition.
    ctx->delay_before_poll();

    stat = ctx->m_device_impl->m_ll_device->wait_for_value(*(ctx->m_request_exec_reg), true /* equal */, 0 /* val */, 1 /* mask */);
    return_on_error(stat);

    // Query ResponseResultReg / Poll, till response valid

    // Poll SBUS master until operation completes or timeout occurs.
    for (int i = 0; !response.valid && (i < ctx->get_poll_timeout()); i++) {
        stat = ctx->m_device_impl->m_ll_device->read_register(*(ctx->m_response_result_reg), sizeof(response), &response);
        return_on_error(stat);

        // Experimental delay in poll to debug ifg sbus master timeouts
        ctx->delay_in_poll();
    }

    if (!response.valid) {
        // Response is still invalid (reached timeout)
        aapl_log_message(ERROR, ctx, "Timeout for Valid response on SBus Master write (ADDR 0x%X, Register 0x%X)", addr, reg_addr);
        return LA_STATUS_EUNKNOWN;
    }

    if (command == SBUS_MASTER_RCVR_CMD_RESET) {
        if (response.code != SBUS_MASTER_RESULT_RESET) {
            // Operation completed but reset is unsuccessful
            aapl_log_message(
                ERROR, ctx, "Failed reset to SBus Master (%d - ADDR 0x%X, Register 0x%X)", response.code, addr, reg_addr);
            return LA_STATUS_EUNKNOWN;
        }
    } else {
        // command == SBUS_MASTER_RCVR_CMD_WRITE
        if (response.code != SBUS_MASTER_RESULT_WRITE_COMPLETE) {
            // Operation completed but write is unsuccessful
            aapl_log_message(
                ERROR, ctx, "Failed write to SBus Master (%d - ADDR 0x%X, Register 0x%X)", response.code, addr, reg_addr);
            return LA_STATUS_EUNKNOWN;
        }
    }

    return LA_STATUS_SUCCESS;
}

// Function to wrap aapl_bind_get for casting convenience
// If needed to get the aapl_client_data_struct, call aapl_bind_get() defined in aapl_core.c and aapl_core.h
// return: void pointer for client_data usage
// aapl: aapl handler
// type: label indicating which pointer in the aapl_client_data_struct
//        silicon_one::DATA_CLIENT_DEFAULTPTR, silicon_one::DATA_CLIENT_LOG_BUFFER
std::shared_ptr<void>
silicon_one::aapl_bind_get_wrapper(Aapl_t* aapl, silicon_one::client_data_label label)
{
    silicon_one::aapl_client_data_struct<la_aapl_user>* get_client_data
        = static_cast<silicon_one::aapl_client_data_struct<la_aapl_user>*>(aapl_bind_get(aapl));
    if (!get_client_data) {
        return nullptr;
    }

    switch (label) {
    case silicon_one::client_data_label::CLIENT_DATA_LOG_BUFFER:
        return std::static_pointer_cast<void>(get_client_data->log_buffer);
    default:
        return std::static_pointer_cast<void>(get_client_data->default_ptr);
    }
}

// Function to communicate with SBus through Leaba LLD and to be registered to AAPL
// Register using aapl_register_sbus_fn which defined in aapl_core.h and aapl_core.c.
// Following is from aapl_core.c:
/**          The arguments for the registered SBus function are: */
/**             return: TRUE or FALSE to indicate if the command succeeded. */
/**             addr: SBus address to operate on. Corresponds to the *_sbus_receiver_address ports of the SBus master. */
/**             reg_addr: Data address within the given SBus address to operate on. */
/**             Corresponds to the *_sbus_data_address ports on the SBus master. */
/**             command: SBus command to send. Corresponds to the *_sbus_command ports on the SBus master. */
/**                 Required commands are: 1: write, 2: read, 0: reset */
/**             sbus_data: Pointer to the SBus data to write. Results of SBus read operations will be placed here. */
uint
la_aapl_user_sbus_fn(::Aapl_t* aapl, uint addr, unsigned char reg_addr, unsigned char command, uint* sbus_data)
{
    // check aapl != nullptr
    if (!aapl) {
        return FALSE;
    }
    la_aapl_user* aapl_user = nullptr;
    std::shared_ptr<void> get_ptr
        = silicon_one::aapl_bind_get_wrapper(aapl, silicon_one::client_data_label::CLIENT_DATA_DEFAULT_PTR);

    if (get_ptr) {
        aapl_user = static_cast<la_aapl_user*>(get_ptr.get());
    }
    if (!aapl_user) {
        return FALSE;
    }

    if (!aapl_user->m_device_impl) {
        return FALSE;
    }

    la_status stat = LA_STATUS_SUCCESS;

    if (command == 1) {
        // write command
        stat = sbus_master_write_register(aapl_user, addr, SBUS_MASTER_RCVR_CMD_WRITE, reg_addr, sbus_data);

        return (stat == LA_STATUS_SUCCESS);
    }

    if (command == 2) {
        // read command
        stat = sbus_master_read_register(aapl_user, addr, reg_addr, sbus_data);

        return (stat == LA_STATUS_SUCCESS);
    }

    if (command == 0) {
        // reset command
        stat = sbus_master_write_register(aapl_user, addr, SBUS_MASTER_RCVR_CMD_RESET, reg_addr, sbus_data);

        return (stat == LA_STATUS_SUCCESS);
    }

    return FALSE;
}

// Callback function to be used by AAPL
// Interface defined in aapl_core.h and aapl_core.c
int
la_aapl_comm_open_fn(::Aapl_t* aapl)
{
    if (!aapl) {
        return FALSE;
    }

    la_aapl_user* aapl_user = nullptr;
    std::shared_ptr<void> get_ptr
        = silicon_one::aapl_bind_get_wrapper(aapl, silicon_one::client_data_label::CLIENT_DATA_DEFAULT_PTR);

    if (get_ptr) {
        aapl_user = static_cast<la_aapl_user*>(get_ptr.get());
    }

    if (!aapl_user) {
        return FALSE;
    }

    if (!aapl_user->m_device_impl) {
        return FALSE;
    }

    return TRUE;
}

// Callback function to be used by AAPL
// Interface defined in aapl_core.h and aapl_core.c
int
la_aapl_comm_close_fn(::Aapl_t* aapl)
{
    if (!aapl) {
        return FALSE;
    }

    la_aapl_user* aapl_user = nullptr;
    std::shared_ptr<void> get_ptr
        = silicon_one::aapl_bind_get_wrapper(aapl, silicon_one::client_data_label::CLIENT_DATA_DEFAULT_PTR);

    if (get_ptr) {
        aapl_user = static_cast<la_aapl_user*>(get_ptr.get());
    }

    if (!aapl_user) {
        return FALSE;
    }

    if (!aapl_user->m_device_impl) {
        return FALSE;
    }

    if (!aapl_user->m_device_impl) {
        return FALSE;
    }

    return TRUE;
}

void
la_aapl_log_fn(Aapl_t* aapl, Aapl_log_type_t log_sel, const char* buf, size_t new_item_length)
{

    la_aapl_user* ctx = nullptr;
    std::shared_ptr<void> get_ptr
        = silicon_one::aapl_bind_get_wrapper(aapl, silicon_one::client_data_label::CLIENT_DATA_DEFAULT_PTR);

    if (get_ptr) {
        ctx = static_cast<la_aapl_user*>(get_ptr.get());
    }

    la_logger_level_e log_level = la_logger_level_e::ERROR;

    if (log_sel < Aapl_log_type_t::AVAGO_ERR) {
        log_level = la_logger_level_e::DEBUG;
    } else if (log_sel == Aapl_log_type_t::AVAGO_ERR) {
        log_level = la_logger_level_e::ERROR;
    } else if (log_sel == Aapl_log_type_t::AVAGO_WARNING) {
        log_level = la_logger_level_e::WARNING;
    } else if (log_sel == Aapl_log_type_t::AVAGO_INFO) {
        log_level = la_logger_level_e::INFO;
    }

    logger& instance = logger::instance();
    la_device_id_t device_id = ctx->m_device_impl->get_id();
    if (instance.is_logging(device_id, la_logger_component_e::AAPL, log_level)) {
        instance.log(device_id, la_logger_component_e::AAPL, log_level, "%s: %s", ctx->m_name.c_str(), buf);
    }
}

// Callback function to be used by AAPL
int
la_aapl_log_open_fn(Aapl_t*)
{
    return TRUE;
}

// Callback function to be used by AAPL
int
la_aapl_log_close_fn(Aapl_t*)
{
    return TRUE;
}
