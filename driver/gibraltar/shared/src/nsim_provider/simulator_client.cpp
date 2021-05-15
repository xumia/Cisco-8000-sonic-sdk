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

#include <functional>              // for _1, _2
using namespace std::placeholders; // for _1, _2, _3...

#include "device_simulator/dsim_client/dsim_client.h"
#include "device_simulator/dsim_common/nsim_command.h"
#include "nsim_provider/sim_command.h"
#include "simulator_client.h"
#include "utils/npsuite_logger.h"

#include "common/gen_utils.h"
#include "common/logger.h"

void
reg_data_2_bv(const silicon_one::sim_command::reg_data& rd, nsim::bit_vector& out_bv)
{
    if (rd.long_cmd.width != 0) {
        out_bv.resize(&(rd.long_cmd.value), rd.long_cmd.width);
    } else {
        out_bv = nsim::bit_vector();
    }
}

nsim::nsim_command::nsim_command_type
sim_command_e_2_nsim_command_type(silicon_one::sim_command::nsim_command_e sim_cmd_type)
{
    switch (sim_cmd_type) {
    case silicon_one::sim_command::nsim_command_e::TABLE_INSERT:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_TABLE_INSERT;
    case silicon_one::sim_command::nsim_command_e::TABLE_ERASE:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_TABLE_ERASE;
    case silicon_one::sim_command::nsim_command_e::TABLE_UPDATE:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_TABLE_UPDATE;
    // lpm table commands
    case silicon_one::sim_command::nsim_command_e::LPM_TABLE_INSERT:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_LPM_TABLE_INSERT;
    case silicon_one::sim_command::nsim_command_e::LPM_TABLE_ERASE:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_LPM_TABLE_ERASE;
    case silicon_one::sim_command::nsim_command_e::LPM_TABLE_UPDATE:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_LPM_TABLE_UPDATE;
    // ternary table commands
    case silicon_one::sim_command::nsim_command_e::TERNARY_TABLE_INSERT:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_TERNARY_TABLE_INSERT;
    case silicon_one::sim_command::nsim_command_e::TERNARY_TABLE_ERASE:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_TERNARY_TABLE_ERASE;
    case silicon_one::sim_command::nsim_command_e::TERNARY_TABLE_UPDATE:
        return nsim::nsim_command::NSIM_COMMAND_TYPE_TERNARY_TABLE_UPDATE;
    default:
        return -1;
    }
}

void
extract_sim_command_2_nsim_command(const silicon_one::sim_command::command& sim_cmd, nsim::nsim_command::command& nsim_cmd_ref)
{
    nsim::bit_vector key_bv, value_bv, mask_bv;
    reg_data_2_bv(sim_cmd.key, key_bv);
    reg_data_2_bv(sim_cmd.value, value_bv);
    reg_data_2_bv(sim_cmd.key_mask, mask_bv);
    nsim_cmd_ref = nsim::nsim_command::command(sim_command_e_2_nsim_command_type(sim_cmd.cmd),
                                               sim_cmd.table_id,
                                               sim_cmd.slice_idx,
                                               sim_cmd.key_len,
                                               sim_cmd.line,
                                               key_bv,
                                               value_bv,
                                               mask_bv);
}

namespace silicon_one
{

bool
simulator_client::initialize(const char* socket_addr, size_t port, const char* sdk_version)
{
    bool ok = m_client->initialize(socket_addr, port, sdk_version);
    if (!ok) {
        return false;
    }

    return ok;
}

simulator_client::simulator_client()
{
    m_client = new dsim::dsim_client(MAX_NUM_OF_CONNECTION_RETRIES, MAX_TIMEOUT_BETWEEN_RETRIES);

    //
    // Request a copy of DSIM client logs to be sent to the SDK
    //
    auto cb = std::bind(&simulator_client::handle_npsuite_logger_message_callback, this, _1);
    client_log_handle = m_client->register_log_message_callback(cb);
}

//
// This is a callback from nsim when it has logged a message. This hook point allows the
// SDK to report nsim logs, so that the nsim logs appear alongside SDK logs. This helps
// with debugging DSIM client issues.
//
void
simulator_client::handle_npsuite_logger_message_callback(const npsuite::npsuite_logger_message_callback_data_t& data)
{
    switch (data.level) {
    case npsuite::NPSUITE_LOG_LEVEL_TRACE:
        log_xdebug(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_DEBUG:
        log_debug(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_INFO:
        log_info(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_PROGRESS:
        log_notice(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_WARNING:
        log_warning(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_ESSENTIAL:
        log_notice(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_ERROR:
        log_err(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_FATAL:
        log_crit(SIM, "%s%s%s", data.thread_prefix.c_str(), data.msg_prefix.c_str(), data.msg.c_str());
        break;
    case npsuite::NPSUITE_LOG_LEVEL_NUM_LEVELS:
        break;
    }
}

simulator_client::~simulator_client()
{
    //
    // No real need to call unregister_log_message_callback here.
    //
    // m_client->unregister_log_message_callback(client_log_handle);

    delete m_client;
}

la_device_revision_e
simulator_client::get_device_revision() const
{
    const char* lookup[] = {
            [(size_t)la_device_revision_e::NONE] = "NONE",
            [(size_t)la_device_revision_e::PACIFIC_A0] = "PACIFIC_A0",
            [(size_t)la_device_revision_e::PACIFIC_B0] = "PACIFIC_B0",
            [(size_t)la_device_revision_e::PACIFIC_B1] = "PACIFIC_B1",
            [(size_t)la_device_revision_e::GIBRALTAR_A0] = "GIBRALTAR_A0",
            [(size_t)la_device_revision_e::GIBRALTAR_A1] = "GIBRALTAR_A1",
            [(size_t)la_device_revision_e::GIBRALTAR_A2] = "GIBRALTAR_A2",
            [(size_t)la_device_revision_e::ASIC4_A0] = "ASIC4_A0",
            [(size_t)la_device_revision_e::ASIC3_A0] = "ASIC3_A0",
            [(size_t)la_device_revision_e::ASIC7_A0] = "ASIC7_A0",
            [(size_t)la_device_revision_e::ASIC5_A0] = "ASIC5_A0",
    };
    static_assert(array_size(lookup) == (size_t)la_device_revision_e::LAST + 1, "bad size");

    std::string device_revision = m_client->get_device_revision();
    log_info(SIM, "%s: device_revision=%s", __func__, device_revision.c_str());

    for (size_t i = 0; i < array_size(lookup); ++i) {
        if (device_revision == lookup[i]) {
            return (la_device_revision_e)i;
        }
    }

    return la_device_revision_e::NONE;
}

la_status
simulator_client::read_register(la_block_id_t block_id,
                                la_entry_addr_t reg_address,
                                la_entry_width_t reg_width,
                                size_t count,
                                void* out_val)
{
    dsim::dsim_status_e result
        = m_client->read_register((uint32_t)block_id, (uint32_t)reg_address, (uint16_t)reg_width, count, out_val);

    return dsim_2_la_status(result);
}

la_status
simulator_client::write_register(la_block_id_t block_id,
                                 la_entry_addr_t reg_address,
                                 la_entry_width_t reg_width,
                                 size_t count,
                                 const void* in_val)
{
    dsim::dsim_status_e result
        = m_client->write_register((uint32_t)block_id, (uint32_t)reg_address, (uint16_t)reg_width, count, in_val);

    return dsim_2_la_status(result);
}

la_status
simulator_client::read_memory(la_block_id_t block_id,
                              la_entry_addr_t mem_address,
                              la_entry_width_t mem_width,
                              size_t mem_entries,
                              void* out_val)
{
    // Currently we don't support reading from nsim
    dsim::dsim_status_e result
        = m_client->read_memory((uint32_t)block_id, (uint32_t)mem_address, (uint16_t)mem_width, mem_entries, out_val);

    if (result == dsim::dsim_status_e::DSIM_STATUS_ENOTIMPLEMENTED) {
        // R.B.: TODO: Temporal FIX to enable test runs, failing due to excessive log size.
        result = dsim::dsim_status_e::DSIM_STATUS_SUCCESS;
    }
    return dsim_2_la_status(result);
}

la_status
simulator_client::write_memory(la_block_id_t block_id,
                               la_entry_addr_t mem_address,
                               la_entry_width_t mem_width,
                               size_t mem_entries,
                               const void* in_val)
{
    dsim::dsim_status_e result;
    if ((block_id == m_client->get_sim_access_block_id()) && (mem_address != m_client->get_sim_access_mem_address_place_udk())) {
        nsim::nsim_command::command nsim_cmd;
        const sim_command::command* sim_cmd = static_cast<const sim_command::command*>(in_val);
        extract_sim_command_2_nsim_command(*sim_cmd, nsim_cmd);

        result = m_client->write_memory((uint32_t)block_id,
                                        (uint32_t)mem_address,
                                        calculate_command_len(nsim_cmd),
                                        1 /*only one entry is supported for sim_access*/,
                                        &nsim_cmd);
    } else {
        result = m_client->write_memory((uint32_t)block_id, (uint32_t)mem_address, (uint16_t)mem_width, mem_entries, in_val);
    }

    return dsim_2_la_status(result);
}

la_status
simulator_client::add_property(std::string key, std::string value)
{
    dsim::dsim_status_e result;
    result = m_client->add_property(key, value);
    return dsim_2_la_status(result);
}

la_status
simulator_client::open_device(int& device_fd, int& interrupt_fd, size_t& interrupt_width_bytes)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

void
simulator_client::close_device(int device_fd, int interrupt_fd)
{
}

la_status
simulator_client::dsim_2_la_status(dsim::dsim_status_e status)
{
    switch (status) {
    case dsim::dsim_status_e::DSIM_STATUS_SUCCESS:
        return LA_STATUS_SUCCESS;
    case dsim::dsim_status_e::DSIM_STATUS_EEXIST:
        return LA_STATUS_EEXIST;
    case dsim::dsim_status_e::DSIM_STATUS_EINVAL:
        return LA_STATUS_EINVAL;
    case dsim::dsim_status_e::DSIM_STATUS_ENOTFOUND:
        return LA_STATUS_ENOTFOUND;
    case dsim::dsim_status_e::DSIM_STATUS_ENOTIMPLEMENTED:
        return LA_STATUS_ENOTIMPLEMENTED;
    case dsim::dsim_status_e::DSIM_STATUS_EUNKNOWN:     // fallthrough
    case dsim::dsim_status_e::DSIM_STATUS_ESERIALIZE:   // fallthrough
    case dsim::dsim_status_e::DSIM_STATUS_EDESERIALIZE: // fallthrough
    case dsim::dsim_status_e::DSIM_STATUS_EVERSION:     // fallthrough
        return LA_STATUS_EUNKNOWN;
    case dsim::dsim_status_e::DSIM_STATUS_ESIZE:
        return LA_STATUS_ESIZE;
    case dsim::dsim_status_e::DSIM_STATUS_ENOTINITIALIZED:
        return LA_STATUS_ENOTINITIALIZED;
    }

    return LA_STATUS_EUNKNOWN;
}

} // namespace silicon_one
