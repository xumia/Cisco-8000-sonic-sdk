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

#include "device_simulator/dsim_client/dsim_socket_client.h"
#include "device_simulator/socket_command.h"
#include "device_simulator/packet_dma_inject.h"
#include "utils/logger/logger.h"
#include "utils/serialize.h"

using namespace npsuite;
using namespace dsim;

const std::pair<packet_dma_inject_reg_id_t, unsigned>& dsim::packet_dma_inject::INJ_DMA_REG_UNKNOWN
    = std::make_pair(INJ_DMA_REG_ID_MAX, 0);

static const std::string send_prefix = "DSIM client packet dma inject tx: ";

dsim::packet_dma_inject::packet_dma_inject()
{
    m_logger = nullptr;
    m_socket_client = nullptr;
}

void
dsim::packet_dma_inject::initialize(npsuite::Logger* logger,
                                    socket_client* client,
                                    const device_info& device_info,
                                    std::istringstream& stream_reg_addresses,
                                    std::istringstream& stream_reg_names)
{
    if (strcmp(device_info.device_name, "gibraltar") == 0) {
        m_device = DEVICE_TYPE_GIBRALTAR;
        m_pd_desc_increment = 1;
        m_pd_desc_multiplier = DESC_BUFFER_ELEMENT_SIZE_BYTES;
    } else {
        m_device = DEVICE_TYPE_PACIFIC;
        m_pd_desc_increment = DESC_BUFFER_ELEMENT_SIZE_BYTES;
        m_pd_desc_multiplier = 1;
    }

    //
    // Deserialize packet DMA data
    //
    std::array<uint32_t, dsim::INJ_DMA_REG_ID_MAX> reg_addresses;
    for (auto& i : reg_addresses) { // VC did not like {{}} initializer
        i = 0;
    }
    stream_reg_addresses >> encapsulate_value(reg_addresses);

    std::array<std::string, dsim::INJ_DMA_REG_ID_MAX> reg_names;
    for (auto& i : reg_names) { // VC did not like {{}} initializer
        i = "";
    }
    stream_reg_names >> encapsulate_value(reg_names);

    //
    // Create a map for faster lookups
    //
    auto idx = 0U;
    for (const auto& reg_name : reg_names) {
        m_reg_name_to_addr[reg_name] = reg_addresses[idx];
        idx++;
    }

    memset(&m_inj_asic, 0, sizeof(m_inj_asic));
    m_inj_asic.inj_dma_pd_base_lsb_reg_0 = reg_addresses[(int)INJ_DMA_REG_ID_PD_BASE_LOW];
    m_inj_asic.inj_dma_pd_base_msb_reg_0 = reg_addresses[(int)INJ_DMA_REG_ID_PD_BASE_HIGH];
    m_inj_asic.inj_dma_wr_pd_ptr_reg_0 = reg_addresses[(int)INJ_DMA_REG_ID_PD_WR_PTR];
    m_inj_asic.inj_dma_rd_pd_ptr_reg_0 = reg_addresses[(int)INJ_DMA_REG_ID_PD_RD_PTR];
    m_inj_asic.inj_dma_pd_length_reg_0 = reg_addresses[(int)INJ_DMA_REG_ID_PD_LENGTH];
    m_inj_asic.inj_dma_cfg_reg_0 = reg_addresses[(int)INJ_DMA_REG_ID_CFG];

    m_sbif_block_id = device_info.packet_dma_info.sbif_block_id;

    for (int reg = 0; reg < INJ_DMA_REG_ID_MAX; reg++) {
        for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
            m_dma_registers_cache[reg][ctx_id] = 0;
            m_initialized[reg][ctx_id] = false;
            uint32_t ctx_id_offset = static_cast<uint32_t>(ctx_id * sizeof(uint32_t));
            switch (reg) {
            case INJ_DMA_REG_ID_PD_BASE_LOW:
                m_dma_registers_map.insert(std::make_pair(m_inj_asic.inj_dma_pd_base_lsb_reg_0 + ctx_id_offset,
                                                          std::make_pair(INJ_DMA_REG_ID_PD_BASE_LOW, ctx_id)));
                break;
            case INJ_DMA_REG_ID_PD_BASE_HIGH:
                m_dma_registers_map.insert(std::make_pair(m_inj_asic.inj_dma_pd_base_msb_reg_0 + ctx_id_offset,
                                                          std::make_pair(INJ_DMA_REG_ID_PD_BASE_HIGH, ctx_id)));
                break;
            case INJ_DMA_REG_ID_PD_LENGTH:
                m_dma_registers_map.insert(std::make_pair(m_inj_asic.inj_dma_pd_length_reg_0 + ctx_id_offset,
                                                          std::make_pair(INJ_DMA_REG_ID_PD_LENGTH, ctx_id)));
                break;
            case INJ_DMA_REG_ID_PD_RD_PTR:
                m_dma_registers_map.insert(std::make_pair(m_inj_asic.inj_dma_rd_pd_ptr_reg_0 + ctx_id_offset,
                                                          std::make_pair(INJ_DMA_REG_ID_PD_RD_PTR, ctx_id)));
                break;
            case INJ_DMA_REG_ID_PD_WR_PTR:
                m_dma_registers_map.insert(std::make_pair(m_inj_asic.inj_dma_wr_pd_ptr_reg_0 + ctx_id_offset,
                                                          std::make_pair(INJ_DMA_REG_ID_PD_WR_PTR, ctx_id)));
                break;
            case INJ_DMA_REG_ID_CFG:
                m_dma_registers_map.insert(
                    std::make_pair(m_inj_asic.inj_dma_cfg_reg_0 + ctx_id_offset, std::make_pair(INJ_DMA_REG_ID_CFG, ctx_id)));
                break;
            }
        }
    }
    for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
        m_dma_pd_user_buffer[ctx_id] = nullptr;
    }

    m_logger = logger;
    m_socket_client = client;
}

void
dsim::packet_dma_inject::reset_state(void)
{
    for (int reg = 0; reg < INJ_DMA_REG_ID_MAX; reg++) {
        for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
            m_dma_registers_cache[reg][ctx_id] = 0;
        }
    }
    for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
        m_dma_pd_user_buffer[ctx_id] = nullptr;
    }
}

const std::pair<packet_dma_inject_reg_id_t, unsigned>&
dsim::packet_dma_inject::register_select(uint32_t reg_address)
{
    auto query = m_dma_registers_map.find(reg_address);
    if (query == m_dma_registers_map.end()) {
        return INJ_DMA_REG_UNKNOWN;
    }

    return query->second;
}

dsim_status_e
packet_dma_inject::write_register(client_id_t client_id,
                                  client_seqno_t& seqno,
                                  uint32_t block_id,
                                  uint32_t reg_address,
                                  uint16_t reg_width,
                                  size_t count,
                                  const void* in_val,
                                  void* command_buffer)
{
    if (block_id != m_sbif_block_id) {
        return DSIM_STATUS_ENOTFOUND;
    }

    auto query = register_select(reg_address);
    if (query == std::make_pair(INJ_DMA_REG_ID_MAX, (unsigned)0)) {
        return DSIM_STATUS_ENOTFOUND;
    }

    if (count != 1) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Inject: write_register(): count > 1 unsupported!");
        return DSIM_STATUS_ENOTIMPLEMENTED;
    }

    packet_dma_inject_reg_id_t reg = query.first;
    unsigned ctx_id = query.second;
    uint32_t value = *(reinterpret_cast<const uint32_t*>(in_val));

    if (reg == INJ_DMA_REG_ID_CFG) {
        uint32_t mask = INJ_DMA_CFG_REG_MASK_REMOTE | INJ_DMA_CFG_REG_MASK_GO | INJ_DMA_CFG_REG_MASK_WB;
        if (~mask & value) {
            WLOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Inject: write_register(CFG): Disregarding unsupported bits!");
        }
        value = value & mask;
    }

    if (reg == INJ_DMA_REG_ID_PD_RD_PTR) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Inject write_register(PD_RD_PTR): Read-only register!");
        return DSIM_STATUS_EINVAL;
    }

    m_dma_registers_cache[reg][ctx_id] = value;

    if (!m_initialized[reg][ctx_id]) {
        m_initialized[reg][ctx_id] = true;
    }

    if ((reg == INJ_DMA_REG_ID_PD_BASE_LOW || reg == INJ_DMA_REG_ID_PD_BASE_HIGH) && m_initialized[INJ_DMA_REG_ID_PD_BASE_LOW]
        && m_initialized[INJ_DMA_REG_ID_PD_BASE_HIGH]) {
        if (m_device == DEVICE_TYPE_GIBRALTAR) {
            m_dma_pd_user_buffer[ctx_id] = (uint8_t*)((uint64_t)m_dma_registers_cache[INJ_DMA_REG_ID_PD_BASE_HIGH][ctx_id] << 32
                                                      | (uint64_t)m_dma_registers_cache[INJ_DMA_REG_ID_PD_BASE_LOW][ctx_id] << 12);
        } else {
            m_dma_pd_user_buffer[ctx_id] = (uint8_t*)((uint64_t)m_dma_registers_cache[INJ_DMA_REG_ID_PD_BASE_HIGH][ctx_id] << 32
                                                      | (uint64_t)m_dma_registers_cache[INJ_DMA_REG_ID_PD_BASE_LOW][ctx_id]);
        }
    }

    if (reg == INJ_DMA_REG_ID_PD_WR_PTR) {
        if (m_dma_pd_user_buffer[ctx_id] != nullptr && active(ctx_id)) {
            int processed_packets = 0;
            while (!is_empty(ctx_id)) {
                dma_packet_descriptor_t* desc = reinterpret_cast<dma_packet_descriptor_t*>(
                    m_dma_pd_user_buffer[ctx_id]
                    + (m_dma_registers_cache[INJ_DMA_REG_ID_PD_RD_PTR][ctx_id] & ~DESC_BUFFER_WRAP_BIT) * m_pd_desc_multiplier);
                const uint8_t* packet_data = reinterpret_cast<uint8_t*>(desc->phys_addr);
                uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + sizeof(inject_packet_socket_command);
                assert(buffer_size <= SOCKET_COMMAND_BUFFER_LEN);
                socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(command_buffer);
                inject_packet_socket_command* ipsc = reinterpret_cast<inject_packet_socket_command*>(cmd_hdr->payload);

                memset(cmd_hdr, 0, buffer_size);
                cmd_hdr->cmd = socket_command_type_e::INJECT_PACKET;
                cmd_hdr->client_id = client_id;
                cmd_hdr->seqno = seqno++;
                cmd_hdr->flags.expecting_reply = false;
                ipsc->packet_size = static_cast<decltype(ipsc->packet_size)>(desc->size);
                ipsc->ctx_id = ctx_id;

                if (!m_socket_client->send(buffer_size, cmd_hdr, send_prefix)) {
                    ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client command send failed");
                    return DSIM_STATUS_EUNKNOWN;
                }
                if (!m_socket_client->send(static_cast<size_t>(ALIGN(desc->size, BYTES_IN_DQWORD)), packet_data, send_prefix)) {
                    ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client command send failed");
                    return DSIM_STATUS_EUNKNOWN;
                }

                dma_pd_buffer_rd_ptr_inc(ctx_id, m_pd_desc_increment /* increment */);

                processed_packets++;
            }

            if (processed_packets) {
                // update DSIM PD RD register
                // NOTE: We are updating PD RD pointer register in DSIM before
                //       PD WR register is updated on DSIM side.
                //       This is OK, because we have a cached value updated
                //       already if the user tries to read it.
                uint16_t entry_count = (uint16_t)count;
                uint32_t payload_size = static_cast<uint32_t>(reg_width * count);
                uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + sizeof(write_register_socket_command) + payload_size;
                assert(buffer_size <= SOCKET_COMMAND_BUFFER_LEN);
                socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(command_buffer);

                memset(cmd_hdr, 0, buffer_size);

                write_register_socket_command* wrsc = reinterpret_cast<write_register_socket_command*>(cmd_hdr->payload);
                cmd_hdr->cmd = socket_command_type_e::WRITE_REGISTER;
                cmd_hdr->client_id = client_id;
                cmd_hdr->seqno = seqno;
                // side effect client seqno
                seqno++;
                cmd_hdr->flags.expecting_reply = false;
                wrsc->block_id = m_sbif_block_id;
                wrsc->reg_address = (uint32_t)m_inj_asic.inj_dma_rd_pd_ptr_reg_0 + ctx_id * sizeof(uint32_t);
                wrsc->reg_addr_width = sizeof(uint32_t);
                wrsc->entry_count = entry_count;
                memcpy(wrsc->payload, (void*)&m_dma_registers_cache[INJ_DMA_REG_ID_PD_RD_PTR][ctx_id], sizeof(uint32_t));

                if (m_socket_client->send(buffer_size, cmd_hdr, send_prefix) == false) {
                    ELOG_INSTANCE(m_logger, NSIM_DEBUG, "DSIM client command send failed");
                    return DSIM_STATUS_EUNKNOWN;
                }
            }
        }
    }

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim::packet_dma_inject::write_register_by_name(client_id_t client_id,
                                                client_seqno_t& seqno,
                                                const std::string& reg,
                                                size_t reg_index,
                                                uint16_t reg_width,
                                                size_t count,
                                                const void* in_val,
                                                void* command_buffer)
{
    auto found = m_reg_name_to_addr.find(reg);
    if (found == m_reg_name_to_addr.end()) {
        return DSIM_STATUS_ENOTFOUND;
    }

    return write_register(client_id,
                          seqno,
                          m_sbif_block_id,
                          found->second + static_cast<uint32_t>(reg_index),
                          reg_width,
                          count,
                          in_val,
                          command_buffer);
}

dsim_status_e
dsim::packet_dma_inject::read_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, void* out_val)
{
    if (block_id != m_sbif_block_id) {
        return DSIM_STATUS_ENOTFOUND;
    }

    auto query = register_select(reg_address);
    if (query == std::make_pair(INJ_DMA_REG_ID_MAX, (unsigned)0)) {
        return DSIM_STATUS_ENOTFOUND;
    }

    if (count != 1) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Inject: write_register(): count > 1 unsupported!");
        return DSIM_STATUS_ENOTIMPLEMENTED;
    }

    packet_dma_inject_reg_id_t reg = query.first;
    unsigned ctx_id = query.second;

    uint32_t* out_ptr = reinterpret_cast<uint32_t*>(out_val);
    *out_ptr = m_dma_registers_cache[reg][ctx_id];

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim::packet_dma_inject::read_register_by_name(const std::string& reg,
                                               size_t reg_index,
                                               uint16_t reg_width,
                                               size_t count,
                                               void* out_val)
{
    auto found = m_reg_name_to_addr.find(reg);
    if (found == m_reg_name_to_addr.end()) {
        return DSIM_STATUS_ENOTFOUND;
    }

    return read_register(m_sbif_block_id, found->second + static_cast<uint32_t>(reg_index), reg_width, count, out_val);
}

void
packet_dma_inject::dma_pd_buffer_rd_ptr_inc(unsigned ctx_id, unsigned increment)
{
    uint32_t newptr = (m_dma_registers_cache[INJ_DMA_REG_ID_PD_RD_PTR][ctx_id] & ~DESC_BUFFER_WRAP_BIT) + increment;
    uint32_t ptr_wrap_bit = m_dma_registers_cache[INJ_DMA_REG_ID_PD_RD_PTR][ctx_id] & DESC_BUFFER_WRAP_BIT;
    uint32_t pd_buffer_length = m_dma_registers_cache[INJ_DMA_REG_ID_PD_LENGTH][ctx_id];

    if (newptr >= pd_buffer_length) {
        ptr_wrap_bit ^= DESC_BUFFER_WRAP_BIT;
        newptr -= pd_buffer_length;
    }

    m_dma_registers_cache[INJ_DMA_REG_ID_PD_RD_PTR][ctx_id] = ptr_wrap_bit | newptr;
}

bool
dsim::packet_dma_inject::active(unsigned ctx_id)
{
    return !!(m_dma_registers_cache[INJ_DMA_REG_ID_CFG][ctx_id] & INJ_DMA_CFG_REG_MASK_GO);
}

bool
dsim::packet_dma_inject::is_empty(unsigned ctx_id)
{
    return m_dma_registers_cache[INJ_DMA_REG_ID_PD_RD_PTR][ctx_id] == m_dma_registers_cache[INJ_DMA_REG_ID_PD_WR_PTR][ctx_id];
}
