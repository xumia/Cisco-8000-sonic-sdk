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
#include "device_simulator/packet_dma_extract.h"
#include "utils/logger/logger.h"
#include "utils/serialize.h"

using namespace npsuite;
using namespace dsim;

const std::pair<packet_dma_extract_reg_id_t, unsigned>& dsim::packet_dma_extract::EXT_DMA_REG_UNKNOWN
    = std::make_pair(EXT_DMA_REG_ID_MAX, 0);

dsim::packet_dma_extract::packet_dma_extract()
{
    m_logger = nullptr;
    m_socket_client = nullptr;
}

static const std::string receive_prefix = "DSIM client packet dma extract rx: ";
static const std::string send_prefix = "DSIM client packet dma extract tx: ";

void
dsim::packet_dma_extract::initialize(npsuite::Logger* logger,
                                     socket_client* client,
                                     const device_info& device_info,
                                     std::istringstream& stream_reg_addresses,
                                     std::istringstream& stream_reg_names)
{
    if (strcmp(device_info.device_name, "gibraltar") == 0) {
        m_device = DEVICE_TYPE_GIBRALTAR;
        m_pd_desc_increment = 1;
        m_pd_desc_multiplier = DESC_BUFFER_ELEMENT_SIZE_BYTES;
        m_use_ext_data_buffer = false;
        m_ext_cfg_specific = gibraltar_ext_cfg_specific;
    } else {
        m_device = DEVICE_TYPE_PACIFIC;
        m_pd_desc_increment = DESC_BUFFER_ELEMENT_SIZE_BYTES;
        m_pd_desc_multiplier = 1;
        m_use_ext_data_buffer = true;
        m_ext_cfg_specific = pacific_ext_cfg_specific;
    }

    //
    // Deserialize packet DMA data
    //
    std::array<uint32_t, dsim::EXT_DMA_REG_ID_MAX> reg_addresses{{}};
    for (auto& i : reg_addresses) { // VC did not like {{}} initializer
        i = 0;
    }
    stream_reg_addresses >> encapsulate_value(reg_addresses);

    std::array<std::string, dsim::EXT_DMA_REG_ID_MAX> reg_names{{}};
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

    memset(&m_ext_asic, 0, sizeof(m_ext_asic));
    m_ext_asic.ext_dma_pd_base_lsb_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_PD_BASE_LOW];
    m_ext_asic.ext_dma_pd_base_msb_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_PD_BASE_HIGH];
    m_ext_asic.ext_dma_wr_pd_ptr_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_PD_WR_PTR];
    m_ext_asic.ext_dma_rd_pd_ptr_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_PD_RD_PTR];
    m_ext_asic.ext_dma_pd_length_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_PD_LENGTH];
    m_ext_asic.ext_dma_data_base_lsb_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_DATA_BASE_LOW];
    m_ext_asic.ext_dma_data_base_msb_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_DATA_BASE_HIGH];
    m_ext_asic.ext_dma_wr_data_ptr_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_DATA_WR_PTR];
    m_ext_asic.ext_dma_rd_data_ptr_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_DATA_RD_PTR];
    m_ext_asic.ext_dma_data_length_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_DATA_LENGTH];
    m_ext_asic.ext_dma_cfg_reg_0 = reg_addresses[(int)EXT_DMA_REG_ID_CFG];

    m_sbif_block_id = device_info.packet_dma_info.sbif_block_id;

    for (int reg = 0; reg < EXT_DMA_REG_ID_MAX; reg++) {
        for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
            m_dma_registers_cache[reg][ctx_id] = 0;
            m_initialized[reg][ctx_id] = false;
            uint32_t ctx_id_offset = static_cast<uint32_t>(ctx_id * sizeof(uint32_t));
            switch (reg) {
            case EXT_DMA_REG_ID_PD_BASE_LOW:
                m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_pd_base_lsb_reg_0 + ctx_id_offset,
                                                          std::make_pair(EXT_DMA_REG_ID_PD_BASE_LOW, ctx_id)));
                break;
            case EXT_DMA_REG_ID_PD_BASE_HIGH:
                m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_pd_base_msb_reg_0 + ctx_id_offset,
                                                          std::make_pair(EXT_DMA_REG_ID_PD_BASE_HIGH, ctx_id)));
                break;
            case EXT_DMA_REG_ID_PD_LENGTH:
                m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_pd_length_reg_0 + ctx_id_offset,
                                                          std::make_pair(EXT_DMA_REG_ID_PD_LENGTH, ctx_id)));
                break;
            case EXT_DMA_REG_ID_PD_RD_PTR:
                m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_rd_pd_ptr_reg_0 + ctx_id_offset,
                                                          std::make_pair(EXT_DMA_REG_ID_PD_RD_PTR, ctx_id)));
                break;
            case EXT_DMA_REG_ID_PD_WR_PTR:
                m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_wr_pd_ptr_reg_0 + ctx_id_offset,
                                                          std::make_pair(EXT_DMA_REG_ID_PD_WR_PTR, ctx_id)));
                break;
            case EXT_DMA_REG_ID_DATA_BASE_LOW:
                if (m_use_ext_data_buffer) {
                    m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_data_base_lsb_reg_0 + ctx_id_offset,
                                                              std::make_pair(EXT_DMA_REG_ID_DATA_BASE_LOW, ctx_id)));
                }
                break;
            case EXT_DMA_REG_ID_DATA_BASE_HIGH:
                if (m_use_ext_data_buffer) {
                    m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_data_base_msb_reg_0 + ctx_id_offset,
                                                              std::make_pair(EXT_DMA_REG_ID_DATA_BASE_HIGH, ctx_id)));
                }
                break;
            case EXT_DMA_REG_ID_DATA_LENGTH:
                if (m_use_ext_data_buffer) {
                    m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_data_length_reg_0 + ctx_id_offset,
                                                              std::make_pair(EXT_DMA_REG_ID_DATA_LENGTH, ctx_id)));
                }
                break;
            case EXT_DMA_REG_ID_DATA_RD_PTR:
                if (m_use_ext_data_buffer) {
                    m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_rd_data_ptr_reg_0 + ctx_id_offset,
                                                              std::make_pair(EXT_DMA_REG_ID_DATA_RD_PTR, ctx_id)));
                }
                break;
            case EXT_DMA_REG_ID_DATA_WR_PTR:
                if (m_use_ext_data_buffer) {
                    m_dma_registers_map.insert(std::make_pair(m_ext_asic.ext_dma_wr_data_ptr_reg_0 + ctx_id_offset,
                                                              std::make_pair(EXT_DMA_REG_ID_DATA_WR_PTR, ctx_id)));
                }
                break;
            case EXT_DMA_REG_ID_CFG:
                m_dma_registers_map.insert(
                    std::make_pair(m_ext_asic.ext_dma_cfg_reg_0 + ctx_id_offset, std::make_pair(EXT_DMA_REG_ID_CFG, ctx_id)));
                break;
            }
        }
    }
    for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
        m_dma_data_user_buffer[ctx_id] = nullptr;
        m_dma_pd_user_buffer[ctx_id] = nullptr;
    }
    m_logger = logger;
    m_socket_client = client;
}

void
dsim::packet_dma_extract::reset_state(void)
{
    for (int reg = 0; reg < EXT_DMA_REG_ID_MAX; reg++) {
        for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
            m_dma_registers_cache[reg][ctx_id] = 0;
        }
    }
    for (unsigned ctx_id = 0; ctx_id < 12; ctx_id++) {
        m_dma_data_user_buffer[ctx_id] = nullptr;
        m_dma_pd_user_buffer[ctx_id] = nullptr;
    }
}

const std::pair<packet_dma_extract_reg_id_t, unsigned>&
dsim::packet_dma_extract::register_select(uint32_t reg_address)
{
    auto query = m_dma_registers_map.find(reg_address);
    if (query == m_dma_registers_map.end()) {
        return EXT_DMA_REG_UNKNOWN;
    }

    return query->second;
}

dsim_status_e
packet_dma_extract::write_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, const void* in_val)
{
    if (block_id != m_sbif_block_id) {
        return DSIM_STATUS_ENOTFOUND;
    }

    auto query = register_select(reg_address);
    if (query == std::make_pair(EXT_DMA_REG_ID_MAX, (unsigned)0)) {
        return DSIM_STATUS_ENOTFOUND;
    }

    if (count != 1) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Extract: write_register(): count > 1 unsupported!");
        return DSIM_STATUS_ENOTIMPLEMENTED;
    }

    packet_dma_extract_reg_id_t reg = query.first;
    unsigned ctx_id = query.second;
    uint32_t value = *(reinterpret_cast<const uint32_t*>(in_val));

    if (reg == EXT_DMA_REG_ID_CFG) {
        uint32_t mask = m_ext_cfg_specific.ext_dma_cfg_reg_mask_go | m_ext_cfg_specific.ext_dma_cfg_reg_mask_flow_ctrl
                        | m_ext_cfg_specific.ext_dma_cfg_reg_mask_flow_ctrl_pd_thr
                        | m_ext_cfg_specific.ext_dma_cfg_reg_mask_flow_ctrl_data_thr
                        | m_ext_cfg_specific.ext_dma_cfg_reg_mask_remote | m_ext_cfg_specific.ext_dma_cfg_reg_mask_wb;

        if (~mask & value) {
            WLOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Extract: write_register(CFG): Disregarding unsupported bits!");
        }
        value = value & mask;
    }

    if (reg == EXT_DMA_REG_ID_PD_WR_PTR) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Extract write_register(PD_WR_PTR): Read-only register!");
        return DSIM_STATUS_EINVAL;
    }

    if (reg == EXT_DMA_REG_ID_DATA_WR_PTR) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Extract write_register(DATA_WR_PTR): Read-only register!");
        return DSIM_STATUS_EINVAL;
    }

    m_dma_registers_cache[reg][ctx_id] = value;

    if (!m_initialized[reg][ctx_id]) {
        m_initialized[reg][ctx_id] = true;
    }

    if ((reg == EXT_DMA_REG_ID_PD_BASE_LOW || reg == EXT_DMA_REG_ID_PD_BASE_HIGH) && m_initialized[EXT_DMA_REG_ID_PD_BASE_LOW]
        && m_initialized[EXT_DMA_REG_ID_PD_BASE_HIGH]) {
        if (m_device == DEVICE_TYPE_GIBRALTAR) {
            m_dma_pd_user_buffer[ctx_id] = (uint8_t*)((uint64_t)m_dma_registers_cache[EXT_DMA_REG_ID_PD_BASE_HIGH][ctx_id] << 32
                                                      | (uint64_t)m_dma_registers_cache[EXT_DMA_REG_ID_PD_BASE_LOW][ctx_id] << 12);
        } else {
            m_dma_pd_user_buffer[ctx_id] = (uint8_t*)((uint64_t)m_dma_registers_cache[EXT_DMA_REG_ID_PD_BASE_HIGH][ctx_id] << 32
                                                      | (uint64_t)m_dma_registers_cache[EXT_DMA_REG_ID_PD_BASE_LOW][ctx_id]);
        }
    }

    if ((reg == EXT_DMA_REG_ID_DATA_BASE_LOW || reg == EXT_DMA_REG_ID_DATA_BASE_HIGH) && m_initialized[EXT_DMA_REG_ID_DATA_BASE_LOW]
        && m_initialized[EXT_DMA_REG_ID_DATA_BASE_HIGH]) {
        m_dma_data_user_buffer[ctx_id] = (uint8_t*)((uint64_t)m_dma_registers_cache[EXT_DMA_REG_ID_DATA_BASE_HIGH][ctx_id] << 32
                                                    | (uint64_t)m_dma_registers_cache[EXT_DMA_REG_ID_DATA_BASE_LOW][ctx_id]);
    }

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim::packet_dma_extract::write_register_by_name(const std::string& reg,
                                                 size_t reg_index,
                                                 uint16_t reg_width,
                                                 size_t count,
                                                 const void* in_val)
{
    auto found = m_reg_name_to_addr.find(reg);
    if (found == m_reg_name_to_addr.end()) {
        return DSIM_STATUS_ENOTFOUND;
    }

    return write_register(m_sbif_block_id, found->second + static_cast<uint32_t>(reg_index), reg_width, count, in_val);
}

dsim_status_e
dsim::packet_dma_extract::read_register(client_id_t client_id,
                                        client_seqno_t& seqno,
                                        uint32_t block_id,
                                        uint32_t reg_address,
                                        uint16_t reg_width,
                                        size_t count,
                                        void* out_val,
                                        void* command_buffer)
{
    if (block_id != m_sbif_block_id) {
        return DSIM_STATUS_ENOTFOUND;
    }

    auto query = register_select(reg_address);
    if (query == std::make_pair(EXT_DMA_REG_ID_MAX, (unsigned)0)) {
        return DSIM_STATUS_ENOTFOUND;
    }

    if (count != 1) {
        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA Extract: read_register(): count != 1 unsupported!");
        return DSIM_STATUS_ENOTIMPLEMENTED;
    }

    packet_dma_extract_reg_id_t reg = query.first;
    unsigned ctx_id = query.second;

    if (reg == EXT_DMA_REG_ID_PD_WR_PTR) {
        if (m_dma_pd_user_buffer[ctx_id] != nullptr && (!m_use_ext_data_buffer || m_dma_data_user_buffer[ctx_id] != nullptr)
            && active(ctx_id)) {
            uint16_t packets_avail = static_cast<uint16_t>(get_pd_buffer_available_space(ctx_id)) / m_pd_desc_increment;
            size_t bytes_avail;

            //
            // GB does not have data buffer space; only PD buffer space.
            //
            if (m_use_ext_data_buffer) {
                bytes_avail = get_data_buffer_available_space(ctx_id);
            } else {
                bytes_avail = (std::numeric_limits<size_t>::max)(); // ()s avoids macro expansion of max
            }

            if (!packets_avail || !bytes_avail) {
                uint32_t* out_ptr = reinterpret_cast<uint32_t*>(out_val);
                *out_ptr = m_dma_registers_cache[reg][ctx_id];
                WLOG_INSTANCE(m_logger,
                              NSIM_DEBUG,
                              "Packet DMA Extract: out of space; try again. Packet space = " + std::to_string(packets_avail)
                                  + " byte space = "
                                  + std::to_string(bytes_avail));
                return DSIM_STATUS_SUCCESS;
            }
            uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + sizeof(extract_packets_socket_command);
            assert(buffer_size <= SOCKET_COMMAND_BUFFER_LEN);
            socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(command_buffer);

            memset(cmd_hdr, 0, buffer_size);

            extract_packets_socket_command* epsc = reinterpret_cast<extract_packets_socket_command*>(cmd_hdr->payload);
            cmd_hdr->cmd = socket_command_type_e::EXTRACT_PACKETS;
            cmd_hdr->client_id = client_id;
            cmd_hdr->seqno = seqno++;
            cmd_hdr->flags.expecting_reply = true;
            epsc->ctx_id = ctx_id;
            epsc->bytes_available = static_cast<uint32_t>(bytes_avail);
            epsc->packets_available = packets_avail;

            if (!m_socket_client->send(buffer_size, cmd_hdr, send_prefix)) {
                ELOG_INSTANCE(m_logger, NSIM_DEBUG, "client command send failed");
                return DSIM_STATUS_EUNKNOWN;
            }

            int processed_packets = 0;
            while (true) {
                size_t packet_size = 0;
                size_t aligned_packet_size = 0;
                size_t received_bytes = m_socket_client->receive(&packet_size, sizeof(size_t), receive_prefix);
                if (packet_size == 0) {
                    break;
                }
                //
                // As we provided the available space in EXTRACT_PACKETS, this should now never happen.
                //
                aligned_packet_size = ALIGN(packet_size, BYTES_IN_DQWORD);
                if (m_use_ext_data_buffer && (bytes_avail < aligned_packet_size)) {
                    FLOG_INSTANCE(m_logger, NSIM_DEBUG, "Packet DMA extract: No more available space!");
                    assert(false && "Packet DMA extract: No more available space!");
                }
                dma_packet_descriptor_t* desc = reinterpret_cast<dma_packet_descriptor_t*>(
                    m_dma_pd_user_buffer[ctx_id]
                    + (m_dma_registers_cache[EXT_DMA_REG_ID_PD_WR_PTR][ctx_id] & ~DESC_BUFFER_WRAP_BIT) * m_pd_desc_multiplier);
                uint8_t* packet_data;
                if (m_use_ext_data_buffer) {
                    uint32_t first_offset = 0;
                    size_t first_size = 0;
                    size_t second_size = 0;
                    size_t second_received_bytes = 0;

                    dma_data_buffer_get_wr_offsets(ctx_id, aligned_packet_size, first_offset, first_size, second_size);

                    // packet_data must point to the beginning of the destination for the first read
                    // do not set it again for this packet, even if we do a second read
                    packet_data = m_dma_data_user_buffer[ctx_id] + first_offset;

                    // Get the size of the payload (again, this time, it's the aligned size).
                    size_t len_in_bytes = 0;
                    received_bytes = m_socket_client->receive_raw_data(&len_in_bytes, sizeof(size_t), receive_prefix);
                    if (received_bytes == 0) {
                        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "Failed to read packet len from socket");
                        return DSIM_STATUS_ESIZE;
                    }

                    if (len_in_bytes != aligned_packet_size) {
                        ELOG_INSTANCE(m_logger,
                                      NSIM_DEBUG,
                                      string_format("Received unexpected packet size.  Expected %lu but received %lu",
                                                    aligned_packet_size,
                                                    len_in_bytes));
                        if (len_in_bytes > MAX_DATA_BUFFER_ELEMENT_SIZE_BYTES) {
                            ELOG_INSTANCE(m_logger,
                                          NSIM_DEBUG,
                                          string_format("Unexpected packet size (%lu) is greater than maximum (%u)",
                                                        len_in_bytes,
                                                        MAX_DATA_BUFFER_ELEMENT_SIZE_BYTES));
                            return DSIM_STATUS_ESIZE;
                        } else {
                            uint8_t packet_data[MAX_DATA_BUFFER_ELEMENT_SIZE_BYTES];
                            received_bytes = m_socket_client->receive_raw_data(&packet_data[0], len_in_bytes, receive_prefix);
                            if (received_bytes != len_in_bytes) {
                                ELOG_INSTANCE(m_logger,
                                              NSIM_DEBUG,
                                              string_format("Received bytes different than expected, recv=%lu, packet-size=%lu "
                                                            "when flushing the packet on unexpected length",
                                                            received_bytes,
                                                            len_in_bytes));
                                return DSIM_STATUS_EUNKNOWN;
                            }
                            continue;
                        }
                    }

                    // Get the first batch of packet data
                    ILOG_INSTANCE(m_logger, NSIM_DEBUG, string_format("packet_data pointer on first receive: 0x%p", packet_data));
                    received_bytes = m_socket_client->receive_raw_data(&packet_data[0], first_size, receive_prefix);
                    if (received_bytes != first_size) {
                        ELOG_INSTANCE(
                            m_logger,
                            NSIM_DEBUG,
                            string_format("Received bytes different than expected, recv=%lu, second_recv=%lu, aligned_pkt_sz=%lu",
                                          received_bytes,
                                          second_received_bytes,
                                          aligned_packet_size));
                        return DSIM_STATUS_ESIZE;
                    }

                    if (second_size > 0) {
                        // Get the second batch of packet data if we are wrapping the circular buffer
                        //
                        // Offset on second read will always be 0, as we point to that memory when wrapping the circular buffer
                        // do not change packet_data pointer from first call to receive_raw_data
                        uint8_t* packet_data_2 = m_dma_data_user_buffer[ctx_id];
                        ILOG_INSTANCE(
                            m_logger, NSIM_DEBUG, string_format("packet_data pointer on second receive: 0x%p", packet_data_2));
                        second_received_bytes = m_socket_client->receive_raw_data(&packet_data_2[0], second_size, receive_prefix);
                        if (second_received_bytes != second_size) {
                            ELOG_INSTANCE(
                                m_logger,
                                NSIM_DEBUG,
                                string_format(
                                    "Second received bytes different than expected, recv=%lu, aligned_pkt_sz=%lu when eating the "
                                    "packet on unexpected length",
                                    received_bytes,
                                    aligned_packet_size));
                            return DSIM_STATUS_EUNKNOWN;
                        }
                    }
                } else {
                    packet_data = reinterpret_cast<uint8_t*>(desc->phys_addr);
                    received_bytes = m_socket_client->receive(&packet_data[0], aligned_packet_size, receive_prefix);
                    if (received_bytes != aligned_packet_size) {
                        ELOG_INSTANCE(
                            m_logger,
                            NSIM_DEBUG,
                            string_format(
                                "Received bytes different than expected (%lu/%lu) during packet DMA without ext_data_buffer",
                                packet_size,
                                received_bytes));
                        return DSIM_STATUS_ESIZE;
                    }
                }

                // must point to head of first read (if there are multiple reads for this packet)
                desc->phys_addr = reinterpret_cast<uint64_t>(packet_data);
                desc->size_err = 0;
                desc->size = packet_size;
                dma_pd_buffer_wr_ptr_inc(ctx_id, m_pd_desc_increment /* increment */);
                if (m_use_ext_data_buffer) {
                    dma_data_buffer_wr_ptr_inc(ctx_id, ALIGN((uint32_t)(desc->size), BUFFER_PTR_ALIGNMENT));
                }

                processed_packets++;
            }

            if (processed_packets) {
                if (m_use_ext_data_buffer) {
                    // update DSIM DATA WR register
                    uint16_t entry_count = (uint16_t)count;
                    uint32_t payload_size = sizeof(uint32_t) * static_cast<uint32_t>(count);
                    uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + WRITE_REGISTER_SOCKET_COMMAND_SIZE + payload_size;
                    assert(buffer_size <= SOCKET_COMMAND_BUFFER_LEN);
                    socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(command_buffer);

                    memset(cmd_hdr, 0, buffer_size);

                    write_register_socket_command* wrsc = reinterpret_cast<write_register_socket_command*>(cmd_hdr->payload);
                    cmd_hdr->cmd = socket_command_type_e::WRITE_REGISTER;
                    cmd_hdr->client_id = client_id;
                    cmd_hdr->seqno = seqno++;
                    cmd_hdr->flags.expecting_reply = false;
                    wrsc->block_id = m_sbif_block_id;
                    wrsc->reg_address = (uint32_t)m_ext_asic.ext_dma_wr_data_ptr_reg_0 + ctx_id * sizeof(uint32_t);
                    wrsc->reg_addr_width = sizeof(uint32_t);
                    wrsc->entry_count = entry_count;
                    memcpy(wrsc->payload, (void*)&m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id], payload_size);

                    if (!m_socket_client->send(buffer_size, cmd_hdr, send_prefix)) {
                        ELOG_INSTANCE(m_logger, NSIM_DEBUG, "client command send failed");
                        return DSIM_STATUS_EUNKNOWN;
                    }
                }

                // update DSIM PD WR register
                uint16_t entry_count = (uint16_t)count;
                uint32_t payload_size = sizeof(uint32_t) * static_cast<uint32_t>(count);
                uint32_t buffer_size = SOCKET_COMMAND_HEADER_SIZE + WRITE_REGISTER_SOCKET_COMMAND_SIZE + payload_size;
                assert(buffer_size <= SOCKET_COMMAND_BUFFER_LEN);
                socket_command_header* cmd_hdr = reinterpret_cast<socket_command_header*>(command_buffer);

                memset(cmd_hdr, 0, buffer_size);

                write_register_socket_command* wrsc = reinterpret_cast<write_register_socket_command*>(cmd_hdr->payload);
                cmd_hdr->cmd = socket_command_type_e::WRITE_REGISTER;
                cmd_hdr->client_id = client_id;
                cmd_hdr->seqno = seqno++;
                cmd_hdr->flags.expecting_reply = false;
                wrsc->block_id = m_sbif_block_id;
                wrsc->reg_address = (uint32_t)m_ext_asic.ext_dma_wr_pd_ptr_reg_0 + ctx_id * sizeof(uint32_t);
                wrsc->reg_addr_width = sizeof(uint32_t);
                wrsc->entry_count = entry_count;
                memcpy(wrsc->payload, (void*)&m_dma_registers_cache[EXT_DMA_REG_ID_PD_WR_PTR][ctx_id], payload_size);

                if (!m_socket_client->send(buffer_size, cmd_hdr, send_prefix)) {
                    ELOG_INSTANCE(m_logger, NSIM_DEBUG, "client command send failed");
                    return DSIM_STATUS_EUNKNOWN;
                }
            }
        }
    }

    uint32_t* out_ptr = reinterpret_cast<uint32_t*>(out_val);
    *out_ptr = m_dma_registers_cache[reg][ctx_id];

    return DSIM_STATUS_SUCCESS;
}

dsim_status_e
dsim::packet_dma_extract::read_register_by_name(client_id_t client_id,
                                                client_seqno_t& seqno,
                                                const std::string& reg,
                                                size_t reg_index,
                                                uint16_t reg_width,
                                                size_t count,
                                                void* out_val,
                                                void* command_buffer)
{
    auto found = m_reg_name_to_addr.find(reg);
    if (found == m_reg_name_to_addr.end()) {
        return DSIM_STATUS_ENOTFOUND;
    }

    return read_register(client_id,
                         seqno,
                         m_sbif_block_id,
                         found->second + static_cast<uint32_t>(reg_index),
                         reg_width,
                         count,
                         out_val,
                         command_buffer);
}

void
packet_dma_extract::dma_pd_buffer_wr_ptr_inc(unsigned ctx_id, unsigned increment)
{
    uint32_t newptr = (m_dma_registers_cache[EXT_DMA_REG_ID_PD_WR_PTR][ctx_id] & ~DESC_BUFFER_WRAP_BIT) + increment;
    uint32_t ptr_wrap_bit = m_dma_registers_cache[EXT_DMA_REG_ID_PD_WR_PTR][ctx_id] & DESC_BUFFER_WRAP_BIT;
    uint32_t pd_buffer_length = m_dma_registers_cache[EXT_DMA_REG_ID_PD_LENGTH][ctx_id];

    if (newptr >= pd_buffer_length) {
        ptr_wrap_bit ^= DESC_BUFFER_WRAP_BIT;
        newptr -= pd_buffer_length;
    }

    ILOG_INSTANCE(m_logger,
                  NSIM_DEBUG,
                  string_format("%s: ctx_id=%d, newptr=%x, ptr_wrap_bit=%x, pd_buffer_length=%x, old_val=%x, new_val=%x",
                                __FUNCTION__,
                                ctx_id,
                                newptr,
                                ptr_wrap_bit,
                                pd_buffer_length,
                                m_dma_registers_cache[EXT_DMA_REG_ID_PD_WR_PTR][ctx_id],
                                ptr_wrap_bit | newptr));

    m_dma_registers_cache[EXT_DMA_REG_ID_PD_WR_PTR][ctx_id] = ptr_wrap_bit | newptr;
}

void
packet_dma_extract::dma_data_buffer_wr_ptr_inc(unsigned ctx_id, size_t bytes)
{
    uint32_t newptr
        = (m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id] & ~DATA_BUFFER_WRAP_BIT) + static_cast<uint32_t>(bytes);
    uint32_t ptr_wrap_bit = m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id] & DATA_BUFFER_WRAP_BIT;
    uint32_t data_buffer_length = m_dma_registers_cache[EXT_DMA_REG_ID_DATA_LENGTH][ctx_id];

    if (newptr >= data_buffer_length) {
        ptr_wrap_bit ^= DATA_BUFFER_WRAP_BIT;
        newptr -= data_buffer_length;
    }

    ILOG_INSTANCE(m_logger,
                  NSIM_DEBUG,
                  string_format("%s: ctx_id=%d, newptr=%x, ptr_wrap_bit=%x, data_buffer_length=%x, old_val=%x, new_val=%x",
                                __FUNCTION__,
                                ctx_id,
                                newptr,
                                ptr_wrap_bit,
                                data_buffer_length,
                                m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id] & ~DATA_BUFFER_WRAP_BIT,
                                ptr_wrap_bit | newptr));

    m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id] = ptr_wrap_bit | newptr;
}

size_t
dsim::packet_dma_extract::get_pd_buffer_available_space(unsigned ctx_id)
{
    if (!m_initialized[EXT_DMA_REG_ID_PD_LENGTH][ctx_id]) {
        ELOG_INSTANCE(
            m_logger, NSIM_DEBUG, "Packet DMA extract: get_pd_buffer_available_space(): Using uninitialized PD buffer length reg!");
        return 0;
    }
    uint32_t pd_buff_length = m_dma_registers_cache[EXT_DMA_REG_ID_PD_LENGTH][ctx_id];
    uint32_t raw_read_ptr = m_dma_registers_cache[EXT_DMA_REG_ID_PD_RD_PTR][ctx_id];
    uint32_t raw_write_ptr = m_dma_registers_cache[EXT_DMA_REG_ID_PD_WR_PTR][ctx_id];

    ILOG_INSTANCE(
        m_logger,
        NSIM_DEBUG,
        string_format(
            "Packet DMA extract: get_pd_buffer_available_space(): ctx_id=%u, buff_len=0x%x, raw_rd_ptr=0x%x, raw_wr_ptr=0x%x",
            ctx_id,
            pd_buff_length,
            raw_read_ptr,
            raw_write_ptr));

    if (raw_write_ptr == raw_read_ptr) {
        return pd_buff_length;
    } else {
        uint32_t write_ptr = raw_write_ptr & ~DESC_BUFFER_WRAP_BIT;
        uint32_t read_ptr = raw_read_ptr & ~DESC_BUFFER_WRAP_BIT;
        return (write_ptr >= read_ptr) ? pd_buff_length - write_ptr + read_ptr : read_ptr - write_ptr;
    }
}

size_t
dsim::packet_dma_extract::get_data_buffer_available_space(unsigned ctx_id)
{
    if (!m_initialized[EXT_DMA_REG_ID_DATA_LENGTH][ctx_id]) {
        ELOG_INSTANCE(m_logger,
                      NSIM_DEBUG,
                      "Packet DMA extract: get_data_buffer_available_space(): Using uninitialized DATA buffer length reg!");
        return 0;
    }
    uint32_t data_buff_length = m_dma_registers_cache[EXT_DMA_REG_ID_DATA_LENGTH][ctx_id];
    uint32_t raw_read_ptr = m_dma_registers_cache[EXT_DMA_REG_ID_DATA_RD_PTR][ctx_id];
    uint32_t raw_write_ptr = m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id];

    ILOG_INSTANCE(
        m_logger,
        NSIM_DEBUG,
        string_format(
            "Packet DMA extract: get_data_buffer_available_space(): ctx_id=%u, buff_len=0x%x, raw_rd_ptr=0x%x, raw_wr_ptr=0x%x",
            ctx_id,
            data_buff_length,
            raw_read_ptr,
            raw_write_ptr));

    if (raw_write_ptr == raw_read_ptr) {
        return data_buff_length;
    } else {
        uint32_t write_ptr = raw_write_ptr & ~DATA_BUFFER_WRAP_BIT;
        uint32_t read_ptr = raw_read_ptr & ~DATA_BUFFER_WRAP_BIT;
        return (write_ptr >= read_ptr) ? data_buff_length - write_ptr + read_ptr : read_ptr - write_ptr;
    }
}

void
dsim::packet_dma_extract::dma_data_buffer_get_wr_offsets(unsigned ctx_id,
                                                         size_t packet_len,
                                                         uint32_t& first_offset,
                                                         size_t& first_size,
                                                         size_t& second_size)
{
    uint32_t new_offset
        = (m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id] & ~DATA_BUFFER_WRAP_BIT) + static_cast<uint32_t>(packet_len);
    uint32_t data_buffer_length = m_dma_registers_cache[EXT_DMA_REG_ID_DATA_LENGTH][ctx_id];

    first_offset = m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id] & ~DATA_BUFFER_WRAP_BIT;
    if (new_offset >= data_buffer_length) {
        second_size = new_offset - data_buffer_length;
        first_size = packet_len - second_size;
    } else {
        second_size = 0;
        first_size = packet_len;
    }

    ILOG_INSTANCE(m_logger,
                  NSIM_DEBUG,
                  string_format("Packet DMA extract: dma_data_buffer_get_wr_offsets: ctx_id=%u, pkt_len=%lu, newptr=0x%x, "
                                "buff_len=0x%x, unmasked_first=0x%x, first_sz=0x%x, second_sz=0x%x",
                                ctx_id,
                                packet_len,
                                new_offset,
                                m_dma_registers_cache[EXT_DMA_REG_ID_DATA_WR_PTR][ctx_id],
                                first_size,
                                second_size));

    assert(first_size + second_size == packet_len && "Split packet appropriately when wrapping");
}

bool
dsim::packet_dma_extract::active(unsigned ctx_id)
{
    return !!(m_dma_registers_cache[EXT_DMA_REG_ID_CFG][ctx_id] & (m_ext_cfg_specific.ext_dma_cfg_reg_mask_go));
}
