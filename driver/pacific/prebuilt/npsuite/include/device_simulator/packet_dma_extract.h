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

#ifndef __PACKET_DMA_EXTRACT__
#define __PACKET_DMA_EXTRACT__

#include <utility>
#include <cstdint>
#include <map>
#include <sstream>

#include "device_simulator/dsim_config_interface.h"
#include "device_simulator/dsim_common/packet_dma_defs.h"
#include "device_simulator/socket_command.h"
#include "utils/list_macros.h"

namespace npsuite
{
class Logger;
}

namespace dsim
{
// Configuration register commands bit masks
#define PACIFIC_EXT_DMA_CFG_REG_MASK_GO (0x1 << 0)
#define PACIFIC_EXT_DMA_CFG_REG_MASK_FLOW_CTRL (0x1 << 1)
#define PACIFIC_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_PD_THR (0x1f << 2)
#define PACIFIC_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_DATA_THR (0x3ff << 7)
#define PACIFIC_EXT_DMA_CFG_REG_MASK_REMOTE (0x1 << 17)
#define PACIFIC_EXT_DMA_CFG_REG_MASK_WB (0x1 << 18)

// Configuration register commands bit masks
#define GIBRALTAR_EXT_DMA_CFG_REG_MASK_GO (0x1 << 0)
#define GIBRALTAR_EXT_DMA_CFG_REG_MASK_FLOW_CTRL (0x1 << 1)
#define GIBRALTAR_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_PD_THR (0x3f << 2)
#define GIBRALTAR_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_DATA_THR 0 // does not exist on GB
#define GIBRALTAR_EXT_DMA_CFG_REG_MASK_REMOTE (0x1 << 8)
#define GIBRALTAR_EXT_DMA_CFG_REG_MASK_WB (0x1 << 9)

#define PACKET_DMA_EXTRACT_REG_ID_ENUMS(list_macro)                                                                                \
    list_macro(EXT_DMA_REG_ID_PD_BASE_LOW), list_macro(EXT_DMA_REG_ID_PD_BASE_HIGH), list_macro(EXT_DMA_REG_ID_PD_LENGTH),         \
        list_macro(EXT_DMA_REG_ID_PD_RD_PTR), list_macro(EXT_DMA_REG_ID_PD_WR_PTR), list_macro(EXT_DMA_REG_ID_DATA_BASE_LOW),      \
        list_macro(EXT_DMA_REG_ID_DATA_BASE_HIGH), list_macro(EXT_DMA_REG_ID_DATA_LENGTH), list_macro(EXT_DMA_REG_ID_DATA_RD_PTR), \
        list_macro(EXT_DMA_REG_ID_DATA_WR_PTR), list_macro(EXT_DMA_REG_ID_CFG), list_macro(EXT_DMA_REG_ID_MAX),

typedef enum { PACKET_DMA_EXTRACT_REG_ID_ENUMS(LIST_MACRO_VALUE) } packet_dma_extract_reg_id_t;

struct ext_cfg_asic_specific_t {
    uint32_t ext_dma_cfg_reg_mask_go;
    uint32_t ext_dma_cfg_reg_mask_flow_ctrl;
    uint32_t ext_dma_cfg_reg_mask_flow_ctrl_pd_thr;
    uint32_t ext_dma_cfg_reg_mask_flow_ctrl_data_thr;
    uint32_t ext_dma_cfg_reg_mask_remote;
    uint32_t ext_dma_cfg_reg_mask_wb;
};

constexpr struct ext_cfg_asic_specific_t pacific_ext_cfg_specific = ext_cfg_asic_specific_t{
    PACIFIC_EXT_DMA_CFG_REG_MASK_GO,
    PACIFIC_EXT_DMA_CFG_REG_MASK_FLOW_CTRL,
    PACIFIC_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_PD_THR,
    PACIFIC_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_DATA_THR,
    PACIFIC_EXT_DMA_CFG_REG_MASK_REMOTE,
    PACIFIC_EXT_DMA_CFG_REG_MASK_WB,
};

constexpr struct ext_cfg_asic_specific_t gibraltar_ext_cfg_specific = ext_cfg_asic_specific_t{
    GIBRALTAR_EXT_DMA_CFG_REG_MASK_GO,
    GIBRALTAR_EXT_DMA_CFG_REG_MASK_FLOW_CTRL,
    GIBRALTAR_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_PD_THR,
    GIBRALTAR_EXT_DMA_CFG_REG_MASK_FLOW_CTRL_DATA_THR, // does not exist on GB
    GIBRALTAR_EXT_DMA_CFG_REG_MASK_REMOTE,
    GIBRALTAR_EXT_DMA_CFG_REG_MASK_WB,
};

class socket_client;

class packet_dma_extract
{
public:
    packet_dma_extract();

    void initialize(npsuite::Logger* logger,
                    socket_client* client,
                    const device_info& device_info,
                    std::istringstream& reg_addresses,
                    std::istringstream& reg_names);
    void reset_state(void);

    dsim_status_e write_register(uint32_t block_id, uint32_t reg_address, uint16_t reg_width, size_t count, const void* in_val);
    dsim_status_e read_register(client_id_t client_id,
                                client_seqno_t& seqno,
                                uint32_t block_id,
                                uint32_t reg_address,
                                uint16_t reg_width,
                                size_t count,
                                void* out_value,
                                void* command_buffer);
    dsim_status_e write_register_by_name(const std::string& reg,
                                         size_t reg_index,
                                         uint16_t reg_width,
                                         size_t count,
                                         const void* in_val);
    dsim_status_e read_register_by_name(client_id_t client_id,
                                        client_seqno_t& seqno,
                                        const std::string& reg,
                                        size_t reg_index,
                                        uint16_t reg_width,
                                        size_t count,
                                        void* out_value,
                                        void* command_buffer);

private:
    // Return register ID and DMA context ID pair according to address
    const std::pair<packet_dma_extract_reg_id_t, unsigned>& register_select(uint32_t reg_address);

    void dma_pd_buffer_wr_ptr_inc(unsigned ctx_id, unsigned increment);
    void dma_data_buffer_wr_ptr_inc(unsigned ctx_id, size_t bytes);

    // Returns number of available bytes in PD buffer
    size_t get_pd_buffer_available_space(unsigned ctx_id);
    // Returns number of available bytes in DATA buffer
    size_t get_data_buffer_available_space(unsigned ctx_id);
    // Retrieve the first_offset, first_size and second_size for packet DMA writes.  If second_size is 0, then we have only a single
    // read
    void dma_data_buffer_get_wr_offsets(unsigned ctx_id,
                                        size_t buffer_size,
                                        uint32_t& first_offset,
                                        size_t& first_size,
                                        size_t& second_size);

    // Returns true if the DMA is activated
    bool active(unsigned ctx_id);

private:
    bool m_initialized[EXT_DMA_REG_ID_MAX][MAX_DATA_BUFFER_DMA_CTX];
    uint32_t m_dma_registers_cache[EXT_DMA_REG_ID_MAX][MAX_DATA_BUFFER_DMA_CTX];
    std::map<uint32_t, std::pair<packet_dma_extract_reg_id_t, unsigned>> m_dma_registers_map;
    static const std::pair<packet_dma_extract_reg_id_t, unsigned>& EXT_DMA_REG_UNKNOWN;

    uint8_t* m_dma_pd_user_buffer[MAX_DATA_BUFFER_DMA_CTX];
    uint8_t* m_dma_data_user_buffer[MAX_DATA_BUFFER_DMA_CTX];

    npsuite::Logger* m_logger;
    socket_client* m_socket_client;
    device_e m_device;
    bool m_use_ext_data_buffer;
    // use for calculating address of packet descriptor
    uint32_t m_pd_desc_multiplier;
    uint32_t m_pd_desc_increment;
    uint32_t m_sbif_block_id;
    struct ext_asic_specific_t m_ext_asic;
    struct ext_cfg_asic_specific_t m_ext_cfg_specific;
    std::map<std::string, uint32_t> m_reg_name_to_addr;
};
} // namespace dsim

#endif
