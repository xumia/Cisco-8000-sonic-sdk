// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "access_engine.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "ll_device_impl.h"
#include "lld/device_tree.h"

#include <unistd.h>

#include <climits>
#include <iomanip>
#include <sstream>
#include <thread>

using namespace silicon_one;
using namespace std;

// Access Engine commands.
// All Access Engine commands are 3 dwords long and are written to Access Engine command memory.
// The layout of the bit fields is tailored for little endian host and PCIe interface (i.e. little endian dwords)
// in such a way that no byte swapping is needed.
// Other interfaces (e.g. I2C) might need to swap bytes.
union LA_PACKED access_engine::mem_cmd {
    /// @brief Access engine commands
    ///
    /// @note: MUST be in sync with leaba/trunk/Moriah/ASIC/design/css/verilog/sbif_defines.v

    enum { SIZE_IN_DWORDS = 3, SIZE_IN_BYTES = 12 };

    enum class opcode_e : uint32_t {
        WRITE = 1,              ///< Write from buffer.
        READ = 2,               ///< Read from buffer.
        IMPORT = 3,             ///< Import data from host memory.
        EXPORT = 4,             ///< Export data to host memory.
        FETCH = 5,              ///< Fetch commands from host memory.
        WAIT_FOR_VALUE = 6,     ///< Wait for value to be equal (1) or not (0).
        IMMEDIATE_WRITE = 7,    ///< Immediate write, data is packed in a command.
        READ_MODIFY_WRITE = 8,  ///< Read modify write using data and mask entries in a data buffer.
        DELAY = 9,              ///< Wait a specified amount of clock cycles.
        ACQUIRE_SEMAPHORE = 12, ///< Acquire semaphore index between 0 and 63.
        RELEASE_SEMAPHORE = 13, ///< Release semaphore index between 0 and 63.
    };

    uint32_t dwords[SIZE_IN_DWORDS];
    static_assert(sizeof(mem_cmd::dwords) == SIZE_IN_BYTES, "Bad command size");

    struct write_from_buffer {
        // dword 0
        uint32_t length : 10;   // [73:64]
        uint32_t buff_addr : 9; // [82:74]
        uint32_t reserved2 : 1; // [83:83]
        uint32_t interrupt : 1; // [84:84]
        uint32_t reserved1 : 3; // [87:85]
        uint32_t opcode : 5;    // [92:88]
        uint32_t reserved0 : 3; // [95:93]

        // dword 1
        uint32_t block_id : 12; // [43:32]
        uint32_t reserved4 : 4; // [47:44]
        uint32_t count : 10;    // [57:48]
        uint32_t reserved3 : 6; // [63:58]

        // dword 2
        uint32_t addr; // [31:0]
    } write_from_buffer, read_modify_write;
    static_assert(sizeof(mem_cmd::write_from_buffer) == SIZE_IN_BYTES, "Bad command size");

    struct read_to_buffer {
        // dword 0
        uint32_t length : 10;    // [73:64]
        uint32_t buff_addr : 9;  // [82:74]
        uint32_t reserved2 : 1;  // [83:83]
        uint32_t interrupt : 1;  // [84:84]
        uint32_t rd_not_clr : 1; // [85:85]
        uint32_t reserved1 : 2;  // [87:86]
        uint32_t opcode : 5;     // [92:88]
        uint32_t reserved0 : 3;  // [95:93]

        // dword 1
        uint32_t block_id : 12; // [43:32]
        uint32_t reserved4 : 4; // [47:44]
        uint32_t count : 10;    // [57:48]
        uint32_t reserved3 : 6; // [63:58]

        // dword 2
        uint32_t addr; // [31:0]
    } read_to_buffer;
    static_assert(sizeof(mem_cmd::read_to_buffer) == SIZE_IN_BYTES, "Bad command size");

    struct importcmd {
        // dword 0
        uint32_t length : 10;     // [73:64]
        uint32_t buff_addr : 9;   // [82:74]
        uint32_t remote_addr : 1; // [83:83]
        uint32_t interrupt : 1;   // [84:84]
        uint32_t reserved1 : 3;   // [87:85]
        uint32_t opcode : 5;      // [92:88]
        uint32_t reserved0 : 3;   // [95:93]

        // dword 1
        uint32_t upper_addr; // [63:32]

        // dword 2
        uint32_t addr; // [31:0]
    } importcmd, exportcmd;
    static_assert(sizeof(mem_cmd::importcmd) == SIZE_IN_BYTES, "Bad command size");

    struct fetch {
        // dword 0
        uint32_t length : 10;     // [73:64]
        uint32_t reserved2 : 9;   // [82:74]
        uint32_t remote_addr : 1; // [83:83]
        uint32_t interrupt : 1;   // [84:84]
        uint32_t reserved1 : 3;   // [87:85]
        uint32_t opcode : 5;      // [92:88]
        uint32_t reserved0 : 3;   // [95:93]

        // dword 1
        uint32_t upper_addr; // [63:32]

        // dword 2
        uint32_t addr; // [31:0]
    } fetch;
    static_assert(sizeof(mem_cmd::fetch) == SIZE_IN_BYTES, "Bad command size");

    struct wait_for_value {
        // dword 0
        uint32_t value_high : 12; // [75:64]
        uint32_t poll_cnt : 8;    // [83:76]
        uint32_t interrupt : 1;   // [84:84]
        uint32_t equal : 1;       // [85:85]
        uint32_t reserved1 : 2;   // [87:86]
        uint32_t opcode : 5;      // [92:88]
        uint32_t reserved0 : 3;   // [95:93]

        // dword 1
        uint32_t block_id : 12; // [43:32]
        uint32_t mask : 16;     // [59:44]
        uint32_t value_low : 4; // [63:60]

        // dword 2
        uint32_t addr; // [31:0]
    } wait_for_value;
    static_assert(sizeof(mem_cmd::wait_for_value) == SIZE_IN_BYTES, "Bad command size");

    struct immediate_write {
        // dword 0
        uint32_t value_high : 12; // [75:64]
        uint32_t reserved2 : 8;   // [83:76]
        uint32_t interrupt : 1;   // [84:84]
        uint32_t reserved1 : 3;   // [87:85]
        uint32_t opcode : 5;      // [92:88]
        uint32_t reserved0 : 3;   // [95:93]

        // dword 1
        uint32_t block_id : 12;  // [43:32]
        uint32_t value_low : 20; // [63:44]

        // dword 2
        uint32_t addr; // [31:0]
    } immediate_write;
    static_assert(sizeof(mem_cmd::immediate_write) == SIZE_IN_BYTES, "Bad command size");

    struct delay {
        // dword 0
        uint32_t reserved2 : 20; // [83:64]
        uint32_t interrupt : 1;  // [84:84]
        uint32_t reserved1 : 3;  // [87:85]
        uint32_t opcode : 5;     // [92:88]
        uint32_t reserved0 : 3;  // [95:93]

        // dword 1
        uint32_t delay_count_high; // [63:32]

        // dword 2
        uint32_t delay_count_low; // [31:0]
    } delay;
    static_assert(sizeof(mem_cmd::delay) == SIZE_IN_BYTES, "Bad command size");

    struct acquire_semaphore {
        // dword 0
        uint32_t index : 6;      // [69:64]
        uint32_t reserved1 : 18; // [87:70]
        uint32_t opcode : 5;     // [92:88]
        uint32_t reserved0 : 3;  // [95:93]

        // dword 1
        uint32_t reserved2;

        // dword 2
        uint32_t reserved3;
    } acquire_semaphore, release_semaphore;
    static_assert(sizeof(mem_cmd::acquire_semaphore) == SIZE_IN_BYTES, "Bad command size");
}; // union mem_cmd

// Access Engine registers (not all, only the ones we use)

// Go register
static constexpr uint32_t GO_CONTINUOUS = 2; // Continously execute commands as they are pushed to FIFO.

// Fifo pointers are 10 bits, but the fifo has only 2^9 entries.
// The 10th bit toggles between even/odd fifo wrap arounds.
enum cmd_fifo_e {
    CMD_FIFO_PTR_BITS = 10,
    CMD_FIFO_SIZE_IN_DWORDS = 1 << (CMD_FIFO_PTR_BITS - 1),
    CMD_FIFO_PTR_ASIC7_BITS = 7,
    CMD_FIFO_ASIC7_SIZE_IN_DWORDS = 1 << (CMD_FIFO_PTR_ASIC7_BITS - 1),
};

enum cmd_fifo_ptr_mask_e { FIFO_RW_PTR_MASK_DEFAULT = 0x1ff, FIFO_RW_PTR_MASK_ASIC7 = 0x3f };

enum cmd_fifo_wrap_arround_mask_e { FIFO_RW_WRAP_AROUND_MASK_DEFAULT = 0x3ff, FIFO_RW_WRAP_AROUND_MASK_ASIC7 = 0x7f };

union LA_PACKED reg_cmd_ptr {
    struct {
        uint32_t fifo_w : CMD_FIFO_PTR_BITS; // [9] - odd/even round, [8:0] pointer bits
        uint32_t fifo_r : CMD_FIFO_PTR_BITS; // [19] - odd/even round, [18:10] pointer bits
        uint32_t reserved : 12;              // [31:20]
    } fields;
    struct {
        uint32_t fifo_w : CMD_FIFO_PTR_ASIC7_BITS; // [6] - odd/even round, [5:0] pointer bits
        uint32_t fifo_r : CMD_FIFO_PTR_ASIC7_BITS; // [13] - odd/even round, [12:7] pointer bits
        uint32_t reserved : 18;                     // [31:14]
    } fields_asic7;
    uint32_t dword;
};
static_assert(sizeof(reg_cmd_ptr) == sizeof(uint32_t), "Bad register size");

union LA_PACKED reg_status {
    struct {
        uint32_t active : 1;        // [0:0]
        uint32_t state : 6;         // [6:1]
        uint32_t count : 10;        // [16:7]
        uint32_t error : 1;         // [17:17]
        uint32_t err_block_id : 12; // [29:18]
        uint32_t err_inv_cmd : 1;   // [30:30]
        uint32_t err_msb : 1;       // [31:31] Bit 31 has a different meaning in Pacific vs GB
    } fields;
    struct {
        uint32_t active : 1;        // [0:0]
        uint32_t state : 4;         // [4:1]
        uint32_t count : 10;        // [14:5]
        uint32_t error : 1;         // [15:15]
        uint32_t err_block_id : 12; // [27:16]
        uint32_t err_inv_cmd : 1;   // [28:28]
        uint32_t err_msb : 3;       // [31:29] // Meaning of these bits???
    } fields_asic7;
    uint32_t dword;
};
static_assert(sizeof(reg_status) == sizeof(uint32_t), "Bad register size");

static const char*
ae_state_to_cstr(uint8_t ae_state)
{
    // From <leaba>/design/dmc/sbif/verilog/sbif_access_engine.v
    static const char* strs[] = {
        "IDLE",            // 6'd0
        "WR_REQ",          // 6'd1
        "WR_TX_HDR",       // 6'd2
        "WR_TX_ADDR",      // 6'd3
        "WR_TX_DATA",      // 6'd4
        "WR_WAIT_RSP",     // 6'd5
        "RD_REQ",          // 6'd6
        "RD_TX_HDR",       // 6'd7
        "RD_TX_ADDR",      // 6'd8
        "RD_WAIT_RSP",     // 6'd9
        "RD_RX_DATA",      // 6'd10
        "IMP_REQ",         // 6'd11
        "IMP_ST_BURST",    // 6'd12
        "IMP_MID_BURST",   // 6'd13
        "IMP_END_BURST",   // 6'd14
        "FETCH_REQ",       // 6'd15
        "FETCH_ST_BURST",  // 6'd16
        "FETCH_MID_BURST", // 6'd17
        "FETCH_END_BURST", // 6'd18
        "EXP_PREFETCH",    // 6'd19
        "EXP_REQ",         // 6'd20
        "EXP_ST_BURST",    // 6'd21
        "EXP_MID_BURST",   // 6'd22
        "EXP_END_BURST",   // 6'd23
        "POLL_REQ",        // 6'd24
        "POLL_TX_HDR",     // 6'd25
        "POLL_TX_ADDR",    // 6'd26
        "POLL_WAIT_RSP",   // 6'd27
        "POLL_RX_DATA",    // 6'd28
        "IMM_WR_REQ",      // 6'd29
        "IMM_WR_TX_HDR",   // 6'd30
        "IMM_WR_TX_ADDR",  // 6'd31
        "IMM_WR_TX_DATA",  // 6'd32
        "IMM_WR_WAIT_RSP", // 6'd33
        "RMW_RD_REQ",      // 6'd34
        "RMW_RD_TX_HDR",   // 6'd35
        "RMW_RD_TX_ADDR",  // 6'd36
        "RMW_RD_WAIT_RSP", // 6'd37
        "RMW_WR_TX_HDR",   // 6'd38
        "RMW_WR_TX_ADDR",  // 6'd39
        "RMW_WR_TX_DATA",  // 6'd40
        "RMW_WR_WAIT_RSP", // 6'd41
        "DELAY",           // 6'd42
        "SBUS_REG_WR",     // 6'd43
        "SBUS_REG_RD",     // 6'd44
        "SBUS_REG_WAIT",   // 6'd45
        "SBUS_REG_RETRY",  // 6'd46
        "ACQUIRE_SEM",     // 6'd47
        "RELEASE_SEM",     // 6'd48
    };

    return ae_state < array_size(strs) ? strs[ae_state] : "UNKNOWN";
}

static la_status to_status(access_engine::state_e s);

// Maximum value that can be encoded into a 9-bit field - write_from_buffer::count, read_to_buffer::count, etc.
constexpr size_t CIF_COUNT_MAX = (1 << 10) - 1;
// Maximum value that can be encoded into a 6-bit field - write_from_buffer::count, read_to_buffer::count, etc.
constexpr size_t CIF_COUNT_ASIC7_MAX = (1 << 7) - 1;

access_engine::access_engine(ll_device_impl_wptr lld,
                             uint16_t engine_id,
                             const access_engine_info& ae_info,
                             const la_dma_desc& dma_desc)
    : m_ll_device(lld),
      m_engine_id(engine_id),
      m_dma_desc(dma_desc),
      m_data_pos(0),
      m_cmd_pos(0),
      m_cmd_fifo_w(0),
      m_cmd_fifo_shadow(CMD_FIFO_SIZE_IN_DWORDS),
      m_state(state_e::NONE),
      m_error_opcode(0),
      m_error_block_id(LA_BLOCK_ID_INVALID),
      m_error_address(0)
{
    initialize(ae_info);
}

void
access_engine::initialize(const access_engine_info& ae_info)
{
    // There are N Access Engines, each has a set of registers (go/cmd_ptr/...), 2 instances of command memory,
    // and 2 instances of data memory.
    // LBR has N instances of acc_eng_go_reg, but 2*N instances of access_engine_command_mem.
    //
    // For i'th access engine, the relevant registers are lbr_tree->sbif->reg_xxx[i]. Simple!
    //
    // And the relevant memories are lbr_tree->sbif->mem_xxx[i] which are addressible with
    // offset in the range [0:2*memsize-1], i.e. as a flat logical memory block,
    // twice the size of the physical memory instance.
    //
    // And lbr_tree->sbif->mem[N+i] instances are ignored.

    m_cmd_mem_addr = ae_info.cmd_mem_addr;
    m_data_mem_addr = ae_info.data_mem_addr;
    m_go_reg_addr = ae_info.go_reg_addr;
    m_cmd_ptr_reg_addr = ae_info.cmd_ptr_reg_addr;
    m_status_reg_addr = ae_info.status_reg_addr;

    // The usable portion of AE data memory is the minimum between the size of DMA buffer the size of AE data memory.
    size_t entries = ae_info.data_mem_entries;
    size_t entry_width = ae_info.data_width;

    if (!m_ll_device->is_asic7()) {
        dassert_crit(entry_width == 4);
    } else {
        // Asic7 has entry_width = 5
        dassert_crit(entry_width == 5);
    }

    if (m_dma_desc.length) {
        // PCI dev interface
        m_data_mem_entries = std::min(entries, m_dma_desc.length / entry_width);
    } else {
        // Non-PCI dev interface
        m_data_mem_entries = entries;
    }

    uint32_t cmd_fifo_entries = ae_info.cmd_entries;

    log_debug(AE,
              "%s: ae[%d]: dma_va=%p, dma_pa=0x%lx, dma_length=0x%lx, cmd_mem=0x%x, dword entries=0x%x, data_mem=0x%x, "
              "dword entries=0x%x, go=0x%x, cmd_ptr=0x%x, status=0x%x",
              __func__,
              m_engine_id,
              m_dma_desc.virt_addr,
              m_dma_desc.phys_addr,
              m_dma_desc.length,
              m_cmd_mem_addr,
              cmd_fifo_entries,
              m_data_mem_addr,
              m_data_mem_entries,
              m_go_reg_addr,
              m_cmd_ptr_reg_addr,
              m_status_reg_addr);

    if (!m_ll_device->is_asic7()) {
        dassert_crit(cmd_fifo_entries == CMD_FIFO_SIZE_IN_DWORDS);
    } else {
        dassert_crit(cmd_fifo_entries == CMD_FIFO_ASIC7_SIZE_IN_DWORDS);
    }
}

uint16_t
access_engine::get_engine_id() const
{
    return m_engine_id;
}

/// @brief Reset access engine's soft state
la_status
access_engine::reset()
{
    update_state();

    log_debug(AE, "%s: ae[%d], state=%s", __func__, m_engine_id, to_string(m_state));

    if (m_state != state_e::NONE && m_state != state_e::READY) {
        log_err(AE, "%s: ae[%d] error state=%s", __func__, m_engine_id, to_string(m_state));
        if (m_state == state_e::NODEV) {
            return LA_STATUS_ENODEV;
        }

        // AE is in error or busy state, "reset" will attempt to clear.
    }

    // reset the fifo pointers
    m_ll_device->sbif_write_register(m_cmd_ptr_reg_addr, 0);
    m_cmd_fifo_w = 0;
    m_cmd_pos = 0;

    // reset the data buffer
    for (size_t i = 0; i < m_data_mem_entries; i++) {
        m_ll_device->sbif_write_memory(m_data_mem_addr, i, 0);
    }
    m_data_pos = 0;

    // reset the DMA buffer
    if (m_dma_desc.virt_addr) {
        bzero(m_dma_desc.virt_addr, m_dma_desc.length);
    }

    go();

    return LA_STATUS_SUCCESS;
}

void
access_engine::go()
{
    m_ll_device->sbif_write_register(m_go_reg_addr, GO_CONTINUOUS);
    m_state = state_e::READY;
}

static la_status
to_status(access_engine::state_e s)
{
    const la_status statuses[] = {[(size_t)access_engine::state_e::NONE] = LA_STATUS_SUCCESS,
                                  [(size_t)access_engine::state_e::READY] = LA_STATUS_SUCCESS,
                                  [(size_t)access_engine::state_e::BUSY] = LA_STATUS_EBUSY,
                                  [(size_t)access_engine::state_e::FAIL] = LA_STATUS_EUNKNOWN,
                                  [(size_t)access_engine::state_e::NODEV] = LA_STATUS_ENODEV};

    if ((size_t)s < silicon_one::array_size(statuses)) {
        return statuses[(size_t)s];
    }

    return LA_STATUS_EUNKNOWN;
}

const char*
access_engine::to_string(access_engine::state_e s)
{
    const char* strs[] = {[(size_t)access_engine::state_e::NONE] = "NONE",
                          [(size_t)access_engine::state_e::READY] = "READY",
                          [(size_t)access_engine::state_e::BUSY] = "BUSY",
                          [(size_t)access_engine::state_e::FAIL] = "FAIL",
                          [(size_t)access_engine::state_e::NODEV] = "NODEV"};

    if ((size_t)s < silicon_one::array_size(strs)) {
        return strs[(size_t)s];
    }

    return "UNKNOWN";
}

string
access_engine::to_string(access_engine::mem_cmd cmd)
{
    stringstream ss;

    access_engine::mem_cmd::opcode_e op = (access_engine::mem_cmd::opcode_e)cmd.write_from_buffer.opcode;
    switch (op) {
    case access_engine::mem_cmd::opcode_e::WRITE: {
        const auto& op = cmd.write_from_buffer;
        ss << "op=WRITE, buff_addr=0x" << hex << op.buff_addr << ", length=0x" << hex << op.length << ", count=" << op.count
           << ", block_id=0x" << hex << op.block_id << ", addr=0x" << hex << op.addr;
        break;
    }
    case access_engine::mem_cmd::opcode_e::READ: {
        const auto& op = cmd.read_to_buffer;
        ss << "op=READ, rd_not_clr=0x" << hex << op.rd_not_clr << ", buff_addr=0x" << hex << op.buff_addr << ", length=0x" << hex
           << op.length << ", count=" << op.count << ", block_id=0x" << hex << op.block_id << ", addr=0x" << hex << op.addr;
        break;
    }
    case access_engine::mem_cmd::opcode_e::IMPORT: {
        const auto& op = cmd.importcmd;
        ss << "op=IMPORT, remote=" << op.remote_addr << ", buff_addr=0x" << hex << op.buff_addr << ", length=0x" << hex << op.length
           << ", upper_addr=" << op.upper_addr << ", addr=0x" << hex << op.addr;
        break;
    }
    case access_engine::mem_cmd::opcode_e::EXPORT: {
        const auto& op = cmd.exportcmd;
        ss << "op=EXPORT, remote=" << op.remote_addr << ", buff_addr=0x" << hex << op.buff_addr << ", length=0x" << hex << op.length
           << ", upper_addr=" << op.upper_addr << ", addr=0x" << hex << op.addr;
        break;
    }
    case access_engine::mem_cmd::opcode_e::WAIT_FOR_VALUE: {
        const auto& op = cmd.wait_for_value;
        ss << "op=WAIT_FOR_VALUE, equal=" << op.equal << ", poll_cnt=" << op.poll_cnt
           << ", value=" << ((op.value_high << 4) | op.value_low) << ", mask=" << op.mask << ", block_id=0x" << hex << op.block_id
           << ", addr=0x" << op.addr;
        break;
    }
    case access_engine::mem_cmd::opcode_e::IMMEDIATE_WRITE:
        ss << "op=IMM_WRITE, block_id=0x" << hex << cmd.immediate_write.block_id << ", addr=0x" << cmd.immediate_write.addr
           << ", val=0x" << setfill('0') << setw(8) << hex
           << ((cmd.immediate_write.value_high << 20) | cmd.immediate_write.value_low);
        break;
    default:
        ss << "unexpected AE opcode " << cmd.write_from_buffer.opcode << " dword[0]=0x" << setfill('0') << setw(8) << hex
           << cmd.dwords[0] << " dword[1]=0x" << setfill('0') << setw(8) << hex << cmd.dwords[1] << " dword[2]=0x" << setfill('0')
           << setw(8) << hex << cmd.dwords[2];
        break;
    }

    return ss.str();
}

la_status
access_engine::wait_completion()
{
    // Wait for status to become not "busy".
    static constexpr int poll_max = 100000 * mem_cmd::SIZE_IN_DWORDS;

    for (int i = 0; i < poll_max; ++i) {
        update_state();
        if (m_state != state_e::BUSY) {
            break;
        }
        std::this_thread::yield();
    }

    return to_status(m_state);
}

la_status
access_engine::flush()
{
    la_status rc = wait_completion();

    if (m_state == state_e::FAIL) {
        if (pacific_b0_lpm_bubble_errata_workaround_eligible(m_error_block_id, m_error_address)) {
            pacific_b0_lpm_bubble_errata_perform_workaround();
            rc = to_status(m_state);
        } else if (gibraltar_lp_profile_mapping_verifier_workaround_eligible(m_error_block_id, m_error_address)) {
            gibraltar_lp_profile_mapping_verifier_perform_workaround();
            rc = to_status(m_state);
        }

        if (m_state == state_e::FAIL) {
            log_err(AE, "%s: ae[%hd], command failed", __func__, m_engine_id);
            log_posted_commands();

            // Restart the access engine with the next command, skipping the failed command.
            go();
            rc = wait_completion();
        }
    }

    return_on_error_log(rc, AE, ERROR, "wait_completion() failed, rc = %d", rc.value());

    // Access Engine is in READY state and nothing is pending in command FIFO.
    m_data_pos = 0;
    m_cmd_pos = 0;

    return LA_STATUS_SUCCESS;
}

access_engine::mem_cmd
access_engine::read_command_from_fifo(uint16_t fifo_read_pointer) const
{
    uint32_t fifo_r = 0;

    uint32_t cmd_fifo_size_in_dwords = 0;
    uint16_t fifo_read_pointer_mask = 0;

    if (!m_ll_device->is_asic7()) {
        cmd_fifo_size_in_dwords = CMD_FIFO_SIZE_IN_DWORDS;
        fifo_read_pointer_mask = FIFO_RW_PTR_MASK_DEFAULT;
    } else {
        cmd_fifo_size_in_dwords = CMD_FIFO_ASIC7_SIZE_IN_DWORDS;
        fifo_read_pointer_mask = FIFO_RW_PTR_MASK_ASIC7;
    }
    // Retrieve a command from AE command fifo
    // fifo read/write pointers are 9 bits, and bit 10 marks even/odd wrap around
    fifo_r = fifo_read_pointer & fifo_read_pointer_mask;

    uint32_t dword_0 = fifo_r >= 3 ? fifo_r - 3 : (cmd_fifo_size_in_dwords + fifo_r - 3);
    uint32_t dword_1 = fifo_r >= 2 ? fifo_r - 2 : (cmd_fifo_size_in_dwords + fifo_r - 2);
    uint32_t dword_2 = fifo_r >= 1 ? fifo_r - 1 : (cmd_fifo_size_in_dwords + fifo_r - 1);

    mem_cmd cmd = {{0}};
    m_ll_device->sbif_read_memory(m_cmd_mem_addr, dword_0, &cmd.dwords[0]);
    m_ll_device->sbif_read_memory(m_cmd_mem_addr, dword_1, &cmd.dwords[1]);
    m_ll_device->sbif_read_memory(m_cmd_mem_addr, dword_2, &cmd.dwords[2]);

    return cmd;
}

access_engine::state_e
access_engine::update_state()
{
    if (m_state == state_e::NONE || m_state == state_e::FAIL) {
        // Access Engine is in initial state (NONE) or in error state (FAIL).
        // In both cases, it is stopped and the GO register is 0.
        return m_state;
    }

    reg_cmd_ptr cmd_ptr = {.dword = 0};
    reg_status status = {.dword = UINT32_MAX};

    m_ll_device->sbif_read_register(m_status_reg_addr, &status.dword);

    la_logger_level_e level = la_logger_level_e::DEBUG;

    if (!m_ll_device->is_asic7()) {
        if (!status.fields.error) {
            m_ll_device->sbif_read_register(m_cmd_ptr_reg_addr, &cmd_ptr.dword);
            if (!status.fields.active && !status.fields.state && (cmd_ptr.fields.fifo_w == cmd_ptr.fields.fifo_r)) {
                // fifo read pointer reached the write pointer and state is clear ==> DONE
                m_state = state_e::READY;
            } else {
                m_state = state_e::BUSY;
            }
        } else if (status.dword == UINT32_MAX) {
            // All-ones mean that PCI interface is dead.
            log_crit(AE, "%s: Device interface is not present", __func__);
            m_state = state_e::NODEV;
            return m_state;
        } else {
            m_ll_device->sbif_read_register(m_cmd_ptr_reg_addr, &cmd_ptr.dword);
            // Capture details about the offending command: opcode, block_id, address.
            mem_cmd error_mem_cmd = read_command_from_fifo(cmd_ptr.fields.fifo_r);
            m_error_opcode = error_mem_cmd.write_from_buffer.opcode;
            m_error_address = error_mem_cmd.write_from_buffer.addr;
            m_error_block_id = status.fields.err_block_id;

            // The AE error bit (status.fields.error), is set on error and is automatically cleared on read.
            // The GO register is 0.
            //
            // Remember the error as a soft state, to avoid further reads from HW.
            m_state = state_e::FAIL;

            if (!gibraltar_lp_profile_mapping_verifier_workaround_eligible(m_error_block_id, m_error_address)) {
                log_err(AE, "%s: ae[%hd]: last processed command %s", __func__, m_engine_id, to_string(error_mem_cmd).c_str());
                level = la_logger_level_e::ERROR;
            }
        }
    } else {
        if (!status.fields_asic7.error) {
            m_ll_device->sbif_read_register(m_cmd_ptr_reg_addr, &cmd_ptr.dword);
            if (!status.fields_asic7.active && !status.fields_asic7.state
                && (cmd_ptr.fields_asic7.fifo_w == cmd_ptr.fields_asic7.fifo_r)) {
                // fifo read pointer reached the write pointer and state is clear ==> DONE
                m_state = state_e::READY;
            } else {
                m_state = state_e::BUSY;
            }
        } else if (status.dword == UINT32_MAX) {
            // All-ones mean that PCI interface is dead.
            log_crit(AE, "%s: Device interface is not present", __func__);
            m_state = state_e::NODEV;
            return m_state;
        } else {
            m_ll_device->sbif_read_register(m_cmd_ptr_reg_addr, &cmd_ptr.dword);
            // Capture details about the offending command: opcode, block_id, address.
            mem_cmd error_mem_cmd = read_command_from_fifo(cmd_ptr.fields_asic7.fifo_r);
            m_error_opcode = error_mem_cmd.write_from_buffer.opcode;
            m_error_address = error_mem_cmd.write_from_buffer.addr;
            m_error_block_id = status.fields_asic7.err_block_id;

            // The AE error bit (status.fields.error), is set on error and is automatically cleared on read.
            // The GO register is 0.
            //
            // Remember the error as a soft state, to avoid further reads from HW.
            m_state = state_e::FAIL;
        }
    }

    log_message(la_logger_component_e::AE,
                level,
                "%s: ae[%hd]: state=%s, fifo_r=0x%x, fifo_w=0x%x, status=0x%x (active=0x%x, state=0x%x(%s), "
                "count=0x%x, err=0x%x, err_block_id=0x%x, err_inv_cmd=0x%x, err_msb=0x%x), error_address=0x%x, "
                "m_cmd_pos=0x%x, m_data_pos=0x%x",
                __func__,
                m_engine_id,
                to_string(m_state),
                cmd_ptr.fields.fifo_r,
                cmd_ptr.fields.fifo_w,
                status.dword,
                status.fields.active,
                status.fields.state,
                ae_state_to_cstr(status.fields.state),
                status.fields.count,
                status.fields.error,
                status.fields.err_block_id,
                status.fields.err_inv_cmd,
                status.fields.err_msb,
                m_error_address,
                m_cmd_pos,
                m_data_pos);

    return m_state;
}

void
access_engine::log_posted_commands() const
{
    // Dump SW shadow of command fifo
    for (size_t i = 0; i < m_cmd_pos; i += 3) {
        mem_cmd cmd;
        cmd.dwords[0] = m_cmd_fifo_shadow[i];
        cmd.dwords[1] = m_cmd_fifo_shadow[i + 1];
        cmd.dwords[2] = m_cmd_fifo_shadow[i + 2];
        log_err(AE, "ae[%hd], fifo shadow [%ld]: %s", m_engine_id, i, to_string(cmd).c_str());
    }
}

la_status
access_engine::make_room(size_t count)
{
    return make_room(count, 0);
}

la_status
access_engine::make_room(size_t count, la_entry_width_t data_dwords)
{
    bool is_asic7 = m_ll_device->is_asic7();

    uint32_t count_compare = !is_asic7 ? CIF_COUNT_MAX : CIF_COUNT_ASIC7_MAX;

    if (count > count_compare) {
        log_err(AE, "%s: count %ld beyond %ld is not supported", __func__, count, CIF_COUNT_MAX);
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    size_t commands_size = count * mem_cmd::SIZE_IN_DWORDS;
    uint32_t command_size_compare = is_asic7 ? CMD_FIFO_ASIC7_SIZE_IN_DWORDS : CMD_FIFO_SIZE_IN_DWORDS;

    if (commands_size >= command_size_compare) {
        log_err(AE, "Too many commands to fit in AE fifo, count=%ld", count);
        return LA_STATUS_ESIZE;
    }

    if (data_dwords > m_data_mem_entries) {
        log_err(AE, "Data too big to fit in AE data memory, dwords=%d", data_dwords);
        return LA_STATUS_ESIZE;
    }

    if (m_cmd_pos + commands_size >= command_size_compare || m_data_pos + data_dwords >= m_data_mem_entries) {
        // Drain the AE command & data buffers.
        return flush();
    }

    return LA_STATUS_SUCCESS;
}

void
access_engine::encode(const mem_cmd cmd[], size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        encode(cmd[i]);
    }
}

void
access_engine::encode(const mem_cmd& cmd)
{
    static_assert(sizeof(mem_cmd) == mem_cmd::SIZE_IN_BYTES, "Bad command size");
    log_debug(AE, "%s: fifo_w=0x%x, %08x__%08x__%08x", __func__, m_cmd_fifo_w, cmd.dwords[0], cmd.dwords[1], cmd.dwords[2]);

    bool is_asic7 = m_ll_device->is_asic7();

    uint32_t fifo_rw_pointer_mask = !is_asic7 ? FIFO_RW_PTR_MASK_DEFAULT : FIFO_RW_PTR_MASK_ASIC7;
    uint32_t fifo_wrap_around_mask = !is_asic7 ? FIFO_RW_WRAP_AROUND_MASK_DEFAULT : FIFO_RW_WRAP_AROUND_MASK_ASIC7;

    // Write 3 dwords to command memory, wrap around the fifo pointer.
    // In fifo mode (default), we could simply write to a constant offset.
    // In CPU FIFO override mode and in simulation, the offset is meaningful.
    for (int i = 0; i < mem_cmd::SIZE_IN_DWORDS; ++i) {
        // Tricky: fifo read/write pointers are 10bits, but the fifo has only 2^9 entries.
        // The most-significant bit toggles between even/odd fifo wrap arounds.

        // Use bits [8:0] for writing to command fifo
        size_t entry = m_cmd_fifo_w & fifo_rw_pointer_mask;
        m_ll_device->sbif_write_memory(m_cmd_mem_addr, entry, cmd.dwords[i]);

        m_cmd_fifo_shadow[m_cmd_pos + i] = cmd.dwords[i];

        // Use bits [9:0] when wrapping around
        m_cmd_fifo_w = (m_cmd_fifo_w + 1) & fifo_wrap_around_mask;
    }

    m_cmd_pos += mem_cmd::SIZE_IN_DWORDS;

    bool fifo_enabled = m_ll_device->get_access_engine_cmd_fifo_enabled();
    bool nosim = (m_ll_device->get_device_simulator() == nullptr);
    if (fifo_enabled && nosim) {
        // We are done! This is the default mode (Fifo mode, no simulator)
    } else {
        // Update the Fifo write pointer if we are in simulation or if the HW access engine is in non-fifo mode.
        reg_cmd_ptr cmd_ptr = {};
        m_ll_device->sbif_read_register(m_cmd_ptr_reg_addr, &cmd_ptr.dword);
        if (!is_asic7) {
            cmd_ptr.fields.fifo_w = m_cmd_fifo_w;
        } else {
            cmd_ptr.fields_asic7.fifo_w = m_cmd_fifo_w;
        }
        m_ll_device->sbif_write_register(m_cmd_ptr_reg_addr, cmd_ptr.dword);
    }
}

la_status
access_engine::copy_read_result(uint32_t read_cookie, la_entry_width_t width_bytes, size_t count, void* out_val)
{
    la_entry_width_t width_dwords = bit_utils::width_bytes_to_dwords(width_bytes);
    uint32_t data_pos = read_cookie;
    uint8_t* dma_va = (uint8_t*)m_dma_desc.virt_addr + (data_pos << 2);
    uint64_t dma_pa = m_dma_desc.phys_addr + (data_pos << 2);

    // Called after flush(), AE is idle and m_data_pos==m_cmd_pos==0

    // Limitations of EXPORT opcode:
    // - AE data buffer address must be even.
    // - DMA address must be aligned to 8 bytes.
    // - Length (count of DWORDs) must be even. When needed, export an extra redundant DWORD.
    dassert_crit(dma_pa % 8 == 0);
    la_entry_width_t total_width_dwords = count * width_dwords;
    if (total_width_dwords % 2 != 0) {
        total_width_dwords++;
    }

    //
    // Copy data from AE data memory, use either EXPORT or sbif_read
    //
    if (m_dma_desc.virt_addr) {
        // Using EXPORT command - it DMAs data from AE data memory to host

        mem_cmd cmd;

        bzero(&cmd, sizeof(cmd));
        cmd.exportcmd.opcode = (uint32_t)mem_cmd::opcode_e::EXPORT;
        cmd.exportcmd.remote_addr = 1; // host (not ARC)
        cmd.exportcmd.buff_addr = data_pos;
        cmd.exportcmd.length = total_width_dwords;
        cmd.exportcmd.upper_addr = dma_pa >> 32;
        cmd.exportcmd.addr = dma_pa & 0xffffffff;

        encode(cmd);

        la_status rc = wait_completion();
        return_on_error(rc);

        // Aligmnent in DMA mem is on dword, but we want user to see it as alignment per byte
        for (size_t i = 0; i < count; ++i) {
            memcpy((uint8_t*)out_val + i * width_bytes, (uint8_t*)dma_va + i * width_dwords * 4, width_bytes);
        }

        return LA_STATUS_SUCCESS;

    } else {
        // Not a PCIe interface or DMA is disabled, or some EXPORT requirements have not been met
        return m_ll_device->sbif_read_memory_entries(m_data_mem_addr, data_pos, width_dwords * count, (uint32_t*)out_val);
    }
}

la_status
access_engine::read(la_block_id_t block_id,
                    la_entry_addr_t addr,
                    la_entry_width_t width_bytes,
                    size_t count,
                    bool peek,
                    uint32_t& read_cookie)
{
    // TODO: check access engine state

    la_entry_width_t width_dwords = bit_utils::width_bytes_to_dwords(width_bytes);
    la_entry_width_t total_width_dwords = count * width_dwords;

    // EXPORT requires the start offset and dwords count both to be even
    if (m_data_pos % 2 != 0) {
        ++m_data_pos;
    }

    if (total_width_dwords % 2 != 0) {
        ++total_width_dwords;
    }

    la_status rc = make_room(1 /* count */, total_width_dwords);
    return_on_error(rc);

    // Encode READ command and write to access engine command buffer
    mem_cmd cmd = {{0}};
    cmd.read_to_buffer.opcode = (uint32_t)mem_cmd::opcode_e::READ;
    cmd.read_to_buffer.buff_addr = m_data_pos;
    cmd.read_to_buffer.rd_not_clr = peek;
    cmd.read_to_buffer.length = width_dwords;
    cmd.read_to_buffer.count = count;
    cmd.read_to_buffer.block_id = block_id;
    cmd.read_to_buffer.addr = addr;
    encode(cmd);

    read_cookie = m_data_pos;
    m_data_pos += total_width_dwords;

    log_debug(AE,
              "%s: ae[%d]: block_id 0x%x, addr 0x%x, width_bytes 0x%x, count 0x%lx, (cookie)data_pos 0x%x",
              __func__,
              m_engine_id,
              block_id,
              addr,
              width_bytes,
              count,
              read_cookie);

    return LA_STATUS_SUCCESS;
}

la_status
access_engine::write(la_block_id_t block_id, la_entry_addr_t addr, la_entry_width_t width_bytes, size_t count, const void* in_val)
{
    // TODO: check access engine state

    if (width_bytes <= 4) {
        return write_immediate(block_id, addr, width_bytes, count, in_val);
    }

    la_entry_width_t width_dwords = bit_utils::width_bytes_to_dwords(width_bytes);
    la_entry_width_t width_aligned = width_dwords << 2;
    int commands_count = m_dma_desc.virt_addr ? count * 2 : count;
    la_status rc = make_room(commands_count, count * width_dwords);
    if (rc) {
        return rc;
    }

    log_debug(AE,
              "%s: ae[%hd]: block_id=0x%x, addr=0x%x, bytes=0x%x, dwords=0x%x, count=0x%lx, data_pos=0x%x",
              __func__,
              m_engine_id,
              block_id,
              addr,
              width_bytes,
              width_dwords,
              count,
              m_data_pos);

    // Encode WRITE command and write to access engine command buffer
    uint8_t* p = (uint8_t*)in_val;
    uint8_t* dma_va = (uint8_t*)m_dma_desc.virt_addr + (m_data_pos << 2);
    uint64_t dma_pa = m_dma_desc.phys_addr + (m_data_pos << 2);

    for (size_t i = 0; i < count; ++i) {
        mem_cmd cmd;

        // Copy data to AE data memory, use either IMPORT or write directly
        // The input buffer is assumed to have DWORD aligned storage (the actual bytes count does not have to be DWORD aligned).
        if (m_dma_desc.virt_addr) {
            memcpy(dma_va, p, width_aligned);

            // IMPORT command DMAs data from host to AE data memory.
            bzero(&cmd, sizeof(cmd));
            cmd.importcmd.opcode = (uint32_t)mem_cmd::opcode_e::IMPORT;
            cmd.importcmd.remote_addr = 1; // host (not ARC)
            cmd.importcmd.buff_addr = m_data_pos;
            cmd.importcmd.length = width_dwords;
            cmd.importcmd.upper_addr = dma_pa >> 32;
            cmd.importcmd.addr = dma_pa & 0xffffffff;
            encode(cmd);
        } else {
            m_ll_device->sbif_write_memory_entries(m_data_mem_addr, m_data_pos, width_dwords, (const uint32_t*)p);
        }

        // WRITE command
        bzero(&cmd, sizeof(cmd));
        cmd.write_from_buffer.opcode = (uint32_t)mem_cmd::opcode_e::WRITE;
        cmd.write_from_buffer.buff_addr = m_data_pos;
        cmd.write_from_buffer.length = width_dwords;
        cmd.write_from_buffer.count = 1;
        cmd.write_from_buffer.block_id = block_id;
        cmd.write_from_buffer.addr = addr;
        encode(cmd);

        ++addr;                     // destination address of LBR register/memory
        m_data_pos += width_dwords; // index of next available DWORD in AE data memory
        p += width_bytes;           // input pointer, incremented by the entry width in bytes
        dma_va += width_aligned;    // device pointer, incremented entry width in bytes aligned to DWORD boundary
        dma_pa += width_aligned;    // device pointer, incremented entry width in bytes aligned to DWORD boundary
    }

    return LA_STATUS_SUCCESS;
}

la_status
access_engine::write_fill(la_block_id_t block_id,
                          la_entry_addr_t addr,
                          la_entry_width_t width_bytes,
                          size_t count,
                          const void* in_val)
{
    la_entry_width_t width_dwords = bit_utils::width_bytes_to_dwords(width_bytes);
    size_t chunk_count = std::min(count, (size_t)m_data_mem_entries / width_dwords);

    log_debug(AE,
              "%s: ae[%hd]: block_id=0x%x, addr=0x%x, bytes=0x%x, dwords=0x%x, chunk_count=0x%lx, count=0x%lx",
              __func__,
              m_engine_id,
              block_id,
              addr,
              width_bytes,
              width_dwords,
              chunk_count,
              count);

    la_status rc = flush();
    return_on_error(rc);

    // After flush(), AE is idle and m_data_pos==m_cmd_pos==0

    mem_cmd cmd;
    // Fill the data memory starting at m_data_pos==0, replicate 'in_val' chunk_count times.
    if (m_dma_desc.virt_addr) {
        // We just flushed, no need to make_room()

        uint8_t* dma_va = (uint8_t*)m_dma_desc.virt_addr;
        uint64_t dma_pa = m_dma_desc.phys_addr;

        la_entry_width_t width_aligned = width_dwords << 2;
        for (size_t pos = m_data_pos; pos < width_aligned * chunk_count; pos += width_aligned) {
            memcpy(dma_va + pos, in_val, width_aligned);
        }

        bzero(&cmd, sizeof(cmd));
        cmd.importcmd.opcode = (uint32_t)mem_cmd::opcode_e::IMPORT;
        cmd.importcmd.remote_addr = 1; // host (not ARC)
        cmd.importcmd.buff_addr = 0;   // m_data_pos==0
        cmd.importcmd.length = m_data_mem_entries;
        cmd.importcmd.upper_addr = dma_pa >> 32;
        cmd.importcmd.addr = dma_pa & 0xffffffff;

        encode(cmd);
    } else {
        for (size_t pos = m_data_pos; pos < width_dwords * chunk_count; pos += width_dwords) {
            m_ll_device->sbif_write_memory_entries(m_data_mem_addr, pos, width_dwords, (const uint32_t*)in_val);
        }
    }

    // Most of the fields of write_from_buffer are fixed.
    bzero(&cmd, sizeof(cmd));
    cmd.write_from_buffer.opcode = (uint32_t)mem_cmd::opcode_e::WRITE;
    cmd.write_from_buffer.buff_addr = m_data_pos;
    cmd.write_from_buffer.length = width_dwords;
    cmd.write_from_buffer.count = chunk_count;
    cmd.write_from_buffer.block_id = block_id;

    m_data_pos += width_dwords * chunk_count;

    // Write chunks
    la_entry_addr_t addr_end = addr + count;
    for (; addr < addr_end; addr += chunk_count) {
        rc = make_room(1 /* count */);
        if (rc) {
            log_err(AE, "%s: make_room failed, addr=0x%x, chunk_count=%ld, count=%ld", __func__, addr, chunk_count, count);
            return rc;
        }

        cmd.write_from_buffer.addr = addr;
        cmd.write_from_buffer.count = std::min(chunk_count, (size_t)(addr_end - addr));
        encode(cmd);
    }

    return LA_STATUS_SUCCESS;
}

la_status
access_engine::write_immediate(la_block_id_t block_id,
                               la_entry_addr_t addr,
                               la_entry_width_t width_bytes,
                               size_t count,
                               const void* in_val)
{
    // TODO: check access engine state
    la_status rc = make_room(count);
    if (rc) {
        return rc;
    }

    // Encode IMMEDIATE_WRITE command and write to access engine command buffer
    uint8_t* p = (uint8_t*)in_val;
    for (size_t i = 0; i < count; ++i, p += width_bytes, ++addr) {
        uint32_t val = 0;
        memcpy(&val, p, width_bytes);
        log_debug(AE,
                  "%s: ae[%hd]: block_id=0x%x, addr=0x%x, val=0x%x, width_bytes=0x%x",
                  __func__,
                  m_engine_id,
                  block_id,
                  addr,
                  val,
                  width_bytes);

        mem_cmd cmd = {{0}};
        cmd.immediate_write.opcode = (uint32_t)mem_cmd::opcode_e::IMMEDIATE_WRITE;
        cmd.immediate_write.value_high = val >> 20;    // higher 12 bits
        cmd.immediate_write.value_low = val & 0xfffff; // lower 20 bits
        cmd.immediate_write.block_id = block_id;
        cmd.immediate_write.addr = addr;
        encode(cmd);
    }

    return LA_STATUS_SUCCESS;
}

la_status
access_engine::wait_for_value(la_block_id_t block_id,
                              la_entry_addr_t addr,
                              bool equal,
                              uint8_t poll_cnt,
                              uint16_t val,
                              uint16_t mask)
{
    // TODO: check access engine state

    la_status rc = make_room(1 /* count */);
    if (rc) {
        return rc;
    }

    log_debug(AE,
              "%s: block_id 0x%x, addr 0x%x, equal %d, poll_cnt %d, val 0x%x, mask 0x%x",
              __func__,
              block_id,
              addr,
              equal,
              poll_cnt,
              val,
              mask);

    mem_cmd cmd = {{0}};
    cmd.wait_for_value.opcode = (uint32_t)mem_cmd::opcode_e::WAIT_FOR_VALUE;
    cmd.wait_for_value.equal = equal;
    cmd.wait_for_value.interrupt = 0;
    cmd.wait_for_value.poll_cnt = poll_cnt;
    cmd.wait_for_value.value_high = val >> 4; // higher 12 bits
    cmd.wait_for_value.value_low = val & 0xf; // lower 4 bits
    cmd.wait_for_value.mask = mask;
    cmd.wait_for_value.block_id = block_id;
    cmd.wait_for_value.addr = addr;
    encode(cmd);

    rc = wait_completion();
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
access_engine::delay(uint64_t cycles)
{
    if (cycles == 0) {
        return LA_STATUS_SUCCESS;
    }

    la_status rc = make_room(1 /* count */);
    if (rc) {
        return rc;
    }

    log_debug(AE, "%s: cycles 0x%lx", __func__, cycles);

    mem_cmd cmd = {{0}};
    cmd.delay.opcode = (uint32_t)mem_cmd::opcode_e::DELAY;
    cmd.delay.interrupt = 0;
    cmd.delay.delay_count_high = cycles >> 32;
    cmd.delay.delay_count_low = (uint32_t)cycles;
    encode(cmd);

    return LA_STATUS_SUCCESS;
}

la_status
access_engine::acquire_semaphore(uint8_t sem_index)
{
    return semaphore((uint32_t)mem_cmd::opcode_e::ACQUIRE_SEMAPHORE, sem_index);
}

la_status
access_engine::release_semaphore(uint8_t sem_index)
{
    return semaphore((uint32_t)mem_cmd::opcode_e::RELEASE_SEMAPHORE, sem_index);
}

la_status
access_engine::semaphore(uint32_t op, uint8_t sem_index)
{
    la_status rc = make_room(1 /* count */);
    if (rc) {
        return rc;
    }

    log_debug(AE, "%s: op %d, sem_index 0x%x", __func__, (int)op, sem_index);

    if (sem_index > 63) {
        log_err(AE, "%s: op %d, sem_index 0x%x is out of range", __func__, (int)op, sem_index);
        return LA_STATUS_EOUTOFRANGE;
    }

    mem_cmd cmd = {{0}};
    cmd.acquire_semaphore.opcode = (uint32_t)op;
    cmd.acquire_semaphore.index = sem_index;
    encode(cmd);

    return LA_STATUS_SUCCESS;
}

void
access_engine::restart_failed_command()
{
    reg_cmd_ptr cmd_ptr = {};

    m_ll_device->sbif_read_register(m_cmd_ptr_reg_addr, &cmd_ptr.dword);
    cmd_ptr.fields.fifo_r = (cmd_ptr.fields.fifo_r - 3) & 0x3ff;
    m_ll_device->sbif_write_register(m_cmd_ptr_reg_addr, cmd_ptr.dword);

    go();
}
