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

#include "arc_handler_base.h"
#include "hld_utils.h"
#include "lld/gibraltar_tree.h"
#include "lld/pacific_tree.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

static const char DEFAULT_CSS_ARC_MICROCODE_FILE[] = "res/firmware_css_iccm.bin";
static const char CSS_ARC_MICROCODE_FILE_ENVVAR[] = "CSS_ARC_MICROCODE_FILE";

arc_handler_base::arc_handler_base(const la_device_impl_wptr& device) : m_device(device), m_arc_enabled(false)
{
}

arc_handler_base::~arc_handler_base()
{
}

size_t
arc_handler_base::calc_arc_memory_index(arc_msg_offset_type_e msg_location)
{
    size_t mem_index = 0;

    switch (msg_location) {
    case ARC_TO_CPU_CMD_READ_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, to_cpu.cmd_read));
        break;
    case ARC_TO_CPU_CMD_WRITE_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, to_cpu.cmd_write));
        break;
    case ARC_TO_CPU_MSG_READ_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, to_cpu.msg_read));
        break;
    case ARC_TO_CPU_MSG_WRITE_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, to_cpu.msg_write));
        break;
    case ARC_TO_CPU_CMD_QUEUE_START_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, to_cpu.commands));
        break;
    case ARC_TO_CPU_MSG_QUEUE_START_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, to_cpu.msg_buffer));
        break;
    case ARC_FROM_CPU_CMD_READ_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, from_cpu.cmd_read));
        break;
    case ARC_FROM_CPU_CMD_WRITE_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, from_cpu.cmd_write));
        break;
    case ARC_FROM_CPU_MSG_READ_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, from_cpu.msg_read));
        break;
    case ARC_FROM_CPU_MSG_WRITE_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, from_cpu.msg_write));
        break;
    case ARC_FROM_CPU_CMD_QUEUE_START_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, from_cpu.commands));
        break;
    case ARC_FROM_CPU_MSG_QUEUE_START_OFFSET:
        mem_index = (offsetof(css_arc_mem_t, from_cpu.msg_buffer));
        break;
    }
    return mem_index;
}

size_t
arc_handler_base::calc_arc_offset(uint8_t arc_id, arc_msg_offset_type_e msg_location, size_t offset)
{
    offset += calc_arc_memory_index(msg_location);
    offset += (size_t)silicon_one::la_css_memory_layout_e::ARC_SCRATCH + arc_id * sizeof(css_arc_mem_t);
    // Return the line offset
    return offset / 4;
}

la_status
arc_handler_base::read_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, uint8_t* data, size_t size)
{
    return read_arc_data(arc_id, msg_location, 0 /* offset */, data, size);
}

la_status
arc_handler_base::read_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, size_t offset, uint8_t* data, size_t size)
{
    offset = calc_arc_offset(arc_id, msg_location, offset);
    return m_device->m_ll_device->read_memory(*(get_mem_ptr()), offset, size / 4, size, data);
}

la_status
arc_handler_base::write_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, uint8_t* data, size_t size)
{
    return write_arc_data(arc_id, msg_location, 0 /* offset */, data, size);
}

la_status
arc_handler_base::write_arc_data(uint8_t arc_id, arc_msg_offset_type_e msg_location, size_t offset, uint8_t* data, size_t size)
{
    offset = calc_arc_offset(arc_id, msg_location, offset);
    return m_device->m_ll_device->write_memory(*(get_mem_ptr()), offset, size / 4, size, data);
}

la_status
arc_handler_base::read_arc_msg_data(uint8_t arc_id, bit_vector& bv, size_t size)
{
    uint32_t msg_read;

    if ((size % 4) != 0) {
        log_err(LLD, "ARC message size not a multiple of 4B - size=%zd", size);
        return LA_STATUS_EINVAL;
    }

    // Read the msg read ptr.
    read_arc_data(arc_id, ARC_TO_CPU_MSG_READ_OFFSET, (uint8_t*)&msg_read, sizeof(msg_read));

    // resize the bit vector to the size of the message.
    bv.resize(size * bit_vector::BV_BITS_IN_BYTE);

    uint64_t data;
    size_t start_bit = 0;
    for (size_t bytes = 0; bytes < size; bytes += 4) {
        read_arc_data(arc_id, ARC_TO_CPU_MSG_QUEUE_START_OFFSET, msg_read, (uint8_t*)&data, 4);
        bv.set_bits(start_bit + 31, start_bit, data);
        start_bit += 32;
        msg_read += 4;
        if (msg_read >= CMD_MSG_BUF_SIZE) {
            msg_read = 0;
        }
    }

    // write the msg_read ptr back to CSS
    write_arc_data(arc_id, ARC_TO_CPU_MSG_READ_OFFSET, (uint8_t*)&msg_read, sizeof(msg_read));

    return LA_STATUS_SUCCESS;
}

la_status
arc_handler_base::write_arc_msg_data(uint8_t arc_id, uint8_t* data, size_t length)
{
    uint32_t msg_read;
    uint32_t msg_write;
    uint32_t free_msg_bytes;

    if (length == 0) {
        // Nothing to do
        return LA_STATUS_SUCCESS;
    }

    // Only handle messages that have length in multiples of 4B.
    if ((length % 4) != 0) {
        log_err(LLD, "ARC message length not a multiple of 4B - length=%zd", length);
        return LA_STATUS_EINVAL;
    }

    // Read the msg read ptr.
    read_arc_data(arc_id, ARC_FROM_CPU_MSG_READ_OFFSET, (uint8_t*)&msg_read, sizeof(msg_read));

    // Read the msg write ptr.
    read_arc_data(arc_id, ARC_FROM_CPU_MSG_WRITE_OFFSET, (uint8_t*)&msg_write, sizeof(msg_write));

    // ensure there is enough space in the message buffer
    if (msg_read == msg_write) {
        free_msg_bytes = CMD_MSG_BUF_SIZE;
    } else if (msg_read > msg_write) {
        free_msg_bytes = msg_read - msg_write; // in bytes
    } else {
        free_msg_bytes = (CMD_MSG_BUF_SIZE - msg_write) + msg_read;
    }

    if (length > free_msg_bytes) {
        log_err(LLD, "ARC message Not enough room in message buffer free space=%d", free_msg_bytes);
        return LA_STATUS_ERESOURCE;
    }

    // copy the message to the CSS message buffer
    if (msg_write + length >= CMD_MSG_BUF_SIZE) {
        // Handle the wrap case.
        uint32_t wrap_bytes = ((msg_write + length) - CMD_MSG_BUF_SIZE);
        write_arc_data(arc_id, ARC_FROM_CPU_MSG_QUEUE_START_OFFSET, msg_write, data, (length - wrap_bytes));
        if (wrap_bytes != 0) {
            write_arc_data(arc_id, ARC_FROM_CPU_MSG_QUEUE_START_OFFSET, data + (length - wrap_bytes), wrap_bytes);
        }
        msg_write = wrap_bytes;
    } else {
        write_arc_data(arc_id, ARC_FROM_CPU_MSG_QUEUE_START_OFFSET, msg_write, data, length);
        msg_write += length;
    }

    // write the msg_read ptr back to CSS
    write_arc_data(arc_id, ARC_FROM_CPU_MSG_WRITE_OFFSET, (uint8_t*)&msg_write, sizeof(msg_write));

    return LA_STATUS_SUCCESS;
}

std::vector<bit_vector>
arc_handler_base::collect_arc_events(uint8_t arc_id)
{

    if (!m_arc_enabled) {
        return {};
    }

    // Read the cmd and msg ptrs.
    uint32_t cmd_read;
    uint32_t cmd_write;

    read_arc_data(arc_id, ARC_TO_CPU_CMD_READ_OFFSET, (uint8_t*)&cmd_read, sizeof(cmd_read));
    read_arc_data(arc_id, ARC_TO_CPU_CMD_WRITE_OFFSET, (uint8_t*)&cmd_write, sizeof(cmd_write));

    // Do a sanity check on the read/write ptrs
    if ((cmd_read >= CMD_QUEUE_SIZE) || (cmd_write >= CMD_QUEUE_SIZE)) {
        return {};
    }

    if (cmd_read == cmd_write) {
        // Pointers equal, nothing to do.
        return {};
    }

    std::vector<bit_vector> events;
    while (cmd_read != cmd_write) {
        CMD_INDEX_INCR(cmd_read);

        arc_cmd_t cmd;
        read_arc_data(arc_id, ARC_TO_CPU_CMD_QUEUE_START_OFFSET, cmd_read * sizeof(cmd), (uint8_t*)&cmd, sizeof(cmd));

        if (cmd.msg_length) {
            bit_vector bv;
            read_arc_msg_data(arc_id, bv, cmd.msg_length);
            events.push_back(std::move(bv));
        }
    }

    // Update the read_ptrs
    write_arc_data(arc_id, ARC_TO_CPU_CMD_READ_OFFSET, (uint8_t*)&cmd_read, sizeof(cmd_read));

    return events;
}

la_status
arc_handler_base::arc_send_from_cpu_msg(uint8_t arc_id, arc_cmd_type_e type, size_t length, uint8_t* msg)
{
    la_status status;

    if (!m_arc_enabled) {
        return LA_STATUS_ENOTINITIALIZED;
    }

    if (length > ARC_FROM_CPU_MAX_MSG_LENGTH) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // Read the cmd ptrs.
    uint32_t cmd_read;
    uint32_t cmd_write;

    read_arc_data(arc_id, ARC_FROM_CPU_CMD_READ_OFFSET, (uint8_t*)&cmd_read, sizeof(cmd_read));
    read_arc_data(arc_id, ARC_FROM_CPU_CMD_WRITE_OFFSET, (uint8_t*)&cmd_write, sizeof(cmd_write));

    CMD_INDEX_INCR(cmd_write);

    // ensure there is enough space in the command queue
    if (cmd_write == cmd_read) {
        // the command queue is full
        log_err(LLD, "ARC message Not enough room in cmd buffer - cmd_write=%d", cmd_write);
        return LA_STATUS_ERESOURCE;
    }

    // write the message to the message queue.
    status = write_arc_msg_data(arc_id, msg, length);
    return_on_error(status);

    // setup the command
    arc_cmd_t cmd;
    cmd.type = type;
    cmd.msg_length = length;

    // write the command to cmd queue.
    write_arc_data(arc_id, ARC_FROM_CPU_CMD_QUEUE_START_OFFSET, cmd_write * sizeof(cmd), (uint8_t*)&cmd, sizeof(cmd));

    // write the cmd write ptr
    write_arc_data(arc_id, ARC_FROM_CPU_CMD_WRITE_OFFSET, (uint8_t*)&cmd_write, sizeof(cmd_write));

    return LA_STATUS_SUCCESS;
}

la_status
arc_handler_base::configure_css_arc_cpus()
{
    la_status status;

    // Reset the ARC CPUs
    status = m_device->m_ll_device->reset_css_arcs();
    return_on_error(status);

    // Load the ARC CPU firmware
    std::string filename = find_resource_file(CSS_ARC_MICROCODE_FILE_ENVVAR, DEFAULT_CSS_ARC_MICROCODE_FILE);
    status = m_device->m_ll_device->load_css_arc_microcode(filename);
    return_on_error(status);

    // Start the ARC CPUs
    status = m_device->m_ll_device->start_css_arcs();
    return_on_error(status);

    m_arc_enabled = true;

    return LA_STATUS_SUCCESS;
}

la_status
arc_handler_base::reset_arc_cpus()
{
    la_status status;

    // Stop the ARC CPUs
    status = m_device->m_ll_device->stop_css_arcs();
    return_on_error(status);

    // Reset the ARC CPUs
    status = m_device->m_ll_device->reset_css_arcs();
    return_on_error(status);

    m_arc_enabled = false;

    return LA_STATUS_SUCCESS;
}
}
