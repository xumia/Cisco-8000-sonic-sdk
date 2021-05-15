// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "arc_command_queue.h"
#include "arc_types.h"

#define ALIGN(_v, _a) (((_v) + (_a)-1) & ~((_a)-1))

void
arc_command_receive(arc_context_t* ctx)
{
    uint32_t cmd_read = ctx->css->from_cpu.cmd_read;
    uint32_t cmd_write = ctx->css->from_cpu.cmd_write;
    uint8_t msg[ARC_FROM_CPU_MAX_MSG_LENGTH];

    // this is not a while() loop as we only process 1 message per run loop
    if (cmd_read == cmd_write) {
        // Nothing to do
        return;
    }

    CMD_INDEX_INCR(cmd_read);
    arc_cmd_t cmd;

    // copy the command to the stack
    _vsmemcpy(&cmd, &(ctx->css->from_cpu.commands[cmd_read]), sizeof(cmd));

    dbg_count(ctx, ARC_DBG_CMD_RCV_COUNT);

    // if there is a message portion copy it
    if (cmd.msg_length > 0) {
        uint32_t msg_read = ctx->css->from_cpu.msg_read;
        css_ptr_t msg_start = &(ctx->css->from_cpu.msg_buffer[msg_read]);

        // Align the length to a 4B alignment.
        uint32_t length = ALIGN(cmd.msg_length, 4);

        // Adjust msg_read ptr
        uint32_t wrap_bytes = 0;
        if (msg_read + length > CMD_MSG_BUF_SIZE) {
            wrap_bytes = ((msg_read + length) - CMD_MSG_BUF_SIZE);
        } else {
            msg_read += length;
        }

        if (length > ARC_FROM_CPU_MAX_MSG_LENGTH) {
            dbg_count(ctx, ARC_DBG_CMD_MSG_TOO_BIG);
            // write the msg_read back to CSS
            ctx->css->from_cpu.msg_read = msg_read;

            // write the read index back to css
            ctx->css->from_cpu.cmd_read = cmd_read;
            return;
        }

        if (wrap_bytes != 0) {
            _vsmemcpy(msg, msg_start, (length - wrap_bytes));
            _vsmemcpy(msg + (length - wrap_bytes), msg_start + (length - wrap_bytes), wrap_bytes);
        } else {
            _vsmemcpy(msg, msg_start, length);
        }

        // write the msg_read back to CSS
        ctx->css->from_cpu.msg_read = msg_read;
    }

    // write the read index back to css
    ctx->css->from_cpu.cmd_read = cmd_read;

    // search all the command callbacks for this message type
    uint32_t found = 0;
    uint32_t i;
    for (i = 0; i < ctx->command_callbacks_count; i++) {
        if (cmd.type == ctx->command_callbacks[i].type) {
            ctx->command_callbacks[i].callback_fn(ctx, msg, cmd.msg_length);
            found = 1;
        }
    }
    if (!found) {
        dbg_count(ctx, ARC_DBG_CMD_RCV_OUT_OF_RANGE);
    }
}

int
arc_command_send(arc_context_t* ctx, uint16_t type, void* msg, uint16_t length)
{
    uint32_t cmd_read = ctx->css->to_cpu.cmd_read;
    uint32_t cmd_write = ctx->css->to_cpu.cmd_write;
    uint32_t msg_read = ctx->css->to_cpu.msg_read;
    uint32_t msg_write = ctx->css->to_cpu.msg_write;
    uint32_t free_msg_bytes;

    CMD_INDEX_INCR(cmd_write);
    // ensure there is enough space in the command queue
    if (cmd_write == cmd_read) {
        // the command queue is full
        dbg_count(ctx, ARC_DBG_CMD_SND_QUEUE_FULL);
        return -1;
    }

    // ensure there is enough space in the message buffer
    if (msg_read == msg_write) {
        free_msg_bytes = CMD_MSG_BUF_SIZE;
    } else if (msg_read > msg_write) {
        free_msg_bytes = msg_read - msg_write; // in bytes
    } else {
        free_msg_bytes = (CMD_MSG_BUF_SIZE - msg_write) + msg_read;
    }
    if (length > free_msg_bytes) {
        dbg_count(ctx, ARC_DBG_CMD_SND_MSG_BUF_FULL);
        return -1;
    }

    // setup the command
    volatile _Uncached arc_cmd_t* cmd = &ctx->css->to_cpu.commands[cmd_write];
    cmd->type = type;

    // Make sure msg length is aligned to 4B
    length = ALIGN(length, 4);
    cmd->msg_length = length;

    // copy the message to the CSS message buffer
    if (length > 0) {
        css_ptr_t msg_start = &(ctx->css->to_cpu.msg_buffer[msg_write]);
        if (msg_write + length >= CMD_MSG_BUF_SIZE) {
            uint32_t wrap_bytes = ((msg_write + length) - CMD_MSG_BUF_SIZE);
            _vdmemcpy(msg_start, msg, (length - wrap_bytes));
            if (wrap_bytes != 0) {
                _vdmemcpy(msg_start + (length - wrap_bytes), (uint8_t*)msg + (length - wrap_bytes), wrap_bytes);
            }
            msg_write = wrap_bytes;
        } else {
            _vdmemcpy(msg_start, msg, length);
            msg_write += length;
        }

        // update the message buffer write pointer in CSS
        ctx->css->to_cpu.msg_write = msg_write;
    }

    // update the command queue write pointer in CSS
    ctx->css->to_cpu.cmd_write = cmd_write;

    return 0;
}
