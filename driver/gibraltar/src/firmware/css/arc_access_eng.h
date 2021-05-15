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

#ifndef __ARC_ACCESS_ENG_H__
#define __ARC_ACCESS_ENG_H__

#include <stdint.h>

#include "arc_types.h"

// error codes
typedef enum {
    ERR_OK = 0,
    ERR_ACCESS_ENGINE = 1,
} ae_error_t;

typedef struct memory_info_ {
    uint32_t block_id;
    uint32_t address;
    uint32_t width;
} memory_info_t;

typedef struct npu_host_memory_ {
    memory_info_t eth_mp_em_access_register;
    memory_info_t eth_mp_em_response_register;
    memory_info_t evq_counters;
    memory_info_t cpu_q_config_read_adress;
    memory_info_t cpu_q_config_write_adress;
    memory_info_t event_queue;
} npu_host_memory_t;

typedef struct asic_memory_info_ {
    npu_host_memory_t npuh;
} asic_memory_info_t;

extern asic_memory_info_t pacific_tree;

void ae_reset(arc_context_t* ctx);
void ae_init_ptrs(arc_context_t* ctx, uint32_t access_engine_id);
ae_error_t ae_read_memory(arc_context_t* ctx, memory_info_t* info, uint32_t offset, uint32_t* data);
ae_error_t ae_read_register(arc_context_t* ctx, memory_info_t* info, uint32_t* data);

ae_error_t ae_write_memory(arc_context_t* ctx, memory_info_t* info, uint32_t offset, uint32_t* data);
ae_error_t ae_write_register(arc_context_t* ctx, memory_info_t* info, uint32_t* data);

#endif // __ARC_ACCESS_ENG_H__
