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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lld_conn_lib.h"

#if 0
// Safe string-to-short conversion
static int str2port(const char *str, uint16_t *port)
{
    char *end;
    long i = strtol(str, &end, 10);

    if ((str == end) || (i == 0) || (i > 0xffff))
        return -1;

    *port = (uint16_t)i;
    return 0;
}
#endif

static void
int_handler(uint64_t data)
{
    printf("%s: 0x%lx\n", __func__, data);
}

typedef union {
    uint8_t bytes[LLD_COMMAND_MAX_DATA_LEN];
    uint16_t word;
    uint32_t dword;
    uint64_t qword;
} reg_mem_data_t;

typedef struct reg_mem {
    uint16_t block_id;
    uint32_t addr;
    uint32_t width_bits;
    reg_mem_data_t data;
} reg_mem_t;

// Test emulates the driver side
int
test_lld_driver(lld_conn_h h)
{
    int err = -1;
    size_t i;
    reg_mem_t *r,
        regs[] = {{// Block: SCH, Block index: 7, Reg name: DebugGrantCfg, Size: 34 bits
                   .block_id = (3 << 6) | 8,
                   .addr = 0x197,
                   .width_bits = 34,
                   .data = {.bytes = {0x12, 0x34, 0x56, 0x78, 0x3}}},
                  {// Block: SCH, Block index: 6, Mem name: VscTokenBucketCfg, Size: 25 bits
                   .block_id = (3 << 6) | 7,
                   .addr = 0x400000,
                   .width_bits = 25,
                   .data = {.bytes = {0xba, 0xdc, 0xfe, 0x1}}}};

    printf("driver: start interrupt thread\n");
    lld_conn_start_interrupt_thread(h, int_handler);

    // Test - fire a few R/W commands
    for (r = regs, i = 0; i < sizeof(regs) / sizeof(regs[0]); i++, r++) {
        reg_mem_data_t data = {};
        uint32_t nbytes = (r->width_bits + 7) / 8; // byte count, rounded up
        uint64_t addr = ((uint64_t)r->block_id << 32) | r->addr;

        printf("driver: write, addr 0x%hx:0x%x, size %u\n", r->block_id, r->addr, nbytes);
        if ((err = lld_conn_write_regmem(h, addr, r->data.bytes, nbytes))) {
            break;
        }

        printf("driver: read, addr 0x%hx:0x%x, size %u\n", r->block_id, r->addr, nbytes);
        if ((err = lld_conn_read_regmem(h, addr, data.bytes, nbytes))) {
            break;
        }

        if (r->data.qword != data.qword) {
            err = -1;
            printf("R/W ERROR: got/expected 0x%lx/0x%lx\n", data.qword, r->data.qword);
            break;
        }

        printf("R/W OK: data 0x%lx\n", data.qword);
    }

    if (!err) {
        printf("driver: wait a bit for more interrupts (if any).\n");
        sleep(3 /* seconds */);
    }

    return err;
}

#ifdef LLD_TEST_STANDALONE
int
main(int argc, char* argv[])
{
    lld_conn_h h;
    bool as_server = false;
    int err;

    if (argc == 1) {
        as_server = false;
    } else if (argc == 3 && strcmp(argv[1], "--as_server") == 0) {
        as_server = !!atoi(argv[2]);
    } else if (argc > 2) {
        fprintf(stderr, "USAGE: %s [--as_server <0|1>]\n", argv[0]);
        return -1;
    }

    if (as_server) {
        printf("driver: create server and wait for connection\n");
        h = lld_server_create(7474, 7475);
    } else {
        printf("driver: connect as a client\n");
        h = lld_client_connect("localhost", 7474, 7475);
    }
    if (!h) {
        return -1;
    }

    do {
        if (as_server) {
            printf("driver: wait for connection\n");
            if (lld_server_wait_conn(h) < 0)
                continue;
        }

        printf("driver: connected\n");
        err = test_lld_driver(h);
    } while (as_server);

    printf("driver: disconnect\n");
    lld_conn_destroy(h);
    printf("driver: done, test %s\n", err ? "ERROR" : "OK");

    return err;
}
#endif
