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

#include <inttypes.h>
#include <map>
#include <stdio.h>
#include <string.h>

#include "lld_conn_lib.h"

typedef struct lld_data {
    uint8_t bytes[LLD_COMMAND_MAX_DATA_LEN];
} lld_data_t;

// Test emulates the device side
int
test_lld_device(lld_conn_h h)
{
    std::map<uint64_t, lld_data_t> memory;
    std::map<uint64_t, lld_data_t>::iterator memory_it;

    printf("device: firing a few interrupts\n");
    for (int i = 0; i < 10; i++) {
        lld_conn_send_interrupt(h, 1 << i);
    }

    while (1) {
        char cmd;
        uint64_t addr;
        lld_data_t data = {{0}};
        uint32_t data_sz = -1;

        printf("device: waiting for command\n");
        if (lld_conn_recv_command(h, &cmd, &addr, data.bytes, &data_sz) < 0) {
            fprintf(stderr, "device: failed to receive a command\n");
            break;
        }
        if (data_sz > sizeof(data)) {
            printf("device: bad size %u\n", data_sz);
            break;
        }

        printf("device: cmd %c, addr 0x%lx, size %u\n", cmd, addr, data_sz);

        switch (cmd) {
        case 'W':
            memory[addr] = data;
            break;
        case 'R':
            memory_it = memory.find(addr);
            if (memory_it == memory.end()) {
                printf("device: read miss\n");
            } else {
                printf("device: read hit\n");
                data = memory_it->second;
            }
            lld_conn_send_response(h, cmd, addr, data.bytes, data_sz);
            break;
        default:
            fprintf(stderr, "device: bad command 0x%x\n", cmd);
            break;
        }
    }

    return 0;
}

#ifdef LLD_TEST_STANDALONE
int
main(int argc, char** argv)
{
    lld_conn_h h;
    bool as_server = true;

    if (argc == 1) {
        as_server = true;
    } else if (argc == 3 && strcmp(argv[1], "--as_server") == 0) {
        as_server = !!atoi(argv[2]);
    } else if (argc > 2) {
        fprintf(stderr, "USAGE: %s [--as_server <0|1>]\n", argv[0]);
        return -1;
    }

    if (as_server) {
        printf("device: create server\n");
        h = lld_server_create(7474, 7475);
    } else {
        printf("device: connect as a client\n");
        h = lld_client_connect("localhost", 7474, 7475);
    }
    if (!h) {
        return -1;
    }

    // If server - loop for ever, if client - run once
    do {
        if (as_server) {
            printf("device: wait for connection\n");
            if (lld_server_wait_conn(h) < 0)
                continue;
        }

        printf("device: connected\n");
        test_lld_device(h);
    } while (as_server);

    printf("device: disconnect\n");
    lld_conn_destroy(h);
    printf("device: done\n");

    return 0;
}
#endif
