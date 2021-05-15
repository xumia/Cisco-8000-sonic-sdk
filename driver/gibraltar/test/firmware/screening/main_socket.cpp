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
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lld_conn_lib.h"
#include "screening.h"

// Externals symbols, used by screening.cpp and spi_flash.cpp
int scr_debug_level = DEBUG_LEVEL_ERROR;
platform_ops ops;

// Local symbols
static int ops_fd;
static lld_conn_h lld_conn;

static inline uint64_t
sbif_addr(uint32_t addr)
{
    return (((uint64_t)707) << 32) | // sbif block id
           (1 << 24) |               // bit 24 marks sbif reg/mem (this is bit would be 0 for CSS reg/mem)
           addr;
}

int
platform_ops::sbif_write_dword(uint32_t addr, uint32_t val_dword)
{
    LOG_D("%s: addr=0x%x, val=0x%x\n", __func__, addr, val_dword);
    return lld_conn_write_regmem(lld_conn, sbif_addr(addr), &val_dword, 4 /* data_sz */);
}

// In RTL, sbif is dword addressable (step 1).
// But in silicon this should be 4, i.e. byte addressable.
#define RTL_SBIF_MEMORY_STEP 1
int
platform_ops::sbif_write_dwords(uint32_t addr, uint32_t val_dwords_n, const uint32_t* val_dwords)
{
    int err = 0;
    for (size_t i = 0; (i < val_dwords_n) && !err; ++i, addr += RTL_SBIF_MEMORY_STEP, ++val_dwords) {
        err = sbif_write_dword(addr, *val_dwords);
    }
    return err;
}

int
platform_ops::sbif_read_dword(uint32_t addr, uint32_t* val_dword)
{
    int rc = lld_conn_read_regmem(lld_conn, sbif_addr(addr), val_dword, 4 /* data_sz */);
    LOG_D("%s: addr=0x%x, val=0x%x\n", __func__, addr, *val_dword);
    return rc;
}

int
platform_ops::sbif_read_dwords(uint32_t addr, uint32_t val_dwords_n, uint32_t* val_dwords)
{
    int err = 0;
    for (size_t i = 0; (i < val_dwords_n) && !err; ++i, addr += RTL_SBIF_MEMORY_STEP, ++val_dwords) {
        err = sbif_read_dword(addr, val_dwords);
    }
    return err;
}

void
platform_ops::yield()
{
    sched_yield();
}

void
platform_ops::storage_rewind(uint32_t base)
{
    lseek(ops_fd, base, SEEK_SET);
}

int
platform_ops::storage_read_dwords(uint32_t ndwords, uint32_t* dwords)
{
    size_t nbytes = ndwords << 2;
    size_t n = read(ops_fd, dwords, nbytes);
    return (n == nbytes ? 0 : -1);
}

void
usage_and_exit(const char* prog)
{
    fprintf(stderr, "Usage: %s <-c|--cfile commands-file-path> <-h|--host hostname> <-r|--port_rw N> <-i|--port_int N>\n", prog);
    fprintf(stderr, "Example: %s --cfile ./commands.bin --host localhost --port_rw 44444 --port_int 55555\n", prog);
    exit(1);
}

int
main(int argc, char** argv)
{
    int debug, dry_run;

    struct option long_options[] = {// These options set a flag
                                    {"debug", no_argument, &debug, 1},
                                    {"dry_run", no_argument, &dry_run, 0},
                                    // These options don't set a flag.
                                    // We distinguish them by their indices.
                                    {"host", required_argument, 0, 'h'},
                                    {"port_rw", required_argument, 0, 'r'},
                                    {"port_int", required_argument, 0, 'i'},
                                    {"cfile", required_argument, 0, 'c'},
                                    // End of options
                                    {0, 0, 0, 0}};

    int opt;
    int option_index;

    const char *host = NULL, *cfile = NULL;
    uint16_t port_rw = 0, port_int = 0;

    while ((opt = getopt_long(argc, argv, "h:r:i:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 0:
            // If this option sets a flag, do nothing else.
            break;
        case 'c':
            cfile = strdup(optarg);
            break;
        case 'h':
            host = strdup(optarg);
            break;
        case 'r':
            port_rw = atoi(optarg);
            break;
        case 'i':
            port_int = atoi(optarg);
            break;
        default:
            usage_and_exit(argv[0]);
        }
    }

    if (!cfile || !host || !port_rw || !port_int) {
        usage_and_exit(argv[0]);
    }

    lld_conn = lld_client_connect(host, port_rw, port_int);
    if (!lld_conn) {
        fprintf(stderr, "lld_client_connect failed\n");
        exit(EXIT_FAILURE);
    }

    ops_fd = open(cfile, O_RDONLY);
    if (ops_fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    uint32_t storage_base = 0; // the first command is at offset 0
    int is_exec = (dry_run == 0);
    scr_error_t err = scr_read_from_storage_and_exec(storage_base, is_exec);
    close(ops_fd);

    LOG_I("disconnect\n");
    lld_conn_destroy(lld_conn);
    LOG_I("done, err %d\n", err);

    return 0;
}
