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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ae.h"

int
main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("USAGE: %s <IN_commands.hex> <OUT_commands.bin>\n", argv[0]);
        return -1;
    }

    // Parse input file with lines in this format:
    //   cmd[32bit] block_id[16bit] addr[32bit] width_bytes[16bit] val[variable size]
    FILE* fin = fopen(argv[1], "r");
    int fout = open(argv[2], O_CREAT | O_WRONLY | O_TRUNC);
    if (!fin || fout < 0) {
        perror("open");
        return -1;
    }

    char line[4096];
    ssize_t nwrite = 0;
    for (int line_n = 0; fgets(line, sizeof(line), fin); ++line_n) {
        char *tok_cmd, *tok_block_id, *tok_addr, *tok_width_bytes, *tok_val;

        tok_cmd = strtok(line, " ");
        tok_block_id = strtok(NULL, " ");
        tok_addr = strtok(NULL, " ");
        tok_width_bytes = strtok(NULL, " ");
        tok_val = strtok(NULL, " \n");

        if (!(tok_cmd && tok_block_id && tok_addr && tok_width_bytes && tok_val)) {
            printf("bad format, line %d\n", line_n);
            return -1;
        }

        cmd_header_t hdr;

        hdr.cmd = strtol(tok_cmd, NULL, 16);
        if (!errno)
            hdr.block_id = strtol(tok_block_id, NULL, 16);
        if (!errno)
            hdr.addr = strtol(tok_addr, NULL, 16);
        if (!errno)
            hdr.width_bytes = strtol(tok_width_bytes, NULL, 16);
        if (errno) {
            printf("bad cmd/block_id/addr/width_bytes, line %d\n", line_n);
            return -1;
        }

        uint32_t* p = (uint32_t*)&hdr;
        printf("hdr: %08x_%08x_%08x", p[0], p[1], p[2]);
        nwrite += write(fout, &hdr, sizeof(hdr));

        // The value is a string of hex nibles. Pad it to be dword aligned
        char val_nibles[MAX_VAL_BYTES * 2 + 1]; // ASCII sequence of hex nibles (human readable)
        uint8_t val[MAX_VAL_BYTES];             // big-endian byte stream

        size_t nibles = strlen(tok_val);
        size_t nibles_padding = (8 - (nibles % 8)) % 8;

        if ((nibles + 1) / 2 != hdr.width_bytes) {
            printf("\nERROR: bad value - width_bytes=%d does not match the actual nibles %ld\n", hdr.width_bytes, nibles);
            return -1;
        }
        if (nibles_padding + nibles >= MAX_VAL_BYTES * 2) {
            printf("\nERROR: bad value - too long, nibles %ld\n", nibles);
            return -1;
        }

        for (int i = 0; i < nibles_padding; ++i) {
            val_nibles[i] = 0;
        }

        memcpy(&val_nibles[nibles_padding], tok_val, nibles);
        val_nibles[nibles_padding + nibles] = 0;

        printf(", val: ", (nibles_padding + nibles) / 2);
        for (int i = 0; i < nibles_padding + nibles; i += 2) {
            char byte_str[3] = {val_nibles[i], val_nibles[i + 1], '\0'};
            val[i / 2] = strtol(byte_str, NULL, 16);
            printf("%02x ", val[i / 2]);
            if (errno) {
                printf("bad nibles at index %d\n", i);
                return -1;
            }
        }
        printf("\n");
        nwrite += write(fout, val, (nibles_padding + nibles) / 2);
    }

    // END marker - pad with all-ones header (3 dwords)
    cmd_header_t hdr;
    memset(&hdr, 0xff, sizeof(hdr));
    nwrite += write(fout, &hdr, sizeof(hdr));

    printf("Total size: %zd\n", nwrite);

    if (nwrite % 4) {
        printf("ERROR - total size is not dword aligned\n");
    }

    fclose(fin);
    close(fout);

    return 0;
}
