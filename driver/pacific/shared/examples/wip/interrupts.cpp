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

/// @file
/// @brief Pacific interrupts example
///
/// @example interrupts.cpp
///
/// Monitor critical and normal interrupts simultaneously from one thread.

#include "example_system.h"

#include "api/system/la_device.h"
#include "api/system/la_notification.h"

using namespace silicon_one;

int
main()
{
    example_system es;
    example_system_init(&es);

    int fd_crit, fd_norm;
    es.device->open_notification_fds(LA_NOTIFICATION_MASK_ALL, &fd_crit, &fd_norm);

    fd_set active_fd_set, read_fd_set;
    FD_ZERO(&active_fd_set);
    FD_SET(fd_crit, &active_fd_set);
    FD_SET(fd_norm, &active_fd_set);

    while (1) {
        // Block until an interrupt descriptor becomes available on one of file descriptors
        read_fd_set = active_fd_set;
        if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
            perror("select");
            if (errno == EINTR) {
                continue; // Interrupted, back to waiting.
            }
            return -1;
        }

        for (int i = 0; i < FD_SETSIZE; i++) {
            if (!FD_ISSET(i, &read_fd_set))
                continue;

            la_notification_desc desc;

            if (i == fd_crit) {
                read(fd_crit, &desc, sizeof(desc);
                printf("Got critical interrupt, id %ld, type %d\n", desc.id, (int)desc.type);
            } else if (i == fd_norm) {
                read(fd_norm, &desc, sizeof(desc);
                printf("Got normal interrupt, id %ld, type %d\n", desc.id, (int)desc.type);
            }
        }
    }

    return 0;
}
