// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

/*
 * Cisco Systems, Inc.
 */

#ifndef __USER_SPACE_KERNEL_H__
#define __USER_SPACE_KERNEL_H__

#include <atomic>
#include <device_simulator/dsim_client/dsim_client.h>

class user_space_kernel
{
private:
    std::atomic<bool> m_stop_listening{false};

private:
    int kernel_inject(void* packet, unsigned len, int slice);
    void check_for_packets_from_kernel();
    static void* listen_thread_func(void*);
    int create_named_sock(char* name, int* fd);
    dsim::dsim_client* create_dsim_client(const char* addr, size_t port);

public:
    int initialize(int dev_id, const char* dsim_addr_and_port);
    void close_connected_sockets();
    int start_listening_for_packets();
    void destroy();
    void set_add_wrapper_header(bool enable);
    void set_debug_level(int level);
};
#endif
