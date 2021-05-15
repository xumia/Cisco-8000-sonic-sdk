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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "pacific_tree.h"

extern "C" {
#include <kernel_mock.h>
#include <leaba_module.h>
}

#include <user_space_kernel.h>

// in microseconds
#define TIMER_PERIOD 100

#ifdef DEBUG_PRINTS
#define debug_printf(...) fprintf(stdout, __VA_ARGS__)
#else
#define debug_printf(...)
#endif

// Ideally, we want all these s_ variables to be members of the class
// We would also like the ioread/write/netif_rx to move to kernel_mock.h
// This is problematic because these functions use the s_ variables, and they can't be part of class
// because they are called from the kernel
struct net_device s_ndev[NUM_INTERFACES_TO_CREATE];
static struct pci_dev s_pcidev;
static struct leaba_device_t s_leaba_device;
static char s_packet_buffer[10 * 1024];
static int s_name_sock_listen_fd[NUM_INTERFACES_TO_CREATE];
static int s_name_sock_connected_fd[NUM_INTERFACES_TO_CREATE];
static dsim::dsim_client* s_simulator;

#define M_SBIF_BLOCK_ID silicon_one::pacific_tree::lld_block_id_e::LLD_BLOCK_ID_SBIF

void
iowrite32(uint32_t val, uint8_t* addr)
{
#ifdef REG_ACCESS_DEBUG
    printf("write addr:0x%lx val:0x%lx\n", (uint64_t)addr, val);
#endif
    s_simulator->write_register(M_SBIF_BLOCK_ID, (uint64_t)addr, sizeof(val), 1, &val);
}

uint32_t
ioread32(uint8_t* addr)
{
    uint32_t out_val;

    s_simulator->read_register(M_SBIF_BLOCK_ID, (uint64_t)addr, sizeof(out_val), 1, &out_val);
#ifdef REG_ACCESS_DEBUG
    printf("read addr:0x%lx out_val:0x%lx\n", (uint64_t)addr, out_val);
#endif
    return out_val;
}

void
netif_rx(struct sk_buff* skb)
{
    int slice = skb->dev->index;

    if (s_name_sock_connected_fd[slice] > -1) {
        debug_printf("Sending packet to kernel on slice %d len %d\n", slice, skb->len);
        uint8_t buf[10 * 1024 + sizeof(uint32_t)];
        uint32_t* len_ptr = (uint32_t*)buf;

        if (skb->len - 4 + sizeof(uint32_t) > sizeof(buf)) {
            debug_printf(
                "Failed to send packet to kernel on slice %d, len (%lu) is too big\n", slice, skb->len - 4 + sizeof(uint32_t));
            dev_kfree_skb(skb);
            return;
        }

        // Set the len to be the beginning of the buffer
        *len_ptr = skb->len - 4;

        // leaba module pass to the kernel ethernet packet with 2 vlan tags
        // The kernel remove 1 vlan tag. This emulates the kernel behavior
        memcpy(buf + sizeof(uint32_t), skb->data, 12);
        memcpy(&buf[12] + sizeof(uint32_t), &skb->data[16], skb->len - 16);

        ssize_t sent_bytes = 0;
        size_t off = 0;
        size_t send_len = skb->len - 4 + sizeof(uint32_t);
        while (send_len != off) {
            sent_bytes = send(s_name_sock_connected_fd[slice], buf + off, send_len - off, 0);
            if (sent_bytes < 0) {
                debug_printf("Failed to send packet to kernel on slice %d, fd is closed\n", slice);
                break;
            }

            off += sent_bytes;
        }
    } else {
        debug_printf("Not sending packet to kernel on slice %d, fd is invalid\n", slice);
    }

    dev_kfree_skb(skb);
}

void
dump_buf(char* buf, int len)
{
    int i = 0;

    while (i < len) {
        if ((i % 16 == 0) && (i != 0)) {
            printf("\n");
        }
        printf("0x%02x ", (uint8_t)buf[i]);
        i++;
    }
}

extern "C" {
void set_module_param_m_add_wrapper_header(uint enable);
void set_module_param_g_leaba_module_debug_level(uint level);
}

void
user_space_kernel::set_add_wrapper_header(bool enable)
{
    if (enable) {
        set_module_param_m_add_wrapper_header(1);
    } else {
        set_module_param_m_add_wrapper_header(0);
    }
}

void
user_space_kernel::set_debug_level(int level)
{
    set_module_param_g_leaba_module_debug_level(level);
}

int
user_space_kernel::kernel_inject(void* packet, unsigned len, int slice)
{
    if (s_ndev[slice].is_stopped) {
        return 0;
    }

    struct sk_buff* skb = dev_alloc_skb(len);
    if (skb == NULL) {
        return -1;
    }

    skb_put(skb, len);
    memcpy(skb->data, packet, len);

    // calling leaba_nic_tx
    skb->dev = &s_ndev[slice];
    s_ndev[slice].netdev_ops->ndo_start_xmit(skb, &s_ndev[slice]);

    return 0;
}

void
user_space_kernel::check_for_packets_from_kernel()
{
    int i;

    for (i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
        leaba_check_device_pointers((struct leaba_nic_t*)s_ndev[i].priv);
    }
}

int
user_space_kernel::create_named_sock(char* name, int* fd)
{
    struct sockaddr_un namesock;
    int ret;

    ret = unlink(name);
    if (ret < 0) {
        if (errno != ENOENT) {
            perror("unlink failed");
            return -1;
        }
    }

    namesock.sun_family = AF_UNIX;
    strcpy(namesock.sun_path, name);
    *fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ret = bind(*fd, (struct sockaddr*)&namesock, sizeof(struct sockaddr_un));
    if (ret < 0) {
        perror("Bind failed");
        return -1;
    }

    return 0;
}

void*
user_space_kernel::listen_thread_func(void* kernel_obj_param)
{
    fd_set rfds;
    struct timeval tv;
    int retval;
    int max_fd = 0;
    user_space_kernel* kernel_obj = (user_space_kernel*)kernel_obj_param;

    for (int i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
        listen(s_name_sock_listen_fd[i], 1);
        if (s_name_sock_listen_fd[i] > max_fd) {
            max_fd = s_name_sock_listen_fd[i];
        }
    }

    debug_printf("user_space_kernel::listen_thread_func - max_fd:%d\n", max_fd);

    while (1) {
        FD_ZERO(&rfds);
        for (int i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
            if (s_name_sock_connected_fd[i] > 0) {
                FD_SET(s_name_sock_connected_fd[i], &rfds);
            } else {
                FD_SET(s_name_sock_listen_fd[i], &rfds);
            }
        }
        // exit every TIMER_PERIOD, so we will check for kernel punt packets
        tv.tv_sec = TIMER_PERIOD / 1000;
        tv.tv_usec = TIMER_PERIOD % 1000;
        retval = select(max_fd + 1, &rfds, NULL, NULL, &tv);

        // retval equals the number of file descriptor with data to consume
        if (retval > 0) {
            for (int i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
                if (s_name_sock_connected_fd[i] > 0) {
                    if (FD_ISSET(s_name_sock_connected_fd[i], &rfds)) {
                        int len;
                        // Get first four bytes first. These 4 bytes specify length of packet buffer
                        // that is either in flight or completely received.
                        // Continue to receive byte stream of upto the value specified before
                        // processing packet.
                        uint32_t buf_len = 0;
                        uint8_t* recv_ptr = (uint8_t*)&buf_len;
                        uint32_t off = 0;
                        int rcvd_bytes = 0;
                        while (off != sizeof(buf_len)) {
                            rcvd_bytes = recv(s_name_sock_connected_fd[i], recv_ptr + off, sizeof(buf_len) - off, 0);
                            if (rcvd_bytes <= 0) {
                                debug_printf(" NSIM USK client slide closed connection while reading length");
                                if ((EAGAIN == errno) || (EINTR == errno)) {
                                    continue;
                                }
                                break;
                            } else {
                                off += rcvd_bytes;
                            }
                        }

                        if (buf_len > sizeof(s_packet_buffer)) {
                            debug_printf("NSIM client sent buffer stream of length (%lx) > max packet size (%lx)",
                                         buf_len,
                                         sizeof(s_packet_buffer));
                            debug_printf("user_space_kernel::Exiting listen thread\n");
                            kernel_obj->m_stop_listening = false;
                            return NULL;
                        }

                        // Receive  buf_len bytes into s_packet_buffer
                        off = 0;
                        recv_ptr = (uint8_t*)s_packet_buffer;
                        while (off != buf_len) {
                            len = recv(s_name_sock_connected_fd[i], recv_ptr + off, buf_len - off, MSG_DONTWAIT);
                            if (len <= 0) {
                                if ((EAGAIN == errno) || (EINTR == errno)) {
                                    continue;
                                }
                                s_name_sock_connected_fd[i] = -1;
                                debug_printf("buffer %d - connection closed\n", i);
                            } else {
                                off += len;
                            }
                        }

                        if (buf_len > 0) {
                            debug_printf("%d bytes available on buffer %d\n", buf_len, i);
                            kernel_obj->kernel_inject(s_packet_buffer, buf_len, i);
                        }
                    }
                } else if (FD_ISSET(s_name_sock_listen_fd[i], &rfds)) {
                    int new_sock_fd;
                    debug_printf("connection request on socket %d.\n", i);
                    new_sock_fd = accept(s_name_sock_listen_fd[i], nullptr, nullptr);
                    if (new_sock_fd < 0) {
                        debug_printf("error connecting to sock %d\n", i);
                    } else {
                        s_name_sock_connected_fd[i] = new_sock_fd;
                        if (new_sock_fd > max_fd) {
                            max_fd = new_sock_fd;
                        }
                        debug_printf("connection established fd %d\n", new_sock_fd);
                    }
                }
            }
        }
        if (kernel_obj->m_stop_listening) {
            break;
        }
        kernel_obj->check_for_packets_from_kernel();
    }

    kernel_obj->m_stop_listening = false;

    debug_printf("user_space_kernel::Exiting listen thread\n");
    return NULL;
}

// For testing warm boot
// We close sockets from kernel side, in order to make kernel listen thread in SAI exit
void
user_space_kernel::close_connected_sockets()
{
    for (int i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
        if (s_name_sock_connected_fd[i] > 0) {
            debug_printf("Closing connected socket %d\n", i);
            close(s_name_sock_connected_fd[i]);
            s_name_sock_connected_fd[i] = -1;
        }
    }
}

int
user_space_kernel::start_listening_for_packets()
{
    pthread_t thread_num;

    if (pthread_create(&thread_num, NULL, listen_thread_func, this)) {
        perror("Failed initializing kernel thread");
        return -1;
    }
    pthread_detach(thread_num);

    return 0;
}

dsim::dsim_client*
user_space_kernel::create_dsim_client(const char* addr, size_t port)
{
    dsim::dsim_client* sim = new dsim::dsim_client();

    if (!sim->initialize(addr, port)) {
        delete sim;
        return nullptr;
    }

    return sim;
}

void
user_space_kernel::destroy()
{
    char sock_name[40];

    m_stop_listening = true; // Will exit the listening thread
    while (m_stop_listening)
        ; // Make sure we exited from loop in listen thread
    for (int i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
        leaba_nic_store_if((struct device*)&s_pcidev.dev, NULL, "D", 2, i); // deactivate interface
        leaba_nic_store_if((struct device*)&s_pcidev.dev, NULL, "0", 2, i); // remove interface
    }
    leaba_nic_teardown(&s_pcidev);

    for (int i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
        sprintf(sock_name, "/tmp/leaba%d_%d", s_leaba_device.devno, i);
        unlink(sock_name);
    }
}

int
user_space_kernel::initialize(int dev_id, const char* dsim_addr_and_port)
{
    int i;
    char sock_name[40];
    char ip_addr[20];
    size_t port;

    memset(&s_leaba_device, 0, sizeof(s_leaba_device));
    memset(&s_pcidev, 0, sizeof(s_pcidev));

    if (sscanf(dsim_addr_and_port, "/dev/testdev%d/%*[^/]/%[^:]:%lud", &s_leaba_device.devno, ip_addr, &port) != 3) {
        fprintf(stderr, "Failed parsing address string %s\n", dsim_addr_and_port);
        return -1;
    } else {
        debug_printf("user_space_kernel::initialize dev_name:%s addr:%s port:%lu\n", dsim_addr_and_port, ip_addr, port);
    }

    s_simulator = create_dsim_client(ip_addr, port);
    if (s_simulator == NULL) {
        fprintf(stderr, "Failed connecting to simulator server\n");
        return -1;
    }

    s_pcidev.priv = &s_leaba_device;
    s_pcidev.device = LEABA_PACIFIC_DEVICE_ID;
    if (leaba_nic_initialize(&s_pcidev) < 0) {
        fprintf(stderr, "leaba_nic_initialize failed\n");
        return -1;
    }

    for (i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
        memset(&s_ndev[i], 0, sizeof(s_ndev[i]));
    }

    for (i = 0; i < NUM_INTERFACES_TO_CREATE; i++) {
        s_ndev[i].is_stopped = 0;
        s_ndev[i].index = i;

        leaba_nic_store_if((struct device*)&s_pcidev.dev, NULL, "1", 2, i); // add interface
        leaba_nic_store_if((struct device*)&s_pcidev.dev, NULL, "A", 2, i); // activate interface

        sprintf(sock_name, "/tmp/leaba%d_%d", s_leaba_device.devno, i);

        if (create_named_sock(sock_name, &s_name_sock_listen_fd[i]) < 0) {
            fprintf(stderr, "Failed creating name sock %s\n", sock_name);
            return -1;
        } else {
            debug_printf("Created name sock %s fd:%d\n", sock_name, s_name_sock_listen_fd[i]);
        }
        s_name_sock_connected_fd[i] = -1;
    }

    return 0;
}

#ifdef COMPILE_WITH_MAIN
int
main(int argc, char** argv)
{
    int ret;

    if (argc < 2) {
        printf("Must provide addr/port string argument\n");
        exit(-1);
    }
    user_space_kernel kernel = user_space_kernel();
    ret = kernel.initialize(1, argv[1]);
    if (ret < 0) {
        fprintf(stderr, "Kernel init failed\n");
        return ret;
    }

    ret = kernel.start_listening_for_packets();
    if (ret < 0) {
        fprintf(stderr, "Failed starting kernel thread\n");
        retrun ret;
    }
}
#endif
