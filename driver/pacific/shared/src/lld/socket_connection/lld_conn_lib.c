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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "lld_conn_lib.h"

typedef struct lld_conn {
    // listening sockets (server only), used for connection establishment
    int srv_so_rw;
    int srv_so_int;

    // connection sockets (client or server), data flows through these socketsd
    int so_rw;
    int so_int;

    uint16_t port_rw;
    uint16_t port_int;

    // driver side
    void (*int_handler)(uint64_t data);
    pthread_t interrupt_tid;
} lld_conn_t;

// Currently, a single instance of server is supported.
// If a need for multiple servers arises, the "signalled" state should be handled per-instance.
static int g_server_signalled = 0;

// Command format
//
// |                               header                             |    data      |
// +---------------+------------+---------------------------+---------+--------------+
// | 32b: block_id |  32b: addr | 32b: data length in bytes | 8b: cmd | varlen: data |
// +---------------+------------+---------------------------+---------+--------------+
//
// Command types
//   'W' - write command, driver-to-device, payload == header+data.
//   'R' - read command,  driver-to-device, payload == header (w/o data).
//   'R' - read response, device-to-driver, payload == header+data.
//
// Data field is
//   - big endian, number of bytes is from 1 to 512
//   - sent only with "Write" command and "Read" response.
//   - NOT sent with "Read" command
//

#pragma pack(push, 1)
typedef struct lld_socket_command {
    uint64_t addr; // 32b block id + 32b addr
    uint32_t len;
    uint8_t cmd;
} lld_socket_command_t;
#pragma pack(pop)

#define CLIENT_CONNECT_RETRY_DELAY 10 // seconds
#define CLIENT_CONNECT_RETRY_MAX 2000 // max number of retry attempts

// Disable Nagle's algorithm which accumulates small packets.
static inline void
set_tcp_nodelay(int so)
{
    int opt = 1;
    setsockopt(so, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

static int
client_connect(struct hostent* hostinfo, uint16_t port, int autoretry_delay_seconds, int autoretry_max_attempts)
{
    struct sockaddr_in sa;
    int so;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr = *(struct in_addr*)hostinfo->h_addr;

    if ((so = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server_init (socket)");
        return -1;
    }

    for (;;) {
        if (connect(so, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
            printf("%s: so %d connected to %s:%hu\n", __func__, so, inet_ntoa(sa.sin_addr), port);
            return so;
        }

        fprintf(stderr, "%s: %s:%hu - %s\n", __func__, inet_ntoa(sa.sin_addr), port, strerror(errno));
        if (autoretry_max_attempts-- > 0) {
            fprintf(stderr, "%s: retries left %d\n", __func__, autoretry_max_attempts + 1);
            sleep(autoretry_delay_seconds);
            continue;
        }

        close(so);
        return -1;
    };

    set_tcp_nodelay(so);
}

// Initialize client connection, connect on two sockets.
// Return connection context on success, NULL on failure.
lld_conn_t*
lld_client_connect(const char* hostname, uint16_t port_rw, uint16_t port_int)
{
    int so_rw = -1, so_int = -1;
    struct hostent* hostinfo;
    lld_conn_t* s;

    if (!port_rw || !port_int) {
        fprintf(stderr, "%s: ports must be non-zero.\n", __func__);
        goto Error;
    }

    if (!(hostinfo = gethostbyname(hostname))) {
        fprintf(stderr, "%s: Unknown host %s.\n", __func__, hostname);
        goto Error;
    }

    // Retry connection attempt every 'x' seconds for 'y' times.
    if ((so_rw = client_connect(hostinfo, port_rw, CLIENT_CONNECT_RETRY_DELAY, CLIENT_CONNECT_RETRY_MAX)) < 0) {
        goto Error;
    }

    // Try to connect only once, no retries
    if ((so_int = client_connect(hostinfo, port_int, 0, 0)) < 0) {
        goto Error;
    }

    if (!(s = calloc(1, sizeof(*s)))) {
        fprintf(stderr, "%s: Out of memory\n", __func__);
        goto Error;
    }

    s->so_rw = so_rw;
    s->so_int = so_int;
    return s;

Error:
    exit(EXIT_FAILURE);
    return NULL;
}

static int
make_server_socket(uint16_t port)
{
    int sock;
    struct sockaddr_in sa;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "bind error: port %hu, %s\n", port, strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0) {
        fprintf(stderr, "listen error: port %hu, %s\n", port, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

#ifdef NDEBUG
#define dbg_hex_dump(str, sz, buf)                                                                                                 \
    do {                                                                                                                           \
    } while (0)
#else
static void
dbg_hex_dump(const char* str, int sz, void* buf)
{
    uint8_t* p = (uint8_t*)buf;

    fprintf(stderr, "%s:", str);
    while (sz--) {
        fprintf(stderr, " %02x", *p++);
    }
    fprintf(stderr, "\n");
}
#endif

// Read full message.
// Return:
//   in_buf_size - on success
//   0           - on EOF, peer has closed the connection
//   -1          - other error
static int
read_message(int fd, void* in_buf, int in_buf_sz)
{
    int nbytes, off = 0;

    do {
        nbytes = read(fd, (char*)in_buf + off, in_buf_sz - off);
        if (nbytes > 0) {
            // Data read.
            off += nbytes;
        } else {
            if (nbytes < 0) {
                // Read error.
                fprintf(stderr, "%s: client so %d, read %s\n", __func__, fd, strerror(errno));
            } else {
                // nbytes == 0, end-of-file, client has dropped the connection.
                fprintf(stderr, "%s: client so %d has dropped the connection\n", __func__, fd);
            }
            return nbytes;
        }
    } while (off < in_buf_sz);

    dbg_hex_dump(__func__, in_buf_sz, in_buf);

    return off;
}

static int
get_sock_port(int so, uint16_t* port)
{
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    if (getsockname(so, (struct sockaddr*)&sin, &len)) {
        return -1;
    }

    *port = ntohs(sin.sin_port);

    return 0;
}

// The server supports two active connections - one for R/W commands/replies and
// another for interrupts. Only one connection of each type is supported.
//
// The commands/replies connection is bi-directional.
// The interrupts flow only from server to client.
//
// port_rw == 0 or port_int == 0 implies that port numbers are allocated
// automatically and can be later retrieved by lld_server_get_ports()
lld_conn_h
lld_server_create(uint16_t port_rw, uint16_t port_int)
{
    lld_conn_t* s;

    if (!(s = (lld_conn_t*)calloc(1, sizeof(*s)))) {
        fprintf(stderr, "%s: Out of memory\n", __func__);
        return NULL;
    }

    s->srv_so_rw = s->srv_so_int = s->so_rw = s->so_int = -1;

    // create sockets, then bind, then listen
    if ((s->srv_so_rw = make_server_socket(port_rw)) < 0 || (s->srv_so_int = make_server_socket(port_int)) < 0) {
        lld_conn_destroy(s);
        return NULL;
    }

    // obtain port numbers (if initially zero)
    if (!port_rw && get_sock_port(s->srv_so_rw, &port_rw)) {
        lld_conn_destroy(s);
        return NULL;
    }
    if (!port_int && get_sock_port(s->srv_so_int, &port_int)) {
        lld_conn_destroy(s);
        return NULL;
    }

    s->port_rw = port_rw;
    s->port_int = port_int;

    printf("%s: started, port_rw %hu, port_int %hu\n", __func__, port_rw, port_int);

    return s;
}

int
lld_server_get_ports(lld_conn_t* s, uint16_t* port_rw, uint16_t* port_int)
{
    if (!s) {
        return -1;
    }
    if (port_rw) {
        *port_rw = s->port_rw;
    }
    if (port_int) {
        *port_int = s->port_int;
    }

    return 0;
}

// Block until we accept two connections - one on each socket
// Stop blocking if we get signalled by SIGINT (CTRL-C)
int
lld_server_wait_conn(lld_conn_t* s)
{
    return lld_server_wait_conn_signalled(s, SIGINT);
}

static void
server_sig_handler(int signum)
{
    printf("%s: %d (%s)\n", __func__, signum, strsignal(signum));
    g_server_signalled = 1;
}

// Block until we accept two connections - one on each socket
// Stop blocking if we get signalled by 'signum'
int
lld_server_wait_conn_signalled(lld_conn_t* s, int signum)
{
    fd_set active_fd_set, read_fd_set;
    int i;

    // Finalize current active connection (if any)
    // This is needed for re-connects.
    if (s->so_rw >= 0) {
        close(s->so_rw);
        s->so_rw = -1;
    }
    if (s->so_int >= 0) {
        close(s->so_int);
        s->so_int = -1;
    }

    printf("Waiting for inbound connection, port_rw=%hu, port_int=%hu.\n", s->port_rw, s->port_int);

    // Install signal handler
    if (signum) {
        struct sigaction new_action, old_action;
        new_action.sa_handler = server_sig_handler;
        sigemptyset(&new_action.sa_mask);
        new_action.sa_flags = 0;
        sigaction(signum, NULL, &old_action);
        if (old_action.sa_handler != SIG_IGN) {
            sigaction(signum, &new_action, NULL);
        }
        printf("Use signal %d (%s) to stop waiting.\n", signum, strsignal(signum));
    }

    FD_ZERO(&active_fd_set);
    FD_SET(s->srv_so_rw, &active_fd_set);
    FD_SET(s->srv_so_int, &active_fd_set);

    while (s->so_rw < 0 || s->so_int < 0) {
        // Block until a connection request arrives on one of active sockets
        read_fd_set = active_fd_set;
        if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
            perror("select");
            if (errno == EINTR) {
                if (g_server_signalled == 0) {
                    continue; // Interrupted, but not by our special signal - back to waiting.
                }
                printf("%s: signalled by %d (%s) - terminating.\n", __func__, signum, strsignal(signum));
                g_server_signalled = 0;
                return -1;
            }
            if (errno == EAGAIN) {
                continue;
            }
            // some other error
            return -1;
        }

        for (i = 0; i < FD_SETSIZE; i++) {
            if (!FD_ISSET(i, &read_fd_set))
                continue;

            // Incoming connection request
            struct sockaddr_in client_sa;
            int so;
            socklen_t size = sizeof(client_sa);

            so = accept(i, (struct sockaddr*)&client_sa, &size);
            if (so < 0) {
                perror("accept");
                return -1;
            }

            if (i == s->srv_so_rw) {
                s->so_rw = so;
            } else {
                s->so_int = so;
            }

            set_tcp_nodelay(so);

            // printf("%s: client so %d, host %s, port %hu (%s).\n",
            //       __func__,
            //       so,
            //       inet_ntoa(client_sa.sin_addr),
            //       ntohs(client_sa.sin_port),
            //       i == srv_so_rw ? "R/W" : "INT");

            // Stop listening on this socket
            FD_CLR(i, &active_fd_set);
        }
    }

    return 0;
}

// Close sockets, drop active connections, kill the interrupt thread and release the server context.
void
lld_conn_destroy(lld_conn_t* s)
{
    // TODO: server-side "active close" may become a huge problem should the
    // connection be quickly re-established (e.g. when running unitests).
    //
    // For more info, search the Web for "TIME_WAIT" and "Address already in use".
    //
    // Generally, "client-closes-first" approach is usually the way to go, but
    // this requires just a bit of app-level handshake.
    if (s->srv_so_rw >= 0)
        close(s->srv_so_rw);
    if (s->srv_so_int >= 0)
        close(s->srv_so_int);
    if (s->so_rw >= 0)
        close(s->so_rw);
    if (s->so_int >= 0)
        close(s->so_int);
    if (s->interrupt_tid)
        pthread_join(s->interrupt_tid, NULL);
    free(s);
}

// Wait for data on "interrupt" socket as long as a client is connected.
// Assume, interrupt file descriptor is not set to O_NONBLOCK.
// Invoke 'int_handler' when data is received on the socket.
static void*
interrupt_thread(void* arg)
{
    lld_conn_t* s = (lld_conn_t*)arg;
    uint64_t data;

    while (1) {
        // Block until data arrives on interrupt socket, break if error.
        if (read_message(s->so_int, &data, sizeof(data)) <= 0) {
            break;
        }

        s->int_handler(data);
    }

    return NULL;
}

// Start a thread that waits for data on "interrupt" socket as long as a client
// is connected.
// Invoke 'int_handler' when data is received on the socket.
int
lld_conn_start_interrupt_thread(lld_conn_t* s, void (*int_handler)(uint64_t data))
{
    s->int_handler = int_handler;
    if (pthread_create(&s->interrupt_tid, NULL, interrupt_thread, s)) {
        perror("thread_create");
        return -1;
    }
    return 0;
}

static int
send_command(lld_conn_t* s, char cmd, uint64_t addr, const void* data, uint32_t data_sz)
{
    int nbytes, nbytes_expected;
    lld_socket_command_t hdr = {.addr = addr, .len = data_sz, .cmd = cmd};

    // Since we set TCP_NODELAY, each individual write() is immediately sent on socket.
    // So we use writev() to join 'hdr' and 'data' in a single packet.
    if (data) {
        struct iovec iov[2] = {{.iov_base = &hdr, .iov_len = sizeof(hdr)},     // header
                               {.iov_base = (void*)data, .iov_len = data_sz}}; // data

        nbytes_expected = sizeof(hdr) + data_sz;

        dbg_hex_dump("send_command: hdr", iov[0].iov_len, iov[0].iov_base);
        dbg_hex_dump("send_command: data", iov[1].iov_len, iov[1].iov_base);

        nbytes = writev(s->so_rw, iov, 2);
    } else {
        nbytes_expected = sizeof(hdr);
        nbytes = write(s->so_rw, &hdr, sizeof(hdr));
    }

    if (nbytes != nbytes_expected) {
        fprintf(stderr, "%s: failed sending command, %d/%d, %s\n", __func__, nbytes, nbytes_expected, strerror(errno));
        return -1;
    }
    return 0;
}

// Send message.
int
lld_conn_send_message(lld_conn_h h, const void* message, uint32_t data_sz)
{
    return send_command(h, 'M', 0x00 /*no use*/, message, data_sz);
}

// Receive message.
int
lld_conn_recv_message(lld_conn_h h, void* message, uint32_t max_data_sz)
{
    lld_socket_command_t hdr;

    if (read_message(h->so_rw, &hdr, sizeof(hdr)) <= 0) {
        return -1;
    }

    if (hdr.cmd != 'M') {
        fprintf(stderr, "%s: expected message, but got different command code: %c\n", __func__, (char)hdr.cmd);
        return -1;
    }

    if (hdr.len > max_data_sz) {
        fprintf(stderr, "%s: overflow reading message, max: %d, received: %d\n", __func__, max_data_sz, hdr.len);
        return -1;
    }

    if (read_message(h->so_rw, message, hdr.len) <= 0) {
        return -1;
    }

    return hdr.len;
}

// Send write reg/mem command.
int
lld_conn_write_regmem(lld_conn_t* s, uint64_t addr, const void* data, uint32_t data_sz)
{
    return send_command(s, 'W', addr, data, data_sz);
}

// Send read reg/mem command and wait for read response.
int
lld_conn_read_regmem(lld_conn_t* s, uint64_t addr, void* data, uint32_t data_sz)
{
    lld_socket_command_t hdr;

    if (send_command(s, 'R', addr, NULL, data_sz)) {
        return -1;
    }
    if (read_message(s->so_rw, &hdr, sizeof(hdr)) <= 0) {
        return -1;
    }
    if (read_message(s->so_rw, data, data_sz) <= 0) {
        return -1;
    }

    return 0;
}

// Receive read/write command
int
lld_conn_recv_command(lld_conn_t* s, char* cmd, uint64_t* addr, uint8_t* data, uint32_t* data_sz)
{
    lld_socket_command_t hdr;

    if (read_message(s->so_rw, &hdr, sizeof(hdr)) <= 0) {
        return -1;
    }
    if (hdr.cmd == 'W' && read_message(s->so_rw, data, hdr.len) <= 0) {
        return -1;
    }

    *addr = hdr.addr;
    *data_sz = hdr.len;
    *cmd = hdr.cmd;

    return hdr.len;
}

// Send response to 'read' command
void
lld_conn_send_response(lld_conn_t* s, char cmd, uint64_t addr, const uint8_t* data, uint32_t data_sz)
{
    send_command(s, cmd, addr, data, data_sz);
}

// Send interrupt data
void
lld_conn_send_interrupt(lld_conn_t* s, uint64_t data)
{
    write(s->so_int, &data, sizeof(data));
}

int
lld_conn_get_interrupt_fd(lld_conn_t* s)
{
    return s->so_int;
}
