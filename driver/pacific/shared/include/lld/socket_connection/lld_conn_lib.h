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

#ifndef __LEABA_LLD_CONN_LIB_H__
#define __LEABA_LLD_CONN_LIB_H__
#include <inttypes.h>

// Max number of data bytes for read/write commands
#define LLD_COMMAND_MAX_DATA_LEN 512

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lld_conn* lld_conn_h;

//============================================================================
// Server or client connection
//============================================================================

// Open a session against hostname on port_rw and port_int.
lld_conn_h lld_client_connect(const char* hostname, uint16_t port_rw, uint16_t port_int);

/// @brief  Create two server sockets, bound to port_rw/int.
///
/// @note   Is port is zero, the number is chosed automatically and can be
///         retrieved later using lld_server_get_ports().
///
/// @param[in]  port_rw     Read/Write port
/// @param[in]  port_int    Interrupt port
///
/// @return Server handle if successfull, or NULL otherwise.
lld_conn_h lld_server_create(uint16_t port_rw, uint16_t port_int);

/// @brief  Get listening ports.
///
/// @param[in]  h           Server handle
/// @param[out] port_rw     Read/Write port
/// @param[out] port_int    Interrupt port
///
/// @return Server handle if successfull, or NULL otherwise.
int lld_server_get_ports(lld_conn_h h, uint16_t* port_rw, uint16_t* port_int);

/// @brief  Block till a client connects to both sockets or till signalled by SIGINT.
///
/// @param[in]  h           Server handle
///
/// @return 0 if a client has connected, -1 if interrupted by SIGINT or an error occurred.
int lld_server_wait_conn(lld_conn_h h);

/// @brief  Block till a client connects to both sockets or till signalled by 'signum'.
///
/// @param[in]  h           Server handle
/// @param[in]  signum      Signal number that can be used to terminate this operation.
///
/// @return 0 if a client has connected, -1 if interrupted by 'signum' or an error occurred.
int lld_server_wait_conn_signalled(lld_conn_h h, int signum);

/// @brief  Drop the connection, kill the interrupt thread  and release the connection context
///
/// @param[in]  h           Server handle
///
/// @return None
void lld_conn_destroy(lld_conn_h h);

//============================================================================
// General I/O. Can be used by device and driver
//============================================================================
// Send message text - only block on file I/O, no ack from the remote peer is expected.
int lld_conn_send_message(lld_conn_h h, const void* message, uint32_t data_sz);

// Receive message text - block until command is received or a connection is dropped.
int lld_conn_recv_message(lld_conn_h h, void* message, uint32_t max_data_sz);

//============================================================================
// Driver-side I/O
//============================================================================

// Start a thread that waits for data on "interrupt" socket.
// Invoke 'int_handler' when data is received on the socket.
// The thread terminates if the TCP connection is dropped (e.g. one of the peers closes the socket).
int lld_conn_start_interrupt_thread(lld_conn_h h, void (*int_handler)(uint64_t data));

// Send 'read' command and block until a response is received.
int lld_conn_read_regmem(lld_conn_h h, uint64_t addr, void* data, uint32_t data_sz);

// Send 'write' command - only block on file I/O, no ack from the remote peer is expected.
int lld_conn_write_regmem(lld_conn_h h, uint64_t addr, const void* data, uint32_t data_sz);

// Get interrupt file descriptor, can be used with read/select/poll/...
int lld_conn_get_interrupt_fd(lld_conn_h h);

//============================================================================
// Device-side I/O
//============================================================================

// Receive read/write command - block until command is received or a connection is dropped
int lld_conn_recv_command(lld_conn_h h, char* cmd, uint64_t* addr, uint8_t* data, uint32_t* data_sz);

// Send read response - only block on file I/O, no ack from the remote peer is expected.
void lld_conn_send_response(lld_conn_h h, char cmd, uint64_t addr, const uint8_t* data, uint32_t data_sz);

// Send interrupt - only block on file I/O, no ack from the remote peer is expected.
void lld_conn_send_interrupt(lld_conn_h h, uint64_t data);

#ifdef __cplusplus
}
#endif

#endif
