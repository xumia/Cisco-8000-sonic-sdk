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

#ifndef __LEABA_PIPE_H__
#define __LEABA_PIPE_H__

#include "common/cereal_utils.h"
#include "common/la_status.h"

#include <unistd.h>

namespace silicon_one
{

/// @brief Convenience wrapper for POSIX unnamed pipe
class pipe
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief c'tor
    pipe();

    /// @brief d'tor
    ~pipe();

    /// @brief Copy c'tor - deleted
    pipe(const pipe& other) = delete;

    /// @brief Copy assignment - deleted
    pipe& operator=(const pipe& other) = delete;

    /// @brief Open a pipe, store read and write file descriptors in fdr and fdw.
    ///
    /// @return Status code
    la_status open();

    /// @brief Close a pipe by closing both read and write file descriptors.
    ///
    /// @return Status code
    la_status close();

    /// @brief Read from the read end of the pipe.
    ///
    /// @param[out] buf     Output buffer.
    /// @param[in]  count   Bytes count.
    //
    /// @return The return value of POSIX read() call.
    ssize_t read(void* buf, size_t count);

    /// @brief Write to the write end of the pipe.
    ///
    /// @param[in]  buf     Input buffer.
    /// @param[in]  count   Bytes count.
    //
    /// @return The return value of POSIX write() call.
    ssize_t write(const void* buf, size_t count);

    /// @brief Get the read file descriptor of the pipe.
    ///
    /// @return Read file descriptor.
    int get_fdr() const;

    /// @brief Get the write file descriptor of the pipe.
    ///
    /// @return Write file descriptor.
    int get_fdw() const;

    /// @brief Get the capacity of a pipe in bytes.
    ///
    /// @param[out] bytes_out  Capacity of the pipe in bytes.
    ///
    /// @return LA_STATUS_SUCCESS   Operation succeeded.
    /// @return LA_STATUS_EUNKNOWN  Operation failed.
    la_status get_capacity(size_t& bytes_out) const;

    /// @brief Set the capacity of a pipe in bytes.
    ///
    /// @param[in] bytes    Capacity of the pipe in bytes.
    ///
    /// @return LA_STATUS_SUCCESS   Operation succeeded.
    /// @return LA_STATUS_EBUSY     Attempting to set the pipe capacity smaller than the amount of
    ///                             buffer space currently used to store data.
    /// @return LA_STATUS_ESIZE     Attempts by an unprivileged process to set the pipe capacity above the system limit.
    /// @return LA_STATUS_EUNKNOWN  Operation failed for unknown reason.
    la_status set_capacity(size_t bytes);

    /// @brief Get the number of unread bytes in the pipe.
    ///
    /// @param[out] bytes_out  Number of unread bytes in the pipe.
    ///
    /// @return LA_STATUS_SUCCESS   Operation succeeded.
    /// @return LA_STATUS_EUNKNOWN  Operation failed.
    la_status get_number_of_unread_bytes(size_t& bytes_out) const;

private:
    // Read and write file descriptors for this pipe
    int m_fdr;
    int m_fdw;
    size_t m_capacity_bytes;
    bool m_fcntl_pipe_size_supported;
};

} // namespace silicon_one

#endif // __LEABA_PIPE_H__
