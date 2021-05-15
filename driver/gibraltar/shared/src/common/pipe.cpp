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

#include "common/pipe.h"
#include "common/gen_utils.h"
#include "common/logger.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_SETPIPE_SZ
// F_SETPIPE_SZ and F_GETPIPE_SZ are defined since Linux 2.6.35.
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 8)
#endif

namespace silicon_one
{

pipe::pipe() : m_fdr(-1), m_fdw(-1), m_capacity_bytes(0), m_fcntl_pipe_size_supported(false)
{
}

pipe::~pipe()
{
    close();
}

la_status
pipe::open()
{
    int fd[2];
    if (::pipe(fd) < 0) {
        log_err(COMMON, "%s: cannot create a pipe, errno %d", __PRETTY_FUNCTION__, errno);
        return LA_STATUS_ERESOURCE;
    }

    m_fdr = fd[0];
    m_fdw = fd[1];

    // Check if F_GETPIPE_SZ and F_SETPIPE_SZ are supported (it suffices to check only one of the two).
    int n = fcntl(m_fdw, F_GETPIPE_SZ);
    if (n == -1) {
        if (errno != EINVAL) {
            // unexpected failure
            log_err(COMMON, "%s: fcntl() failed, errno %d", __PRETTY_FUNCTION__, errno);
            return LA_STATUS_EUNKNOWN;
        }

        log_warning(COMMON, "%s: F_GETPIPE_SZ and F_SETPIPE_SZ are not supported on this OS", __func__);

        // According to "man 7 pipe", since Linux 2.6.11 the pipe capacity is 16 pages;
        // and since Linux 2.6.35 the pipe capacity can be queried and set.
        static long page_sz = sysconf(_SC_PAGESIZE);
        m_capacity_bytes = page_sz * 16;
        m_fcntl_pipe_size_supported = false;
    } else {
        m_capacity_bytes = n;
        m_fcntl_pipe_size_supported = true;
    }

    return LA_STATUS_SUCCESS;
}

static inline la_status
fd_close(int& fd)
{
    if (fd < 0) {
        return LA_STATUS_ENOTINITIALIZED;
    }
    if (::close(fd) < 0) {
        // ::close() may fail in which case errno is set to one of the following values:
        //   EBADF - invalid file descriptor, can happen if, e.g., pipe::close() is called twice.
        //   EINTR - close() was interrupted by a signal.
        //   EIO - I/O error occurred while close() was writing to or reading from the file system.
        //
        // As far as we are concerned, all those errors map to LA_STATUS_EUNKNOWN.
        log_err(COMMON, "%s: cannot close fd=%d, errno %d", __func__, fd, errno);
        return LA_STATUS_EUNKNOWN;
    }

    fd = -1;

    return LA_STATUS_SUCCESS;
}

la_status
pipe::close()
{
    la_status rc1 = fd_close(m_fdr);
    la_status rc2 = fd_close(m_fdw);

    return rc1 ?: rc2;
}

ssize_t
pipe::read(void* buf, size_t nbyte)
{
    return ::read(get_fdr(), buf, nbyte);
}

ssize_t
pipe::write(const void* buf, size_t nbyte)
{
    return ::write(get_fdw(), buf, nbyte);
}

int
pipe::get_fdr() const
{
    return m_fdr;
}

int
pipe::get_fdw() const
{
    return m_fdw;
}

la_status
pipe::get_capacity(size_t& bytes_out) const
{
    bytes_out = m_capacity_bytes;

    return LA_STATUS_SUCCESS;
}

la_status
pipe::set_capacity(size_t bytes)
{
    if (!m_fcntl_pipe_size_supported) {
        return LA_STATUS_EINVAL;
    }

    int rc = fcntl(m_fdw, F_SETPIPE_SZ, bytes);
    if (rc == -1) {
        log_err(COMMON, "%s: fcntl(F_SETPIPE_SZ) failed, %d (%s)", __func__, errno, strerror(errno));
        if (errno == EBUSY) {
            // Attempting to set the pipe capacity smaller than the amount of buffer space currently used to store data
            return LA_STATUS_EBUSY;
        }
        if (errno == EPERM) {
            // An unprivileged process attempts to set the pipe capacity above the limit in /proc/sys/fs/pipe-max-size
            return LA_STATUS_EINVAL;
        }
        return LA_STATUS_EUNKNOWN;
    }

    int n = fcntl(m_fdw, F_GETPIPE_SZ);
    if (n == -1) {
        log_err(COMMON, "%s: fcntl(F_GETPIPE_SZ) failed, %d (%s)", __func__, errno, strerror(errno));
        return LA_STATUS_EUNKNOWN;
    }

    m_capacity_bytes = n;
    log_debug(COMMON, "%s: bytes=%ld, m_capacity_bytes=%ld", __func__, bytes, m_capacity_bytes);

    return LA_STATUS_SUCCESS;
}

la_status
pipe::get_number_of_unread_bytes(size_t& bytes_out) const
{
    int nbytes = 0;
    int rc = ioctl(m_fdw, FIONREAD, &nbytes);
    if (rc) {
        log_err(COMMON, "%s: ioctl(FIONREAD) failed, %d (%s)", __func__, errno, strerror(errno));
        return LA_STATUS_EUNKNOWN;
    }

    bytes_out = nbytes;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
