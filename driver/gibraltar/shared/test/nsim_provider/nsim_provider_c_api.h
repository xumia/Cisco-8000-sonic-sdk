// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "nsim_provider_local.h"

#define NSIM_PROV_C_API_INFO(msg)                                                                                                  \
    if (m_logging_enabled) {                                                                                                       \
        std::cerr << time_now() << " " NSIM_PROV_C_API_PREFIX "INFO: (pid " << getpid() << ") " << msg << std::endl << std::flush; \
    }

#define NSIM_PROV_C_API_DEBUG(msg)                                                                                                 \
    if (m_debug_enabled) {                                                                                                         \
        std::cerr << time_now() << " " NSIM_PROV_C_API_PREFIX "DEBUG: (pid " << getpid() << ") " << msg << std::endl               \
                  << std::flush;                                                                                                   \
    }

#define NSIM_PROV_C_API_G_DEBUG(msg)                                                                                               \
    if (g_debug_enabled) {                                                                                                         \
        std::cerr << time_now() << " " NSIM_PROV_C_API_PREFIX "DEBUG: (pid " << getpid() << ") " << msg << std::endl               \
                  << std::flush;                                                                                                   \
    }

#define NSIM_PROV_C_API_ERROR(msg)                                                                                                 \
    {                                                                                                                              \
        std::cerr << time_now() << " " NSIM_PROV_C_API_PREFIX "ERROR: (pid " << getpid() << ") " << msg << " at " << __FILE__      \
                  << ", " << __FUNCTION__ << ":" << __LINE__ << std::endl                                                          \
                  << std::flush;                                                                                                   \
    }

#define NSIM_PROV_C_API_FATAL(msg)                                                                                                 \
    {                                                                                                                              \
        std::cerr << time_now() << " " NSIM_PROV_C_API_PREFIX "FATAL-ERROR: (pid " << getpid() << ") " << msg << " at "            \
                  << __FILE__ << ", " << __FUNCTION__ << ":" << __LINE__                                                           \
                  << (errno ? ", error: " + std::string(strerror(errno)) : "") << std::endl                                        \
                  << std::flush;                                                                                                   \
        exit(1);                                                                                                                   \
    }

#ifdef ENABLE_NSIM_PROV_TRACE
#define NSIM_PROV_C_API_TRACE() NSIM_PROV_C_API_DEBUG("TRACE: " << __FUNCTION__ << ":" << __LINE__)
#else
#define NSIM_PROV_C_API_TRACE()

#endif
