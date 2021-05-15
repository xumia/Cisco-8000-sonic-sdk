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

#include <assert.h>

#include <algorithm> // std::find
#include <chrono>    // std::tm
#include <fstream>   // std::ifstream
#include <iostream>  // std::cerr
#include <list>      // std::accumulate
#include <map>
#include <mutex>   // std::mutex
#include <numeric> // std::accumulate
#include <signal.h>
#include <sstream>
#include <string>
#include <thread> // std::lock_guard
#include <vector>

#include <map>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "nsim/nsim_log_interface.h"
#include "nsim_provider/nsim_provider.h"

#undef ENABLE_NSIM_PROV_DEBUGGING
#undef ENABLE_NSIM_PROV_TRACE

#define NSIM_LOG_PREFIX "NSIM provider test : "
#define NSIM_PROV_RPC_API_PREFIX "NSIM prov (RPC API): "
#define NSIM_PROV_C_API_PREFIX "NSIM prov (C API)  : "

#define NSIM_PROV_INFO(msg)                                                                                                        \
    if (m_logging_enabled) {                                                                                                       \
        std::cerr << time_now() << " " NSIM_LOG_PREFIX "INFO: (pid " << getpid() << ") " << msg << std::endl << std::flush;        \
    }

#define NSIM_PROV_DEBUG(msg)                                                                                                       \
    if (m_debug_enabled) {                                                                                                         \
        std::cerr << time_now() << " " NSIM_LOG_PREFIX "DEBUG: (pid " << getpid() << ") " << msg << std::endl << std::flush;       \
    }

#define NSIM_PROV_G_DEBUG(msg)                                                                                                     \
    if (g_debug_enabled) {                                                                                                         \
        std::cerr << time_now() << " " NSIM_LOG_PREFIX "DEBUG: (pid " << getpid() << ") " << msg << std::endl << std::flush;       \
    }

#define NSIM_PROV_ERROR(msg)                                                                                                       \
    {                                                                                                                              \
        std::cerr << time_now() << " " NSIM_LOG_PREFIX "ERROR: (pid " << getpid() << ") " << msg << " at " << __FILE__ << ", "     \
                  << __FUNCTION__ << ":" << __LINE__ << std::endl                                                                  \
                  << std::flush;                                                                                                   \
    }

#define NSIM_PROV_FATAL(msg)                                                                                                       \
    {                                                                                                                              \
        std::cerr << time_now() << " " NSIM_LOG_PREFIX "FATAL-ERROR: (pid " << getpid() << ") " << msg << " at " << __FILE__       \
                  << ", " << __FUNCTION__ << ":" << __LINE__ << (errno ? ", error: " + std::string(strerror(errno)) : "")          \
                  << std::endl                                                                                                     \
                  << std::flush;                                                                                                   \
        exit(1);                                                                                                                   \
    }

#ifdef ENABLE_NSIM_PROV_TRACE
#define NSIM_PROV_TRACE() NSIM_PROV_DEBUG("TRACE: " << __FUNCTION__ << ":" << __LINE__)
#else
#define NSIM_PROV_TRACE()
#endif

static inline std::string
to_string(const std::string& s)
{
    return s;
}

//
// Map to string
//
template <typename K, typename V>
static inline std::string
map_to_string(const std::map<K, V>& m)
{
    std::string out = std::accumulate(m.begin(), m.end(), std::string(), [](const std::string& acc, const std::pair<K, V>& elem) {
        return acc + (acc.empty() ? std::string() : ", ") + "'" + elem.first + "' : '" + elem.second + "'";
    });
    return "{" + out + "}";
}

//
// Convert a container of to_string things to a string
//
template <class BaseType, template <typename Elem, typename Allocator = std::allocator<Elem> > class Container>
static inline const std::string
to_string(const Container<BaseType>& elems)
{
    std::string out = "[";
    for (const auto& elem : elems) {
        if (out.size() > 1) {
            out += ", ";
        }
        out += to_string(elem);
    }
    out += "]";
    return out;
}

namespace silicon_one
{
extern std::string time_now(void);
extern bool g_debug_enabled;
}
