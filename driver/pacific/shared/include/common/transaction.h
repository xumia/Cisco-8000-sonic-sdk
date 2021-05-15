// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __TRANSACTION_H__
#define __TRANSACTION_H__

#include "common/la_status.h"
#include <algorithm>
#include <cxxabi.h>
#include <deque>
#include <functional>

/// @file
/// @brief Transaction infrastructure.

namespace silicon_one
{

/// @brief Implementation of c++17 std::uncaught_exceptions() for gcc/clang.
inline int
uncaught_exceptions() noexcept
{
    return *(
        reinterpret_cast<unsigned int*>(static_cast<char*>(static_cast<void*>(__cxxabiv1::__cxa_get_globals())) + sizeof(void*)));
}

/// @brief Transaction.
///
/// Defines a transaction to which rollback functions can be registered.
/// These are executed in reverse order if the transaction is destroyed due
/// to exception, or if its status variable is set to error.

class transaction
{
public:
    using action_t = std::function<void()>;

    /// @brief  Monitored status variable.
    ///
    /// If set to a non-success value, the transaction will execute
    /// rollback functions on destruction.
    la_status status{LA_STATUS_SUCCESS};

    transaction() = default;

    // Allow move construction, disallow copying and assignment.
    transaction(transaction&&) = default;
    transaction(const transaction&) = delete;
    transaction& operator=(const transaction&) = delete;
    transaction& operator=(transaction&&) = delete;

    /// @brief  Register a rollback function to execute on transaction abort.
    ///
    /// @param[in] rollback function to execute
    void on_fail(action_t rollback)
    {
        m_rollbacks.push_back(move(rollback));
    }

    /// @brief  Register an action (function) to execute on transaction destruction.
    ///
    /// @param[in] action to execute
    void on_exit(action_t action)
    {
        m_on_exit.push_back(move(action));
    }

    /// @brief  Abort the transaction, executing rollbacks.
    void abort()
    {
        for_each(m_rollbacks.rbegin(), m_rollbacks.rend(), [](action_t& f) { f(); });

        m_rollbacks.clear();
    }

    /// @brief  execute on exit actions.
    void terminate()
    {
        for_each(m_on_exit.rbegin(), m_on_exit.rend(), [](action_t& f) { f(); });

        m_on_exit.clear();
    }

    ~transaction()
    {
        if (status != LA_STATUS_SUCCESS || uncaught_exceptions() > m_uncaught_exceptions) {
            abort();
        }

        terminate();
    }

private:
    const int m_uncaught_exceptions{uncaught_exceptions()};

    std::deque<action_t> m_rollbacks;
    std::deque<action_t> m_on_exit;
};

} // namespace silicon_one

#endif // __TRANSACTION_H__
