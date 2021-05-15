// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef _SIGNAL_HANDLER_H_
#define _SIGNAL_HANDLER_H_

#include <map>
#include <thread>
#include <mutex>
#include <signal.h>
#include <functional>

#if defined(_WIN32) || defined(_WIN64)
// Not supported on Windows
#define SIGUSR2 -1
#endif

namespace npsuite
{

/**
 * @brief A singleton class that handles signal handling via callbacks
 *
 * The `SignalHandler` class is a singleton that registers a signal handler for the fatal
 * signals `SIGTERM`, `SIGSEGV`, `SIGABRT`, `SIGILL`, and `SIGFPE`, and the non-fatal signal `SIGINT`.
 * It also maintains a registry of callback functions.  When a signal is caught, the callbacks
 * are invoked in reverse order, i.e., the most recently added is invoked first.
 *
 * Callbacks are invoked on a best-effort basis.  There are several situations that could
 * result in a callback not being invoked, including:
 *  - A second signal (of the same of different type) is caught before the callback has run
 *  - The thread on which the signal was caught holds locks or other resources that prevent
 *    either the signal handler itself or another callback from running
 *  - Another callback takes too long to run
 *
 * Callbacks are given a limited time to complete before the signal is re-raised (regardless
 * of whether all callbacks have completed or not).
 */
class SignalHandler
{
public:
    /// Return the single instance.  Installs the signal handler if it is not already installed.
    static SignalHandler& GetInstance();

    /// The type of a callback handle returned by AddCallback() and passed to RemoveCallback()
    typedef uint64_t CallbackId_t;
    /// a CallbackId that will never be returned as a value from addCallback
    static const CallbackId_t NoCallbackId = 0;
    /// Add a callback to the registry
    CallbackId_t AddCallback(std::function<void(int)>); // also automatically converts args of type void(* const func)(int)
    /// Add a member function callback to the registry
    template <class T>
    CallbackId_t AddCallback(T* const object, void (T::*const memberFunc)(int))
    {
        auto func = std::bind(memberFunc, object, std::placeholders::_1);
        return AddCallback(func);
    }
    /// Remove a callback using the ID returned from AddCallback().  Does nothing if no such callback exists in the registry.
    void RemoveCallback(CallbackId_t);

    /// The set of values appropriate for use with SetVerbosity() and GetVerbosity()
    enum class Verbosity : sig_atomic_t { SILENT, ERRORS_ONLY, DEFAULT, CHATTY, MAX };
    /**
     * @brief Set the current verbosity level
     *
     * The SignalHandler can produce various output to `stderr` about its operation.
     * This function allows control over whether that output is produced.
     */
    static void SetVerbosity(Verbosity);
    /// Return the current verbosity level.
    static Verbosity GetVerbosity();

private:
    SignalHandler();
    ~SignalHandler();
    // delete copy and move constructors and assignment operators
    SignalHandler(const SignalHandler&) = delete;
    SignalHandler& operator=(const SignalHandler&) = delete;
    SignalHandler(SignalHandler&&) = delete;
    SignalHandler& operator=(SignalHandler&&) = delete;

    void CallbackThreadMain();
    void User2HandlerThreadMain();
    std::mutex mCallbacksMutex;
    std::map<CallbackId_t, std::function<void(int)>> mCallbacks;
};
} // namespace npsuite

#endif /* UTILS_SIGNAL_HANDLER_H_ */
