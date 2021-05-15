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

#ifndef __COMMON_DEFINES_H__
#define __COMMON_DEFINES_H__

#define concat_tokens2(a, b) a##b
#define concat_tokens(a, b) concat_tokens2(a, b)
///@brief check status. Return immediately on failure.
#define return_on_error_no_log(X)                                                                                                  \
    do {                                                                                                                           \
        la_status __return_on_error_status = X;                                                                                    \
        if (__return_on_error_status != LA_STATUS_SUCCESS) {                                                                       \
            return __return_on_error_status;                                                                                       \
        }                                                                                                                          \
    } while (0)

///@brief Check status. Generate a log message, then return.
#define return_on_error_log(X, component, level, format, ...)                                                                      \
    do {                                                                                                                           \
        la_status __return_on_error_status = X;                                                                                    \
        if (__return_on_error_status != LA_STATUS_SUCCESS) {                                                                       \
            log_message_internal(component,                                                                                        \
                                 level,                                                                                            \
                                 "%s::%d %s status = %s, " format,                                                                 \
                                 __FILE__,                                                                                         \
                                 __LINE__,                                                                                         \
                                 __func__,                                                                                         \
                                 la_status2str(__return_on_error_status).c_str(),                                                  \
                                 ##__VA_ARGS__);                                                                                   \
            return __return_on_error_status;                                                                                       \
        }                                                                                                                          \
    } while (0)

#define GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, NAME, ...) NAME
#define return_on_error(...)                                                                                                       \
    GET_MACRO(__VA_ARGS__,                                                                                                         \
              return_on_error_log,                                                                                                 \
              return_on_error_log,                                                                                                 \
              return_on_error_log,                                                                                                 \
              return_on_error_log,                                                                                                 \
              return_on_error_log,                                                                                                 \
              return_on_error_log,                                                                                                 \
              return_on_error_log,                                                                                                 \
              return_on_error3,                                                                                                    \
              return_on_error2,                                                                                                    \
              return_on_error_no_log)                                                                                              \
    (__VA_ARGS__)

///@brief Check status. Generate a log message, then break.
#define log_on_error(X, component, level, format, ...)                                                                             \
    do {                                                                                                                           \
        la_status __return_on_error_status = X;                                                                                    \
        if (__return_on_error_status != LA_STATUS_SUCCESS) {                                                                       \
            log_message_internal(component, level, "%s::%d %s " format, __FILE__, __LINE__, __func__, ##__VA_ARGS__);              \
        }                                                                                                                          \
    } while (0)

#define return_void_on_error_log(X, component, level, format, ...)                                                                 \
    do {                                                                                                                           \
        la_status __return_on_error_status = X;                                                                                    \
        if (__return_on_error_status != LA_STATUS_SUCCESS) {                                                                       \
            log_message_internal(component, level, "%s::%d %s " format, __FILE__, __LINE__, __func__, ##__VA_ARGS__);              \
            return;                                                                                                                \
        }                                                                                                                          \
    } while (0)

#define LA_UNUSED __attribute__((unused))

#define LA_PACKED __attribute__((packed))

#define LA_ALIGNED(x) __attribute__((aligned(x)))

#define LA_LIKELY(condition) __builtin_expect(static_cast<bool>(condition), 1)

#define LA_UNLIKELY(condition) __builtin_expect(static_cast<bool>(condition), 0)

#if __llvm__ == 1
#define LA_MAYBE_UNUSED __attribute__((unused))
#else
#define LA_MAYBE_UNUSED
#endif

#define STRINGIFY(s) MACRO_AS_STRING(s)
#define MACRO_AS_STRING(s) #s

#ifdef __aarch64__
#define SPINLOCK_NOP __asm__ __volatile__("yield")
#else
#define SPINLOCK_NOP __builtin_ia32_pause()
#endif

#endif
