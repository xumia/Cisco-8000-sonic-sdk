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

#ifndef __DASSERT_H__
#define __DASSERT_H__

#include <string>

#if defined __cplusplus && __GNUC_PREREQ(2, 95)
#define __ASSERT_VOID_CAST static_cast<void>
#else
#define __ASSERT_VOID_CAST (void)
#endif

namespace silicon_one
{

class dassert
{
public:
    /// @brief Assert levels.
    enum class level_e {
        CRITICAL = 0, ///< Critical assert. Hitting it typically means the SDK is in a unstable state.
        NCRITICAL,    ///< Non-critical assert. Hitting it may be an indication of an issue.
        SLOW,         ///< Computationally-heavy assert. Enabling these will impact application performance.
        NUM_LEVELS
    };

    /// @brief Behaviour setings for assert level.
    struct settings {
        bool skip;      ///< Skip the assert completely.
        bool terminate; ///< Terminate on failure. If this flag is set than failure requires termination.
        bool backtrace; ///< Backtrace. If set then print backtrace on failure.
        bool proc_maps; ///< Process maps. If set then print /proc/self/maps on failure.
    };

    /// @brief Get the singleton.
    ///
    /// @return    Singleton instance of dassert.
    static inline dassert& instance()
    {
        static dassert s_assert_instance;
        return s_assert_instance;
    }

    /// @brief Get dynamic assert behavior for severity level.
    ///
    /// @param[in]  level             Level for which to fetch settings.
    /// @return     Structure holding settings for this level.
    const settings& get_settings(level_e level) const
    {
        return m_level_settings_array[static_cast<int>(level)];
    }

    /// @brief Set dynamic assert behavior for severity level.
    ///
    /// @param[in]  level                Change settings for this level.
    /// @param[in]  settings             New settings to be applied.
    void set_settings(const level_e level, const settings& settings);

    /// @brief To be called in case of assert failure.
    ///
    /// @param[in]  level            Severity level of the failed assert.
    ///                              This determines the action to be taken if the assert fails,
    ///                              and the information to be printed out.
    /// @param[in]  line             Line on which the error occured.
    /// @param[in]  function         Function on which the error occured.
    /// @param[in]  file             File on which the error occured.
    /// @param[in]  expr_str         String repressenting the failed expression.
    /// @param[in]  format           Printf like format string.
    void assert_fail(const level_e level,
                     const size_t line,
                     const std::string& function,
                     const std::string& file,
                     const std::string& expr_str,
                     const char* format,
                     ...);

    /// @brief assert_fail without the format string
    ///
    /// @param[in]  level            Severity level of the failed assert.
    ///                              This determines the action to be taken if the assert fails,
    ///                              and the information to be printed out.
    /// @param[in]  line             Line on which the error occured.
    /// @param[in]  function         Function on which the error occured.
    /// @param[in]  file             File on which the error occured.
    /// @param[in]  expr_str         String repressenting the failed expression.
    void assert_fail(const level_e level,
                     const size_t line,
                     const std::string& function,
                     const std::string& file,
                     const std::string& expr_str);

private:
    dassert();
    ~dassert();

    /// @brief This is where configurations for each level are defined.
    settings m_level_settings_array[static_cast<int>(level_e::NUM_LEVELS)];

}; // class dassert

} // namespace silicon_one

#ifndef SWIG

/// @brief Evaluates the expression if skip is not set for this level, and in case of failure calls assert_fail.
///
/// @param[in]  expr             Expression to be evaluated.
/// @param[in]  level            Severity level of the assertion.
///                              This determines the action to be taken if the assert fails,
///                              and the information to be printed out.
/// @param[in]  format           Additional message to be printed, in the format of printf.
#ifndef LEABA_NO_DASSERTS
#define dassert_base(expr, level, ...)                                                                                             \
    {                                                                                                                              \
        /*if settings skip is set than we completly ignore the assert*/                                                            \
        if (silicon_one::dassert::instance().get_settings(level).skip == 0) {                                                      \
            ((expr)                                                                                                                \
                 ? __ASSERT_VOID_CAST(0)                                                                                           \
                 : silicon_one::dassert::instance().assert_fail((level), __LINE__, __FUNCTION__, __FILE__, #expr, ##__VA_ARGS__)); \
        } else {                                                                                                                   \
            __ASSERT_VOID_CAST(0);                                                                                                 \
        }                                                                                                                          \
    }
#else
#define dassert_base(expr, level, ...) (__ASSERT_VOID_CAST(0))
#endif

/// @brief Does dynamic assert, but with CRITICAL level.
///
/// @param[in]  expr             Expression to be evaluated.
/// @param[in]  ...              A printf like format string followed by additional arguments.
#define dassert_crit(expr, ...) dassert_base(expr, silicon_one::dassert::level_e::CRITICAL, ##__VA_ARGS__)

/// @brief Does dynamic assert, but with NCRITICAL level.
///
/// @param[in]  expr             Expression to be evaluated
/// @param[in]  ...              A printf like format string followed by additional arguments.
#define dassert_ncrit(expr, ...) dassert_base(expr, silicon_one::dassert::level_e::NCRITICAL, ##__VA_ARGS__)

/// @brief Does dynamic assert, but with SLOW level.
///
/// @param[in]  expr             Expression to be evaluated
/// @param[in]  ...              A printf like format string followed by additional arguments.
#define dassert_slow(expr, ...) dassert_base(expr, silicon_one::dassert::level_e::SLOW, ##__VA_ARGS__)

#endif /* #ifndef SWIG */

#endif /* __DASSERT_H__ */
