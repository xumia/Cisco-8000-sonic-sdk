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

#ifndef __LA_FUNCTION_H__
#define __LA_FUNCTION_H__

namespace silicon_one
{

/// @brief std::function like interface
///
template <typename T>
struct la_function;

template <typename Result, typename... Args>
struct la_function<Result(Args...)> {
    virtual Result operator()(Args...) = 0;
    virtual ~la_function()
    {
    }
};

template <class Archive, typename... Args>
void
save(Archive& ar, const la_function<Args...>&)
{
}
template <class Archive, typename... Args>
void
load(Archive& ar, la_function<Args...>&)
{
}

} // namespace silicon_one

#endif // __LA_FUNCTION_H__
