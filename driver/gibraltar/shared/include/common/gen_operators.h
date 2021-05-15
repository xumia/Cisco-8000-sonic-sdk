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

#ifndef __GEN_OPERATORS_H__
#define __GEN_OPERATORS_H__

#include <functional>

namespace silicon_one
{

/// @brief Delete unary operator.
///
/// Invokes the delete operator.
/// For example, can be used to delete all items in a container:
///
/// foreach(c.begin(), c.end(), delete_operator());
struct delete_operator {
    template <class T>
    void operator()(T* object)
    {
        delete object;
    }
};

/// @brief Delete all entries in a container, and clear it.
///
/// @param[in]    container      Container to clear and erase all entries of.
template <class T>
void
delete_and_clear_container(T& container)
{
    auto last = container.end();
    for (auto first = container.begin(); first != last; ++first) {
        delete *first;
    }
    container.clear();
}

/// @brief Generic address-based compare, hash operators go smart pointers.
template <class HANDLE>
struct handle_ops {
    inline bool operator()(const HANDLE& lhs, const HANDLE& rhs) const
    {
        return lhs.get() < rhs.get();
    }

    inline size_t operator()(const HANDLE& h) const
    {
        return std::hash<typename HANDLE::element_type*>{}(h.get());
    }
};

} // namespace silicon_one

#endif
