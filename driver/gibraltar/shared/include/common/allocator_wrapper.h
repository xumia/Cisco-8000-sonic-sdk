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

#ifndef __ALLOCATOR_WRAPPER_H__
#define __ALLOCATOR_WRAPPER_H__

#include <bits/functexcept.h>
#include <bits/move.h>
#include <list>
#include <map>
#include <set>
#include <stddef.h>
#include <unordered_map>
#include <vector>

#include "common/allocator.h"

/// @file
/// @brief Leaba memory allocator wrapper.

namespace silicon_one
{

/// @brief allocator_wrapper class definition.
///
/// Leaba memory allocator wrapper.
template <typename _Tp>
class allocator_wrapper
{
public:
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef _Tp* pointer;
    typedef const _Tp* const_pointer;
    typedef _Tp& reference;
    typedef const _Tp& const_reference;
    typedef _Tp value_type;

    template <typename _Tp1>
    struct rebind {
        typedef allocator_wrapper<_Tp1> other;
    };

    allocator_wrapper()
    {
    }

    allocator_wrapper(const allocator_wrapper&)
    {
    }

    template <typename _Tp1>
    allocator_wrapper(const allocator_wrapper<_Tp1>&)
    {
    }

    ~allocator_wrapper()
    {
    }

    pointer address(reference __x) const
    {
        return std::__addressof(__x);
    }

    const_pointer address(const_reference __x) const
    {
        return std::__addressof(__x);
    }

    pointer allocate(size_type __n, const void* = 0)
    {
        return static_cast<_Tp*>(silicon_one::thread_allocator_manager::allocate(__n * sizeof(_Tp)));
    }

    void deallocate(pointer __p, size_type __n)
    {
        silicon_one::thread_allocator_manager::deallocate(__p, __n * sizeof(_Tp));
    }

    size_type max_size() const
    {
        return size_t(-1) / sizeof(_Tp);
    }

    template <typename _Tp1, class... Args>
    void construct(_Tp1* __p, Args&&... __args)
    {
        ::new ((void*)__p) _Tp1(std::forward<Args>(__args)...);
    }

    void destroy(pointer __p)
    {
        __p->~_Tp();
    }
};

template <class X, class Y>
inline bool
operator==(const allocator_wrapper<X>& lhs, const allocator_wrapper<Y>& rhs)
{
    return true;
}

template <class X, class Y>
inline bool
operator!=(const allocator_wrapper<X>& lhs, const allocator_wrapper<Y>& rhs)
{
    return !(lhs == rhs);
}

/// @name Type helper templates.
///
/// Simplify the use of allocator in containers.
///
/// @{

template <class T>
using vector_alloc = std::vector<T, allocator_wrapper<T> >;

template <class T>
using list_alloc = std::list<T, allocator_wrapper<T> >;

template <class T, class _Less = std::less<T> >
using set_alloc = std::set<T, _Less, allocator_wrapper<T> >;

template <class K, class V, class K_less = std::less<K> >
using map_alloc = std::map<K, V, K_less, allocator_wrapper<std::pair<const K, V> > >;

template <class K, class V, class H = std::hash<K>, class K_equal = std::equal_to<K> >
using unordered_map_alloc = std::unordered_map<K, V, H, K_equal, allocator_wrapper<std::pair<const K, V> > >;

template <class T, class Compare = std::less<T> >
using multiset_alloc = std::multiset<T, Compare, allocator_wrapper<T> >;

/// @}

} // namespace silicon_one

#endif
