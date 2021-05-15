// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __WEAK_PTR_UNSAFE_H__
#define __WEAK_PTR_UNSAFE_H__

#include "dassert.h"
#include <memory>

namespace silicon_one
{

template <class T>
class weak_ptr_unsafe
{

    template <class U>
    friend class weak_ptr_unsafe;

public:
    weak_ptr_unsafe() : m_raw_ptr(nullptr)
    {
    }

    weak_ptr_unsafe(std::nullptr_t) : m_raw_ptr(nullptr)
    {
    }

    // allow this constructor only for convertible types
    template <class U, typename = typename std::enable_if<std::is_convertible<U*, T*>::value>::type>
    weak_ptr_unsafe(const std::shared_ptr<U>& sptr) : m_ptr((std::shared_ptr<T>)sptr), m_raw_ptr(sptr.get())
    {
    }

    template <class U>
    weak_ptr_unsafe(const std::weak_ptr<U>& wptr) : m_ptr(wptr), m_raw_ptr(wptr.lock().get())
    {
    }

    template <class U>
    weak_ptr_unsafe(const weak_ptr_unsafe<U>& wptr) : m_ptr(wptr.lock()), m_raw_ptr(wptr.get())
    {
    }

    std::shared_ptr<T> lock() const
    {
        return m_ptr.lock();
    }

    void reset()
    {
        m_ptr.reset();
        m_raw_ptr = nullptr;
    }

    T* operator->() const
    {
        dassert_crit(m_ptr.lock());
        return get();
    }

    T* operator->()
    {
        dassert_crit(m_ptr.lock());
        return get();
    }

    T& operator*()
    {
        dassert_crit(m_ptr.lock());
        return *get();
    }

    const T& operator*() const
    {
        dassert_crit(m_ptr.lock());
        return *get();
    }

    T* get() const
    {
        return m_raw_ptr;
    }

    T* get()
    {
        return m_raw_ptr;
    }

    operator bool() const
    {
        return get() != nullptr;
    }

    weak_ptr_unsafe& operator=(std::nullptr_t)
    {
        m_ptr.reset();
        m_raw_ptr = nullptr;

        return *this;
    }

    weak_ptr_unsafe& operator=(const weak_ptr_unsafe& other)
    {
        if (this != &other) {
            m_ptr.reset();
            m_raw_ptr = nullptr;

            m_ptr = other.m_ptr;
            m_raw_ptr = other.m_raw_ptr;
        }

        return *this;
    }

    template <class U>
    const weak_ptr_unsafe<U> weak_ptr_dynamic_cast() const
    {
        return std::dynamic_pointer_cast<U>(m_ptr.lock());
    }

    template <class U>
    const weak_ptr_unsafe<U> weak_ptr_static_cast() const
    {
        return std::static_pointer_cast<U>(m_ptr.lock());
    }

    template <class U>
    const weak_ptr_unsafe<U> weak_ptr_const_cast() const
    {
        return std::const_pointer_cast<U>(m_ptr.lock());
    }

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_ptr);
        m_raw_ptr = m_ptr.lock().get();
    }

private:
    std::weak_ptr<T> m_ptr;
    T* m_raw_ptr;
};

template <class T>
bool
operator==(const weak_ptr_unsafe<T>& lhs, std::nullptr_t)
{
    return lhs.get() == nullptr;
}

template <class T>
bool
operator!=(const weak_ptr_unsafe<T>& lhs, std::nullptr_t)
{
    return lhs.get() != nullptr;
}

template <class T>
bool
operator==(std::nullptr_t, const weak_ptr_unsafe<T>& rhs)
{
    return rhs.get() == nullptr;
}

template <class T>
bool
operator!=(std::nullptr_t, const weak_ptr_unsafe<T>& rhs)
{
    return rhs.get() != nullptr;
}

template <class T>
bool
operator<(const weak_ptr_unsafe<T>& lhs, const weak_ptr_unsafe<T>& rhs)
{
    return lhs.get() < rhs.get();
}

template <class T>
bool
operator==(const weak_ptr_unsafe<T>& lhs, const std::shared_ptr<T>& rhs)
{
    return lhs.get() == rhs.get();
}

template <class T>
bool
operator!=(const weak_ptr_unsafe<T>& lhs, const std::shared_ptr<T>& rhs)
{
    return lhs.get() != rhs.get();
}

template <class T>
bool
operator==(const std::shared_ptr<T>& lhs, const weak_ptr_unsafe<T>& rhs)
{
    return lhs.get() == rhs.get();
}

template <class T>
bool
operator!=(const std::shared_ptr<T>& lhs, const weak_ptr_unsafe<T>& rhs)
{
    return lhs.get() != rhs.get();
}

template <class T, class U>
bool
operator==(const weak_ptr_unsafe<T>& lhs, const weak_ptr_unsafe<U>& rhs)
{
    return lhs.get() == rhs.get();
}

template <class T, class U>
bool
operator!=(const weak_ptr_unsafe<T>& lhs, const weak_ptr_unsafe<U>& rhs)
{
    return lhs.get() != rhs.get();
}

template <class T, class U>
bool
operator==(const weak_ptr_unsafe<T>& lhs, const U* rhs)
{
    return (const void*)(lhs.get()) == (const void*)rhs;
}

template <class T, class U>
bool
operator!=(const weak_ptr_unsafe<T>& lhs, const U* rhs)
{
    return (const void*)(lhs.get()) != (const void*)rhs;
}

template <class T, class U>
bool
operator==(const T* lhs, const weak_ptr_unsafe<U>& rhs)
{
    return (const void*)lhs == (const void*)(rhs.get());
}

template <class T, class U>
bool
operator!=(const T* lhs, const weak_ptr_unsafe<U>& rhs)
{
    return (const void*)lhs != (const void*)(rhs.get());
}

} // namespace silicon_one

#endif
