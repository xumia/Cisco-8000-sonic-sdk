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

#ifndef __GEN_UTILS_H__
#define __GEN_UTILS_H__

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>

namespace silicon_one
{

/// @brief Return the number of elements in the given array.
template <class T, size_t N>
constexpr size_t
array_size(const T (&)[N])
{
    return N;
}

/// @brief Implementation of C++14 make_unique for single objects
/// TODO: Use std::make_unique if we move to c++14
template <typename T, typename... Args>
inline std::unique_ptr<T>
make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

/// @brief Cast an enum to its underlying integer type
/// Safer than c-style casts and more concise than static_cast
template <typename E>
constexpr typename std::underlying_type<E>::type
to_utype(E enumerator)
{
    return static_cast<typename std::underlying_type<E>::type>(enumerator);
}

/// @brief Convert an integer to an enum and check if in range.
/// Only works for 'enum' types that define FIRST and LAST.
template <typename _enum>
bool
numeric_to_enum(uint64_t n, _enum& e)
{
    bool in_range = (n >= static_cast<uint64_t>(_enum::FIRST) && n <= static_cast<uint64_t>(_enum::LAST));
    if (in_range) {
        e = static_cast<_enum>(n);
    }

    return in_range;
}

/// @brief Check whether element exists in container.
///
/// @param[in]   container     container to search in.
/// @param[in]   element       element to search in container.
///
/// @return true if element exists in container, false otherwise.
template <typename C, typename T>
bool
contains(const C& container, const T& element)
{
    return (std::find(container.begin(), container.end(), element)) != container.end();
}

/// @brief Check whether element exists in map.
///
/// @param[in]   map_container map to search in.
/// @param[in]   element       element to search in container.
///
/// @return true if element exists in map, false otherwise.
template <typename T, typename... C>
bool
contains(const std::map<C...>& map_container, const T& element)
{
    return map_container.find(element) != std::end(map_container);
}

///@brief print in the buffer current timestamp.
///
/// Timestamp is in the format "d-m-Y H:M:S.msec".
/// d    - day of the month.
/// m    - month.
/// Y    - year.
/// H    - hour.
/// M    - Minute.
/// S    - Seconds
/// msec - milliseconds.
///
///@param[in] buffer       buffer to store the timestamp in.
///@param[in] buffer_size  size of the buffer in bytes.
size_t add_timestamp(char* buffer, size_t buffer_size);
std::string get_current_timestamp();

template <typename C, typename T>
void
filter(C& container, const T& value)
{
    auto new_end = std::remove(container.begin(), container.end(), value);
    container.resize(new_end - container.begin());
}

/// @brief invoke shared_from_this and downcast the result to the appropriate type.
///
/// Useful for cases where shared_from_this is implemented at the base class,
/// and causes and unwanted cast to the base class when moving from raw to shared pointer.
///
/// @param[in]   obj       Raw object to convert.
///
/// @return std::shared_ptr<T>
template <class T>
std::shared_ptr<T>
typed_shared_from_this(T* obj)
{
    return obj ? std::static_pointer_cast<T>(obj->shared_from_this()) : std::shared_ptr<T>();
}

} // namespace silicon_one

#endif // __GEN_UTILS_H__
