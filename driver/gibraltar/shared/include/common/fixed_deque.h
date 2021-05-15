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

#ifndef __COMMON_FIXED_DEQUE__
#define __COMMON_FIXED_DEQUE__

#include <deque>
#include <unistd.h>

namespace silicon_one
{

/// @brief Queue with max size management
template <typename T>
class fixed_deque : public std::deque<T>
{
public:
    fixed_deque() : std::deque<T>()
    {
        this->m_max_size = 0;
    }

    explicit fixed_deque(size_t size) : std::deque<T>()
    {
        this->m_max_size = size;
    }

    /// @return void
    /// @brief Add push() to implement a queue
    ///
    /// @return void
    void push(const T& val)
    {
        std::deque<T>::push_front(val);
        // resize if we are over our max
        this->resize_queue();
    };

    /// @brief Add pop() to resemble a queue
    ///
    /// @return void
    void pop()
    {
        // only pop if there is something to pop
        if (this->size() > 0) {
            std::deque<T>::pop_back();
        }
    };

    /// @brief Set the max size of the queue
    ///
    /// @return void
    void set_max_size(size_t size)
    {
        // set changes and resize_queue
        this->m_max_size = size;
        this->resize_queue();
    };

    /// @brief Get the max size of the queue
    ///
    /// @return void
    size_t max_size()
    {
        return this->m_max_size;
    };

// For serialization purposes only
#ifdef ENABLE_SERIALIZATION
    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(*(static_cast<std::deque<T>*>(this)));
        ar(m_max_size);
    }
#endif

private:
    /// @brief Resize the queue to m_max size if larger
    ///
    /// @return void
    void resize_queue()
    {

        // pop until queue size is 0 or (m_max_size - 1)
        while (this->size() > this->m_max_size) {
            this->pop();
        }
    };

    size_t m_max_size;
};

} // namespace silicon_one

#endif // __COMMON_FIXED_DEQUE__
