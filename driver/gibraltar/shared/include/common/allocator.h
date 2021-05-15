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

#ifndef __ALLOCATOR_H__
#define __ALLOCATOR_H__

#include <list>
#include <mutex>

#include "common/allocator_config.h"
#include "common/defines.h"

namespace silicon_one
{

template <typename _BaseAllocator>
class thread_cache_allocator;

/// @brief Manages thread_cache_allocator per thread instance.
class thread_allocator_manager
{
public:
    using thread_allocator = thread_cache_allocator<allocator_traits::central_allocator>;

    /// @brief Allocates memory chunk with size.
    ///
    /// param[in]   size    size of block to allocate.
    /// @return Returns a block of given size.
    static void* allocate(const size_t size)
    {
        return allocate_fn(size);
    }

    /// @brief Deallocates memory chunk of given size.
    ///
    /// param[in]   p      pointer to the block to deallocate.
    /// param[in]   size   size of the block to release.
    static void deallocate(void* p, const size_t size)
    {
        deallocate_fn(p, size);
    }

    /// @brief Reallocates memory chunk.
    ///
    /// @param[in]   p          pointer to the block to reallocate.
    /// @param[in]   old_size   size of the pointer to reallocate.
    /// @param[in]   new_size   size of new block which is result of reallocation.
    /// @returns                pointer to the new memory chunk.
    static void* reallocate(void* p, const size_t old_size, const size_t new_size)
    {
        return reallocate_fn(p, old_size, new_size);
    }

    /// @brief Lazy initializes and returns an instance of #thread_allocator.
    static thread_allocator* get_allocator();

private:
    /// @brief Constructor.
    thread_allocator_manager();

    /// @brief Destructor.
    ~thread_allocator_manager();

    /// @brief Destroys unused thread_allocator instances
    void destroy_unused_thread_allocators();

    /// @brief Initializes a single instance of per thread allocator.
    static thread_allocator* initialize_thread_allocator();

    /// @brief Destroys instance of thread allocator.
    static void destroy_thread_allocator(thread_allocator* p);

    /// @brief Initializes thread allocator manager.
    static void initialize_thread_allocator_manager();

    /// @brief Destroys thread allocator manager.
    static void destroy_thread_allocator_manager();

    static thread_allocator_manager* m_thread_allocator_manager; ///< Pointer to instance of thread allocator manager.
    static std::once_flag m_initialize_thread_allocator_once;

    allocator_traits::central_allocator* m_pool;          ///< Instance of central allocator.
    std::list<thread_allocator*> m_allocators_to_destroy; ///< List of allocators that are no longer used and can be destroyed.
    std::mutex m_my_mutex; ///< Mutex used internally by thread_allocator_manager for synchronization.

    static void* (*allocate_fn)(const size_t size);                                       ///< Pointer to allocate function.
    static void (*deallocate_fn)(void* p, const size_t size);                             ///< Pointer to deallocate function.
    static void* (*reallocate_fn)(void* p, const size_t old_size, const size_t new_size); /// Pointer to reallocate function.
};

} // namespace silicon_one

#endif
