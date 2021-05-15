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

#include "common/dassert.h"
#include <cstring>

#include "common/allocator.h"
#include "common/logger.h"

namespace silicon_one
{

namespace
{

static bool
use_leaba_allocator()
{
    char* allocator = getenv("LEABAMALLOC");
    if (allocator && (strcmp(allocator, "malloc") == 0)) {
        log_message(la_logger_component_e::ALLOCATOR, la_logger_level_e::DEBUG, "Using system memory allocation");
        return false;
    } else {
        log_message(la_logger_component_e::ALLOCATOR, la_logger_level_e::DEBUG, "Using leaba memory allocation");
        return true;
    }
}

static bool
debug_leaba_allocator()
{
    static bool debug_leaba_allocator = getenv("LEABA_ALLOCATOR_CHECK_");
    return debug_leaba_allocator;
}
}

/// @brief Chunks as linked list together with chunk count.
class chunk_list
{
public:
    /// @brief Constructor.
    chunk_list();

    /// @brief Destructor.
    ~chunk_list();

    /// @brief Remove one memory chunk from the top of the list.
    ///
    /// @return Memory chunk from chunk_list.
    void* pop_chunk()
    {
        dassert_crit(debug_count() == m_count);
        if (m_count == 0) {
            dassert_crit(m_head == nullptr);
            return nullptr;
        } else {
            chunk* result = m_head;
            m_head = m_head->next;
            m_count--;
            return (void*)result;
        }
    }

    /// @brief Push one chunk to the top of the list.
    ///
    /// @param[in]    chunk     Memory chunk to push to chunk_list.
    void push_chunk(void* chunk)
    {
        dassert_crit(debug_count() == m_count);
        dassert_crit(chunk != nullptr);
        chunk_list::chunk* new_chunk = (chunk_list::chunk*)chunk;
        new_chunk->next = m_head;
        m_head = new_chunk;
        m_count++;
    }

    /// @brief Number of chunks in chunk_list.
    ///
    /// @return number of chunks in chunk_list.
    size_t count() const
    {
        return m_count;
    }

private:
    /// @brief Copy c'tor - deleted.
    chunk_list(chunk_list&) = delete;

    /// @brief Move c'tor - deleted.
    chunk_list(chunk_list&&) = delete;

    /// @brief Copy assignment - deleted.
    chunk_list& operator=(const chunk_list&) = delete;

    /// @brief Move assignment - deleted.
    chunk_list& operator=(const chunk_list&&) = delete;

    /// @brief Internal representation of memory chunk to be used for list od chunks.
    struct chunk {
        chunk* next; ///< Pointer to the next memory chunk in list.
    };

    /// @brief Return the number of chunks in list by counting.
    ///
    /// @return Number of chunks by manual counting.
    size_t debug_count() const;

    chunk* m_head;  ///< Pointer to the first memory chunk in list.
    size_t m_count; ///< Number of memory chunks in list.
};

chunk_list::chunk_list() : m_head(nullptr), m_count(0)
{
}

chunk_list::~chunk_list()
{
    dassert_crit(m_count == 0);
}

size_t
chunk_list::debug_count() const
{
    if (debug_leaba_allocator()) {
        size_t result = 0;
        chunk* current = m_head;
        while (current != nullptr) {
            current = current->next;
            result++;
        }
        return result;
    } else {
        return m_count;
    }
}

/// @brief Central allocator based on system malloc/free.
class malloc_allocator
{
public:
    /// @brief Constructor.
    malloc_allocator();

    /// @brief Destructor.
    ~malloc_allocator();

    /// @brief Bulk allocate a number of chunks and puts them in the provided #list.
    ///
    /// param[in]    size    Size of each chunk to allocate.
    /// param[in]    count   Number of chunks to allocate.
    /// param[in,out]   list    List where new chunks will be added.
    void allocate_chunks(const size_t size, const size_t count, chunk_list& chunks);

    /// @brief Bulk deallocate a number of chunks taking them from the provided #list.
    ///
    /// param[in]       size    Size of each chunk in the list.
    /// param[in]       count   Number of chunks to deallocate from the #list.
    /// param[in,out]   list    List cointaining the chunks to be deallocated.
    void deallocate_chunks(const size_t size, const size_t count, chunk_list& chunks);

    /// @brief Recommended minimal number of chunks to allocate at once for optimum performance.
    ///
    /// @return Recommended minimal number of chunks to allocate at once for optimum performance.
    size_t get_config_chunks_to_allocate() const
    {
        return 100;
    }

    /// @brief Return true if allocator recommends fast warmup.
    ///
    /// Fast warmup is a mechanism to fast allocate a large number
    /// of memory chunks. The client can request more than
    /// recommended minimal number of chunks to allocate to speed
    /// up the allocation. This increases performance for some
    /// allocators, but not for all.
    ///
    /// @return Returns true if allocator recommends fast warmup.
    bool get_config_fast_warmup() const
    {
        return true;
    }
};

malloc_allocator::malloc_allocator()
{
}

malloc_allocator::~malloc_allocator()
{
}

void
malloc_allocator::allocate_chunks(const size_t size, const size_t count, chunk_list& chunks)
{
    for (size_t i = 0; i < count; i++) {
        void* c = malloc(size);
        chunks.push_chunk(c);
    }
}

void
malloc_allocator::deallocate_chunks(const size_t size, const size_t count, chunk_list& chunks)
{
    void* current;
    for (size_t i = 0; i < count; i++) {
        current = chunks.pop_chunk();
        if (!current) {
            break;
        }
        free(current);
    }
}

/// @brief #cache_line implements memory caching mechanism per memory chunk size.
template <typename _BaseAllocator>
class cache_line
{
public:
    /// @brief Constructs a new cache line with a given size.
    ///
    /// @param[in]  size         Size of cache line.
    /// @param[in]  allocator    Base allocator to use.
    cache_line(const size_t size, _BaseAllocator* const allocator)
        : m_my_size(size),
          m_chunks_on_single_alloc(allocator->get_config_chunks_to_allocate()),
          m_my_allocator(allocator),
          m_stat_allocations(0),
          m_stat_deallocations(0),
          m_stat_central_allocations(0),
          m_stat_central_deallocations(0),
          m_stat_peak_cache_size(0)
    {
    }

    /// @brief Destructor.
    ~cache_line()
    {
        empty_cache();
        dump_statistics();
        dassert_crit(m_free_chunks.count() == 0);
    }

    /// @brief Returns an available chunk from the cache line.
    ///        In case cache_line is empty, it allocated additional memory
    ///        from the base allocator.
    inline void* allocate_chunk()
    {
        if (m_keep_statistics) {
            m_stat_allocations++;
        }

        if (LA_UNLIKELY(m_free_chunks.count() == 0)) {
            base_allocator_allocate();
        }
        return m_free_chunks.pop_chunk();
    }

    /// @brief Returns unused chunk back to the cache line.
    ///
    /// @param[in] chunk   Chunk to return to the cache line.
    inline void deallocate_chunk(void* chunk)
    {
        size_t cache_size = m_free_chunks.count();
        if (LA_UNLIKELY(cache_size > allocator_traits::CACHE_LINE_MAX_SIZE)) {
            base_allocator_deallocate();
        }

        m_free_chunks.push_chunk(chunk);

        if (m_keep_statistics) {
            m_stat_deallocations++;
            m_stat_peak_cache_size = std::max(m_stat_peak_cache_size, m_free_chunks.count());
        }
    }

    /// @brief Empties cache line and returns all the chunks back
    ///        to the central allocator.
    void empty_cache()
    {
        size_t all_chunks = m_free_chunks.count();
        if (all_chunks == 0) {
            return;
        }

        m_my_allocator->deallocate_chunks(m_my_size, all_chunks, m_free_chunks);
        dassert_crit(m_free_chunks.count() == 0);

        if (m_keep_statistics) {
            m_stat_central_deallocations += all_chunks;
        }
    }

private:
    /// @brief Allocated additional chunks from the base allocator
    void base_allocator_allocate()
    {
        m_my_allocator->allocate_chunks(m_my_size, m_chunks_on_single_alloc, m_free_chunks);
        if (m_my_allocator->get_config_fast_warmup()) {
            m_chunks_on_single_alloc = m_chunks_on_single_alloc * 2;
        }

        if (m_keep_statistics) {
            m_stat_central_allocations += m_free_chunks.count();
        }
    }

    /// @brief Returns extra chunks to the base allocator.
    void base_allocator_deallocate()
    {
        size_t chunks_to_release = m_free_chunks.count() - allocator_traits::CACHE_LINE_MAX_SIZE;
        // Release chunks back to the central allocator if the cache line is too big
        if (chunks_to_release > allocator_traits::CACHE_LINE_MIN_CHUNKS_TO_RELEASE) {
            m_my_allocator->deallocate_chunks(m_my_size, chunks_to_release, m_free_chunks);

            if (m_keep_statistics) {
                m_stat_central_deallocations += chunks_to_release;
            }

            if (m_my_allocator->get_config_fast_warmup()) {
                m_chunks_on_single_alloc = m_my_allocator->get_config_chunks_to_allocate();
            }
        }
    }

    /// @brief Prints out cache line statistics.
    void dump_statistics()
    {
        if (m_keep_statistics) {
            log_message(la_logger_component_e::ALLOCATOR,
                        la_logger_level_e::INFO,
                        "Line size = %lu, allocations = %lu, deallocations = %lu, central alloc = %lu, central dealloc = %lu, peak "
                        "cache line = %lu\n",
                        m_my_size,
                        m_stat_allocations,
                        m_stat_deallocations,
                        m_stat_central_allocations,
                        m_stat_central_deallocations,
                        m_stat_peak_cache_size);
        }
    }

    chunk_list m_free_chunks; ///< Chunk list containing the cached chunks.
    const size_t m_my_size;   ///< Size of cache line, a.k.a all chunks in the cache line have this value.

    size_t m_chunks_on_single_alloc;      ///< Number of chunk to allocate from the base allocator in case cache line is empty.
    _BaseAllocator* const m_my_allocator; ///< Pointer to the base allocator.

#ifdef ALLOCATOR_STATISTICS
    static constexpr bool m_keep_statistics = true; ///< Keep statistics.
#else
    static constexpr bool m_keep_statistics = false; ///< Keep statistics.
#endif
    size_t m_stat_allocations;   ///< Statistics: number of chunks client asked from this cache line.
    size_t m_stat_deallocations; ///< Statistics: number of chunks client returned to this cache line.

    size_t m_stat_central_allocations;   ///< Statistics: number of chunks #cache_line allocated from base allocator.
    size_t m_stat_central_deallocations; ///< Statistics: number of chunks #cache_line returned to the base allocator.
    size_t m_stat_peak_cache_size;       ///< Statistics: maximum number of chunks in cache line during the life of #cache_line.
} LA_ALIGNED(64);

/// @brief Cache allocator instantiated per thread.
template <typename _BaseAllocator>
class thread_cache_allocator
{
public:
    /// @brief Constructor.
    ///
    /// param[in]   pool    Base allocator.
    thread_cache_allocator(_BaseAllocator* const pool)
        : m_base_allocator(pool), m_my_thread_id(pthread_self()), m_next_allocator(nullptr)
    {
        size_t cache_line_count = get_cache_line_count();
        posix_memalign((void**)&m_cache_lines, 64, cache_line_count * sizeof(cache_line<_BaseAllocator>));
        for (size_t i = 0; i < cache_line_count; i++) {
            ::new (&m_cache_lines[i]) cache_line<_BaseAllocator>(get_cache_line_size(i), m_base_allocator);
        }
    }

    /// @brief Destructor.
    ~thread_cache_allocator()
    {
        size_t cache_line_count = get_cache_line_count();
        for (size_t i = 0; i < cache_line_count; i++) {
            m_cache_lines[i].~cache_line<_BaseAllocator>();
        }

        free(m_cache_lines);
        m_cache_lines = nullptr;
    }

    /// @brief Allocate #size bytes.
    ///
    /// @param[in]   size  size of memory chunk to allocate.
    /// @return Returns pointer to the memory chunk of #size.
    inline void* allocate(const size_t size)
    {
        dassert_crit(m_my_thread_id == pthread_self());

        if (size < get_max_allocatable_size()) {
            size_t cache_line_index = get_cache_line_index(size);

            cache_line<_BaseAllocator>* const cache_line = &m_cache_lines[cache_line_index];

            return cache_line->allocate_chunk();
        } else {
            return malloc(size);
        }
    }

    /// @brief Deallocates block of #size.
    ///
    /// @param[in]    p      pointer to deallocate.
    /// @param[in]    size   size of the block to deallocate.
    inline void deallocate(void* p, const size_t size)
    {
        dassert_crit(m_my_thread_id == pthread_self());
        if (!p) {
            return;
        }

        if (size < get_max_allocatable_size()) {
            size_t cache_line_index = get_cache_line_index(size);

            cache_line<_BaseAllocator>* const cache_line = &m_cache_lines[cache_line_index];

            cache_line->deallocate_chunk(p);
        } else {
            return free(p);
        }
    }

    /// @brief Reallocate memory block.
    ///
    /// @param[in]   p           pointer to the memory block to reallocate.
    /// @param[in]   old_size    size of input memory block.
    /// @param[in]   new_size    size of the new memory block.
    /// @return   Returns a pointer to the memory block of size #new_size.
    inline void* reallocate(void* p, size_t old_size, size_t new_size)
    {
        if (!p) {
            return allocate(new_size);
        }

        // Don't reallocate if we can fit the same cache line.
        if ((old_size < get_max_allocatable_size()) && (new_size < get_max_allocatable_size())) {
            size_t old_cache_line_index = get_cache_line_index(old_size);
            size_t new_cache_line_index = get_cache_line_index(new_size);

            if (old_cache_line_index == new_cache_line_index) {
                return p;
            }
        }

        void* new_pointer = allocate(new_size);

        if (!new_pointer) {
            return nullptr;
        }

        memcpy(new_pointer, p, std::min<size_t>(old_size, new_size));

        deallocate(p, old_size);

        return new_pointer;
    }

    void empty_cache()
    {
        size_t cache_line_count = get_cache_line_count();
        for (size_t i = 0; i < cache_line_count; i++) {
            m_cache_lines[i].empty_cache();
        }
    }

private:
    cache_line<_BaseAllocator>* m_cache_lines; ///< Array of cache lines.
    _BaseAllocator* const m_base_allocator;    ///< Pointer to the base allocator.
    const pthread_t m_my_thread_id;            ///< My thread identifer.
    thread_cache_allocator<_BaseAllocator>* m_next_allocator;

    /// @brief #cache_line must be power of two for efficient array access.
    static_assert((sizeof(cache_line<_BaseAllocator>) & (sizeof(cache_line<_BaseAllocator>) - 1)) == 0,
                  "cache_line must be power of two for efficient array access");

    /// @brief Returns cache_line object granularity. E.g. if granularity
    ///        is 16, cache_line[0] will have size 16, cache_line[1] will
    ///        have size 32 etc.
    ///
    /// @return Cache line object granularity.
    static constexpr size_t get_cache_line_object_granularity()
    {
        return 1U << allocator_traits::CACHE_LINE_LOG_OBJECT_GRANULARITY;
    }

    /// @brief Returns number of cache lines.
    ///
    /// @returns Returns cache line count.
    static constexpr size_t get_cache_line_count()
    {
        return allocator_traits::CACHE_LINE_MAX_OBJECT_SIZE / get_cache_line_object_granularity();
    }

    /// @brief Returns maximum chunk size for which cache line allocation is used.
    ///
    /// @return  Returns maximum chunk size for which cache line allocation is used.
    static constexpr size_t get_max_allocatable_size()
    {
        return allocator_traits::CACHE_LINE_MAX_OBJECT_SIZE;
    }

    /// @brief Returns cache line index for the given chunk size.
    ///
    /// @param[in]    size    Size of the memory chunk.
    /// @return  Returns the cache line index for the given #size.
    size_t get_cache_line_index(const size_t size) const
    {
        dassert_crit(size > 0);
        return (size - 1) >> allocator_traits::CACHE_LINE_LOG_OBJECT_GRANULARITY;
    }

    /// @brief Returns size of memory chunk for the cache line with given index.
    ///
    /// @param[in]    index   cache line index.
    /// @return   Returns cache line size for the given #index.
    size_t get_cache_line_size(const size_t index) const
    {
        return (index + 1) << allocator_traits::CACHE_LINE_LOG_OBJECT_GRANULARITY;
    }

    friend class thread_allocator_manager;
};

namespace
{

void*
allocate_leaba(const size_t size)
{
    return silicon_one::thread_allocator_manager::get_allocator()->allocate(size);
}

void
deallocate_leaba(void* p, const size_t size)
{
    silicon_one::thread_allocator_manager::get_allocator()->deallocate(p, size);
}

void*
reallocate_leaba(void* p, const size_t old_size, const size_t new_size)
{
    return silicon_one::thread_allocator_manager::get_allocator()->reallocate(p, old_size, new_size);
}

void*
allocate_system(const size_t size)
{
    return malloc(size);
}

void
deallocate_system(void* p, const size_t size)
{
    free(p);
}

void*
reallocate_system(void* p, const size_t old_size, const size_t new_size)
{
    return realloc(p, new_size);
}
}

template <typename T>
class thread_local_destructor
{
public:
    thread_local_destructor() : m_destr_func(nullptr), m_destr_data(nullptr)
    {
    }

    ~thread_local_destructor()
    {
        if (m_destr_func) {
            m_destr_func(m_destr_data);
        }
    }
    void set_destructor_data(void (*destr_func)(T*), T* destr_data)
    {
        m_destr_data = destr_data;
        m_destr_func = destr_func;
    }

private:
    void (*m_destr_func)(T*);
    T* m_destr_data;
};

thread_allocator_manager* thread_allocator_manager::m_thread_allocator_manager = nullptr;
std::once_flag thread_allocator_manager::m_initialize_thread_allocator_once;

void* (*thread_allocator_manager::allocate_fn)(const size_t size) = use_leaba_allocator() ? allocate_leaba : allocate_system;
void (*thread_allocator_manager::deallocate_fn)(void* p, const size_t size)
    = use_leaba_allocator() ? deallocate_leaba : deallocate_system;
void* (*thread_allocator_manager::reallocate_fn)(void* p, const size_t old_size, const size_t new_size)
    = use_leaba_allocator() ? reallocate_leaba : reallocate_system;

inline thread_allocator_manager::thread_allocator*
thread_allocator_manager::get_allocator()
{
    static __thread thread_allocator* m_allocator = nullptr;
    static __thread bool m_is_initialized = false;
    static thread_local thread_local_destructor<thread_allocator> thr_destructor;

    if (LA_LIKELY(m_allocator)) {
        return m_allocator;
    } else {
        if (!m_is_initialized) {
            m_allocator = initialize_thread_allocator();
            m_is_initialized = true;
            thr_destructor.set_destructor_data(destroy_thread_allocator, m_allocator);
            return m_allocator;
        } else {
            dassert_crit(false && "Unreachable: the system cannot allocate new memory once thread allocator has been destroyed");
            return nullptr;
        }
    }
}

thread_allocator_manager::thread_allocator_manager()
{
    posix_memalign((void**)&m_pool, 128, sizeof(allocator_traits::central_allocator));
    ::new (m_pool) allocator_traits::central_allocator();
}

thread_allocator_manager::~thread_allocator_manager()
{
    destroy_unused_thread_allocators();
    free(m_pool);
    m_pool = nullptr;
}

void
thread_allocator_manager::destroy_unused_thread_allocators()
{
    std::lock_guard<std::mutex> lock(m_my_mutex);
    thread_allocator* p;
    while (!m_allocators_to_destroy.empty()) {
        p = m_allocators_to_destroy.front();
        p->~thread_cache_allocator();
        free(p);
        m_allocators_to_destroy.pop_front();
    }
}

thread_allocator_manager::thread_allocator*
thread_allocator_manager::initialize_thread_allocator()
{
    std::call_once(m_initialize_thread_allocator_once, []() { initialize_thread_allocator_manager(); });

    thread_allocator* p;
    posix_memalign((void**)&p, 128, sizeof(thread_allocator));
    ::new (p) thread_allocator(m_thread_allocator_manager->m_pool);

    m_thread_allocator_manager->destroy_unused_thread_allocators();

    return p;
}

void
thread_allocator_manager::destroy_thread_allocator_manager()
{
    m_thread_allocator_manager->~thread_allocator_manager();
    free(m_thread_allocator_manager);
    m_thread_allocator_manager = nullptr;
}

void
thread_allocator_manager::initialize_thread_allocator_manager()
{
    if (m_thread_allocator_manager == nullptr) {
        posix_memalign((void**)&m_thread_allocator_manager, 128, sizeof(thread_allocator_manager));
        ::new (m_thread_allocator_manager) thread_allocator_manager();

        // We don't set up destruction of thread_allocator_manager because
        // memory allocator is needed during the whole time the program is alive.
        // We rely on the operating system to return the mapped memory back when the
        // program is unloaded from memory
    }
}

void
thread_allocator_manager::destroy_thread_allocator(thread_allocator* p)
{
    p->empty_cache();
    {
        std::lock_guard<std::mutex> lock(m_thread_allocator_manager->m_my_mutex);
        m_thread_allocator_manager->m_allocators_to_destroy.push_front(p);
    }
}

} // namespace silicon_one
