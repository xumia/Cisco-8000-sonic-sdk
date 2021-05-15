// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __PROFILE_ALLOCATOR_H__
#define __PROFILE_ALLOCATOR_H__

#include "common/cereal_utils.h"
#include "common/la_status.h"
#include "common/ranged_index_generator.h"
#include "common/weak_ptr_unsafe.h"
#include <map>
#include <memory>
#include <vector>

/// @file
/// @brief Profile allocator.

namespace silicon_one
{

template <typename T>
class profile_allocator_base;

/// @brief Profile
///
/// Class holding and describing a profile based on an assigned type T.
template <typename T>
class la_profile
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_profile(uint64_t profile_id, const T& value, const weak_ptr_unsafe<profile_allocator_base<T> >& allocator)
        : m_value(value), m_profile_id(profile_id), m_allocator(allocator)
    {
    }

    // Disable copy / move (should usually be held by a shared_ptr).
    la_profile(const la_profile&) = delete;
    la_profile& operator=(const la_profile&) = delete;

    /// @brief   Get the profile's assigned ID
    ///
    /// @return  Profile ID
    uint64_t id() const
    {
        return m_profile_id;
    }

    /// @brief  Get the profile associated with this profile
    ///
    /// @return  Profile's value
    const T& value() const
    {
        return m_value;
    }

    ~la_profile()
    {
        m_allocator->on_delete(m_profile_id, m_value);
    }

    /// @brief  Serialize/deserialize to/from archive
    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_value, m_profile_id, m_allocator);
    }

private:
    la_profile() = default; // For serialization purposes only
    T m_value;
    uint64_t m_profile_id;
    weak_ptr_unsafe<profile_allocator_base<T> > m_allocator;
};

// profile_allocator_base just provides the 'delete' capability that does not require
// knowing the compare function
template <typename T>
class profile_allocator_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class la_profile<T>;

public:
    template <class Archive>
    void serialize(Archive& ar)
    {
    }

protected:
    virtual ~profile_allocator_base() = default;

private:
    virtual void on_delete(uint64_t profile_id, const T& m_value) = 0;
};

/// @brief Profile allocator.
///
/// The profile allocator provides a mechanism to associate some shared value of type T
/// with an ID. Multiple requests to allocate profiles of the same value of T, will return
/// the same profile.
///
/// Profiles are returned via shared_ptr, so just let go of the shared_ptr when you are
/// done and it will decrement the refcount and eventually release the profile.
template <typename T, typename Compare = std::less<T>, typename Generator = ranged_index_generator>
class profile_allocator : public profile_allocator_base<T>,
                          public std::enable_shared_from_this<profile_allocator<T, Compare, Generator> >
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    using profile_ptr = std::shared_ptr<la_profile<T> >;

    profile_allocator(uint64_t lower_bound, uint64_t upper_bound, const Compare& comp = Compare())
        : m_map(comp), m_index_generator(lower_bound, upper_bound)
    {
    }

    // Allow to use passed in generator.
    profile_allocator(Generator generator, const Compare& comp = Compare()) : m_map(comp), m_index_generator(std::move(generator))
    {
    }

    // Disable copy
    profile_allocator(const profile_allocator&) = delete;
    profile_allocator& operator=(const profile_allocator&) = delete;

    /// @brief Allocate a profile.
    ///
    /// If there exists a profile already for the provided value, a shared_ptr to the existing
    /// profile will be returned. If not, a new profile id will be allocated and a pointer to
    /// that profile will be returned.
    ///
    /// If a new profile cannot be found, then nullptr will be returned
    ///
    /// @param[in]  val        Value to find or allocate a profile.
    ///
    /// @return     Shared pointer to allocated profile, or nullptr if no matching or new profile is available.
    profile_ptr allocate(const T& val)
    {
        // 1. Look for existing profile
        auto it = m_map.find(val);
        if (it != m_map.end()) {
            return it->second.lock();
        }

        // 2. If none found, allocate a new one if possible
        uint64_t profile_id = m_index_generator.allocate();
        if (profile_id == ranged_index_generator::INVALID_INDEX) {
            return nullptr;
        }

        try {
            auto sp = std::make_shared<la_profile<T> >(profile_id, val, this->shared_from_this());
            // Converts to weak_ptr
            m_map[val] = sp;
            return sp;
        } catch (...) {
            // To avoid leak, release the allocated profile id before propogating an
            // exception, for instance if T's copy constructor throws.
            m_index_generator.release(profile_id);
            throw;
        }
    }

    /// @brief Allocate a profile, updating an existing profile pointer.
    ///
    /// Attempts to modify the value held by .
    ///
    /// This is more likely to succeed then allocating, since if this the only copy
    /// of the shared_ptr, then it will release the existing profile first, guaranteeing
    /// success, since the profile can be reused.
    ///
    /// On failure the old profile will be retained.
    ///
    /// @param[in,out]  profile               Shared pointer to profile to modify
    /// @param[in]      value                 Newly requested value.
    ///
    /// @retval         LA_STATUS_SUCCESS     Operation succeeded
    /// @retval         LA_STATUS_ERESOURCE   Unable to allocate new profile
    la_status reallocate(profile_ptr& profile, const T& value)
    {
        // If old_profile is the only user, then free it first to guarantee success
        if (profile.use_count() == 1) {
            profile.reset();
        }

        profile_ptr new_profile = allocate(value);
        if (!new_profile) {
            return LA_STATUS_ERESOURCE;
        }

        profile = new_profile;
        return LA_STATUS_SUCCESS;
    }

    /// @brief Retrieve the number of used indices.
    ///
    /// @retval Current number of used indices.
    size_t size()
    {
        return m_index_generator.size();
    }

    /// @brief Maximum number of indices.
    ///
    /// @retval Maximum number of indices.
    size_t max_size()
    {
        return m_index_generator.max_size();
    }

    /// @brief Set resource monitor.
    ///
    /// @param[in]  monitor           Resource monitor to attach.
    void set_resource_monitor(const resource_monitor_sptr& monitor)
    {
        m_index_generator.set_resource_monitor(monitor);
    }

    /// @brief Get attached resource monitor.
    ///
    /// @param[out]  out_monitor      Resource monitor to populate.
    void get_resource_monitor(resource_monitor_sptr& out_monitor)
    {
        m_index_generator.get_resource_monitor(out_monitor);
    }

    // Serialize/deserialize to/from archive
    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_map, m_index_generator);
    }
    profile_allocator() = default; // For serialization purposes only

private:
    // Handle is about to be destroyed, do the cleanup
    void on_delete(uint64_t profile_id, const T& value) override
    {
        m_map.erase(value);
        m_index_generator.release(profile_id);
    }

    // Map to search for matching profile id.
    std::map<T, weak_ptr_unsafe<la_profile<T> >, Compare> m_map;

    // Available index allocator
    Generator m_index_generator;
};

} // namespace silicon_one

#endif
