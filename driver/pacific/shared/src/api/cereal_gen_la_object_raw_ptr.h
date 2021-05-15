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

#ifndef __CEREAL_GEN_LA_OBJECT_RAW_PTR_H__
#define __CEREAL_GEN_LA_OBJECT_RAW_PTR_H__

#include "api/types/la_object.h"
#include <memory>

// used for creating a dummy shared_ptr for serialization purposes only.
struct cereal_gen_helper_null_deleter {
    void operator()(void const*) const
    {
    }
};

// in case of regular pointer return dummy shared_ptr
template <class T>
static std::shared_ptr<T>
get_dummy_shared_ptr(T* ptr)
{
    return std::shared_ptr<T>(ptr, cereal_gen_helper_null_deleter());
}

// in case of raw pointer to std::enable_shared_from_this, need to get the shared_ptr stored in the class
template <class T>
static std::shared_ptr<T>
get_dummy_shared_ptr(std::enable_shared_from_this<T>* ptr)
{
    if (!ptr) {
        return std::shared_ptr<T>();
    }
    return ptr->shared_from_this();
}

// verify that only allowed classes are serizlized
// throws static_assert if the class is not derived from la_object
template <class T>
static void
verify_class(T* ptr)
{
    static_assert(std::is_base_of<silicon_one::la_object, T>::value, "only la_object should be serialized using this method!");
}

// this macro should be used for any type stored as raw_pointer.
#define CEREAL_LA_OBJECT_RAW_PTR(class_type)                                                                                       \
                                                                                                                                   \
    /* this macro makes cereal choose the save/load pair and not the single serialize */                                           \
    CEREAL_SPECIALIZE_FOR_ALL_ARCHIVES(class_type*, cereal::specialization::non_member_load_save)                                  \
                                                                                                                                   \
    namespace cereal                                                                                                               \
    {                                                                                                                              \
                                                                                                                                   \
    template <class Archive>                                                                                                       \
    void save(Archive& ar, class_type* const& m)                                                                                   \
    {                                                                                                                              \
        verify_class(m); /* generates static assert if type is not derived from la_object */                                       \
        ar(get_dummy_shared_ptr<class_type>(m));                                                                                   \
    }                                                                                                                              \
                                                                                                                                   \
    template <class Archive>                                                                                                       \
    void load(Archive& ar, class_type*& m)                                                                                         \
    {                                                                                                                              \
        std::shared_ptr<class_type> loaded_shared_ptr;                                                                             \
        ar(loaded_shared_ptr);                                                                                                     \
        m = loaded_shared_ptr.get();                                                                                               \
    }                                                                                                                              \
    }

#endif
