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

#ifndef __SAI_QUEUE_H__
#define __SAI_QUEUE_H__

#include "saitypes.h"
#include "saiobject.h"

#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{

struct queue_watermark_stats {
    la_system_port::egress_max_congestion_watermark egress_cgm_watermark;
    la_system_port::egress_max_delay_watermark egress_delay_watermark;
};

sai_status_t queue_attr_scheduler_profile_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t queue_attr_scheduler_profile_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* attr,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);
sai_status_t queue_attr_pause_status_get(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg);
sai_status_t queue_attr_enable_pfc_dldr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t queue_attr_enable_pfc_dldr_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);
sai_status_t queue_attr_pfc_dlr_init_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
}
}
#endif
