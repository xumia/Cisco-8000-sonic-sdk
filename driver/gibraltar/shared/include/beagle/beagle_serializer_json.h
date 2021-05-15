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

#ifndef __LEABA_BEAGLE_SERIALIZER_JSON_H__
#define __LEABA_BEAGLE_SERIALIZER_JSON_H__

#include "beagle_api/beagle_serializer.h"
#include "beagle_api/beagle_status.h"
#include "common/la_status.h"
#include <jansson.h>
#include <map>
#include <stdint.h>

namespace silicon_one
{

class beagle_serializer_json : public beagle::beagle_serializer
{
public:
    beagle_serializer_json() = default;
    ~beagle_serializer_json() = default;

    using obj_id_t = beagle::beagle_serializer::obj_id_t;

    la_status obj_id2json(obj_id_t root, json_t*& out_root);

    beagle::beagle_status_t insert(obj_id_t parent, const char* key, obj_id_t value) override;
    obj_id_t create_integer(int64_t value) override;
    obj_id_t create_string(const char* value) override;
    obj_id_t create_float(double value) override;
    obj_id_t create_array() override;
    beagle::beagle_status_t array_append(obj_id_t array, obj_id_t value) override;
    beagle::beagle_status_t copy_array(int32_t* in_array, uint32_t size, obj_id_t out_array) override;
    obj_id_t start_proccessing(const char* name) override;
    obj_id_t finish_proccessing(obj_id_t obj_id, const char* name) override;

private:
    obj_id_t m_obj_counter = 0;
    std::map<obj_id_t, json_t*> m_json_objects;
};
}

#endif
