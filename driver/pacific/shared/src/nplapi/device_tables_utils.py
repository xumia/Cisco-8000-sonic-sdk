#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

#######################################################
# CLASS: files_specifications
# @brief Utilities for device tables generator script
#######################################################


class files_specifications:

    source_prefix = '''
                  #define NPLAPI_NUM_SLICES %(num_slices)
                  #include "nplapi/device_tables.h"
                  #include "device_tables_helper.h"
                  #include "common/defines.h"
                  #include "common/gen_utils.h"
                  #include "common/logger.h"

                  namespace silicon_one
                  {

                  la_device_id_t
                  get_device_id(const device_tables* tables)
                  {
                      return tables->get_device_id();
                  }

                  la_status
                  device_tables::initialize_tables(translator_creator& creator)
                  {
                      la_status retval;

                      // Table pre-initialization
                      retval = creator.pre_table_init();
                      return_on_error(retval);
                  '''

    source_suffix = '''
                 retval = creator.post_table_init();
                 return_on_error(retval);

                 return LA_STATUS_SUCCESS;
                 }

                 } // namespace silicon_one
                '''

    header_prefix = '''
                 #include <memory>
                 #include "common/la_status.h"
                 #include "nplapi/nplapi_tables.h"
                 #include "nplapi/translator_creator.h"
                 #include "common/cereal_utils.h"

                 namespace silicon_one
                 {

                 /// @brief Collection of all supported NPL tables.
                 class device_tables
                 {

                     CEREAL_SUPPORT_PRIVATE_MEMBERS

                 public:
                     explicit device_tables(la_device_id_t id) : m_device_id(id) {}
                     device_tables() = default; // Needed by cereal

                     la_status initialize_tables(translator_creator& creator);

                     la_device_id_t get_device_id() const
                     {
                         return m_device_id;
                     }
                 public:
                '''

    header_suffix = '''
                private:
                    la_device_id_t m_device_id;
                };

                } // namespace silicon_one'''

    @classmethod
    def get_source_prefix(cls):
        return cls.source_prefix

    @classmethod
    def get_source_suffix(cls):
        return cls.source_suffix

    @classmethod
    def get_header_prefix(cls):
        return cls.header_prefix

    @classmethod
    def get_header_suffix(cls):
        return cls.header_suffix
