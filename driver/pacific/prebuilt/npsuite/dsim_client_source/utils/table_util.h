// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef _TABLE_WRITER_H_
#define _TABLE_WRITER_H_

#include <string>
#include <vector>

//
// Simple utility to dump the contents of an array, formatted as a table e.g.:
//
//       Per socket stats tx-bytes tx-ok tx-bytes-no-flush rx-bytes rx-ok
// ====================== ======== ===== ================= ======== =====
//           WRITE_MEMORY    22942   430                46        0     0
//       DEVICE_INFO_SYNC       21     1                 0     1064     1
//      VERSION_HANDSHAKE       29     1                 0        4     1
//   WRITE_MEMORY_BY_NAME      360     5                60        0     0
//    READ_MEMORY_BY_NAME     1035    15                 0       15    15
// WRITE_REGISTER_BY_NAME      636    10                76        0     0
//  READ_REGISTER_BY_NAME     1878    30                 0       30    30
//            RESET_STATE       84     4                 0       16     4
//          SNAPSHOT_SAVE      140     5                 0       20     5
//          SNAPSHOT_LOAD       56     2                 0        8     2
//        SNAPSHOT_DELETE       84     3                 0       12     3
//          SNAPSHOT_FIND       84     3                 0       12     3
//        SNAPSHOTS_FETCH       21     1                21        0     0
//                  FLUSH     8967   427                 0     1708   427
//                        -------- ----- ----------------- -------- -----
//                  Total    36337   937               203     2889   491
//
void table_dump(const std::string& title,
                const size_t num_columns,
                const size_t num_rows,
                const std::vector<std::vector<uint64_t>>& data,
                const std::vector<std::string>& row_names,
                const std::vector<bool>& row_contains_data,
                const std::vector<std::string>& column_names,
                const std::vector<bool>& column_contains_data,
                const bool show_header = true,
                const bool show_dividers = true,
                const bool show_totals = true);

#endif
