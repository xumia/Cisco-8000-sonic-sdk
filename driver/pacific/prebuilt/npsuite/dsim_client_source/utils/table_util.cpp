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

#include "table_util.h"
#include <iostream>
#include <iomanip>
#include <algorithm>

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
void
table_dump(const std::string& title,
           const size_t num_columns,
           const size_t num_rows,
           const std::vector<std::vector<uint64_t>>& data,
           const std::vector<std::string>& row_names,
           const std::vector<bool>& row_contains_data,
           const std::vector<std::string>& column_names,
           const std::vector<bool>& column_contains_data,
           const bool show_header,
           const bool show_dividers,
           const bool show_totals)
{
    //
    // Per column max width
    //
    std::vector<size_t> column_max_width = {0};
    column_max_width.resize(num_columns);

    //
    // Per column total
    //
    std::vector<uint64_t> column_totals = {0};
    column_totals.resize(num_columns);

    //
    // Get the width of the first column, the command names
    //
    size_t initial_column_width = title.length();
    for (auto row_name : row_names) {
        initial_column_width = std::max(initial_column_width, row_name.length());
    }

    //
    // Get the maximum column width for each stats as 64 bit numbers get long and fill the screen.
    //
    for (auto row = 0U; row < num_rows; row++) {
        if (row_contains_data[row]) {
            for (auto column = 0U; column < num_columns; column++) {
                //
                // Skip empty columns
                //
                if (!column_contains_data[column]) {
                    continue;
                }

                //
                // Column width minimum is the header length
                //
                if (!column_max_width[column]) {
                    column_max_width[column] = column_names[column].length();
                }

                //
                // Column width grows with that of the stat within it
                //
                size_t stat_length = std::to_string(data[row][column]).length();
                column_max_width[column] = std::max(column_max_width[column], stat_length);
            }
        }
    }

    //
    // Print the table data header
    //
    std::cerr << std::endl;
    if (show_header) {
        auto printed_something_for_this_row = false;
        for (auto column = 0U; column < num_columns; column++) {
            //
            // Skip empty columns
            //
            if (!column_contains_data[column]) {
                continue;
            }
            auto column_width = column_max_width[column];

            //
            // Print the top left column header
            //
            if (column == 0) {
                std::cerr << std::setw(initial_column_width) << title << " ";
            }

            //
            // Print the column header
            //
            std::cerr << std::setw(column_width) << column_names[column] << " ";
            printed_something_for_this_row = true;
        }

        if (printed_something_for_this_row) {
            std::cerr << std::endl;
        }
    }

    //
    // Print a divider
    //
    if (show_dividers) {
        auto printed_something_for_this_row = false;
        for (auto column = 0U; column < num_columns; column++) {
            //
            // Skip empty columns
            //
            if (!column_contains_data[column]) {
                continue;
            }
            auto column_width = column_max_width[column];

            //
            // Print the left divider
            //
            if (column == 0) {
                std::cerr << std::setw(initial_column_width + 1) << std::setfill('=') << " ";
            }

            //
            // Print the row divider
            //
            std::cerr << std::setw(column_width + 1) << std::setfill('=') << " " << std::setfill(' ');
            printed_something_for_this_row = true;
        }

        if (printed_something_for_this_row) {
            std::cerr << std::endl;
        }
    }

    //
    // Now print the table data
    //
    for (auto row = 0U; row < num_rows; row++) {
        auto printed_something_for_this_row = false;
        if (row_contains_data[row]) {
            for (auto column = 0U; column < num_columns; column++) {
                //
                // Skip empty columns
                //
                if (!column_contains_data[column]) {
                    continue;
                }
                auto column_width = column_max_width[column];

                //
                // Print padding for the first row
                //
                if (column == 0) {
                    std::cerr << std::setw(initial_column_width) << row_names[row] << " ";
                }

                //
                // Print the row data
                //
                auto stat = data[row][column];
                std::cerr << std::setw(column_width) << stat << " ";
                printed_something_for_this_row = true;

                column_totals[column] += stat;
            }
        }

        if (printed_something_for_this_row) {
            std::cerr << std::endl;
        }
    }

    //
    // Print totals
    //
    if (show_totals) {
        //
        // Print a divider
        //
        if (show_dividers) {
            auto printed_something_for_this_row = false;
            for (auto column = 0U; column < num_columns; column++) {
                //
                // Skip empty columns
                //
                if (!column_contains_data[column]) {
                    continue;
                }
                auto column_width = column_max_width[column];

                //
                // First row padding
                //
                if (column == 0) {
                    std::cerr << std::setw(initial_column_width + 1) << " ";
                }

                //
                // Print the row divider
                //
                std::cerr << std::setw(column_width + 1) << std::setfill('-') << " " << std::setfill(' ');
                printed_something_for_this_row = true;
            }

            if (printed_something_for_this_row) {
                std::cerr << std::endl;
            }
        }

        auto printed_something_for_this_row = false;
        for (auto column = 0U; column < num_columns; column++) {
            //
            // Skip empty columns
            //
            if (!column_contains_data[column]) {
                continue;
            }
            auto column_width = column_max_width[column];

            //
            // Print first column test
            //
            if (column == 0) {
                std::cerr << std::setw(initial_column_width) << "Total";
            }

            //
            // Print per row total
            //
            std::cerr << std::setw(column_width + 1) << column_totals[column] << std::setfill(' ');
            printed_something_for_this_row = true;
        }

        if (printed_something_for_this_row) {
            std::cerr << std::endl;
        }
    }
}
