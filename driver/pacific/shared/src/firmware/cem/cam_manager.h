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

#include "common.h"
#include "em_commands.h"

// HW issue: When trying to get entry in some bank for key that is already at CAM - the returned entry is the current entry of this
// key on CAM.
// WA: Save the described entry before inserting to CAM.

// This file saves all entries on CAM, for entry that relevant for evacuation it's saves 11 bits entry using exactly 11 bits.
// This 11 bits entry is the entry index on evacuation-bank the CAM-saved entry can potentially be stored at.
// This allowed the user to evacuate entry to evacuation-bank using the saved entry in the future.
// Notice: Get of entry that was saved on CAM without using this file will return undefined value.

/// @brief Save new entry on CAM.
///
/// @param[in]  rec   entry to store on cam.
/// @retval if entry succesfully inserted.
///
bool insert_cam_entry(em_entry_data* rec);

/// @brief Get entry on evacuation-bank for entry that currently on CAM.
///
/// @param[in]  rec                     non-empty entry on CAM that can be evacuated (entry < ENTRIES_IN_CAM_EVACUATION).
/// @param[out]  out_collided_location   counter on evacuation-bank, point to the entry rec can potentially be stored.
///
void get_cam_entry_collided_location(em_entry_data* rec, periodic_counter* out_collided_location);
