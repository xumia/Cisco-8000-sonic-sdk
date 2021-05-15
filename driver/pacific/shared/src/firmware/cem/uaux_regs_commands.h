// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

/// @file
/// @brief UAUX registers definitions for Exact Match Management
///
/// @details Central Exact Match Management (CEM) software is
/// running on a dedicated ARC processor. It interacts with CEM
/// hardware via set of UAUX registers. The register command
/// encodings are defined in this file.
///

#ifndef __CEM_UAUX_REGS_COMMANDS_H__
#define __CEM_UAUX_REGS_COMMANDS_H__

//
// clang-format off
/// @brief Encoding for EM_REQUEST commands.
/// This is the way to communicate with CEM HW
/// source: EM spec.docx
///
enum em_command_e {
    EM_COMMAND_LOOKUP            = 0,      ///< Lookup key. Return entry and location.
    EM_COMMAND_WRITE             = 1,      ///< Writes entry to location. Overrides existing entry if needed.
    EM_COMMAND_FFE               = 2,      ///< Find Free Entry for key
    EM_COMMAND_READ              = 3,      ///< Reads entry for provided location
    EM_COMMAND_POP               = 4,      ///< Obsolete operation
    EM_COMMAND_DELETE            = 5,      ///< Delete entry
    EM_COMMAND_AGE_WRITE         = 6,      ///< Write age for the entry
    EM_COMMAND_AGE_READ          = 7,      ///< Read age for the entry (same as EM_COMMAND_READ)
    EM_COMMAND_QUICK_INSERT      = 8       ///< Inserts entry if can find a location
};

/// @brief Encoding for LEARN commands to be executed by CEM management routines
/// source: EM spec.docx
///
enum learn_command_e {
    LEARN_COMMAND_NEW_WRITE      = 0,      ///< Adding new entry including conflict resolution
    LEARN_COMMAND_UPDATE         = 1,      ///< Update payload of the existing entry
    LEARN_COMMAND_REFRESH        = 2       ///< Age refresh for of existing entry
};

///
/// @brief Bulk Update command encoding
/// The commands are received in rule_hit field in em_response and represent directives from
/// Bulk Update sweep done by HW crawler
enum bulk_command_e {
    BULK_COMMAND_NONE            = 0,     ///< No rule was hit for this entry
    BULK_COMMAND_UPDATE          = 1,     ///< Entry required to update payload. The new payload resides in em_response
    BULK_COMMAND_DELETE          = 2,     ///< Entry should be deleted
    BULK_COMMAND_SEND_TO_CPU     = 3      ///< Entry should be sent to CPU
};
// clang-format on

#endif // __CEM_UAUX_REGS_COMMANDS_H__
