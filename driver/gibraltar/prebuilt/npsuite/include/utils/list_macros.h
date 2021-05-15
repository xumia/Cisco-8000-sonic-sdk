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

#ifndef _LIST_MACRO_H_
#define _LIST_MACRO_H_

#include <string>

//
// Some useful enum to string macros
//
#define LIST_MACRO_VALUE(enum_name) enum_name
#define LIST_MACRO_STRING(enum_name) #enum_name
#define LIST_MACRO_STD_STRING(enum_name) std::string(LIST_MACRO_STRING(enum_name))

#define LIST_MACRO_FIXED_ENUM_VALUE(enum_name, enum_val) enum_name = enum_val
#define LIST_MACRO_FIXED_ENUM_STRING(enum_name, enum_val) #enum_name
#define LIST_MACRO_FIXED_ENUM_STD_STRING(enum_name, enum_val) std::string(LIST_MACRO_STRING(enum_name))
#define LIST_MACRO_FIXED_ENUM_STD_PAIR(enum_name, enum_val) std::make_pair(std::string(LIST_MACRO_STRING(enum_name)), enum_val)

#define LIST_MACRO_FIRST_VALUE(arg1, arg2) arg1
#define LIST_MACRO_SECOND_VALUE(arg1, arg2) arg2
#define LIST_MACRO_SECOND_VALUE_AS_STRING(arg1, arg2) std::string(arg2)

//
// e.g.
//
// #define MY_ENUMS(list_macro) list_macro(RED), list_macro(GREEN), list_macro(BLUE),
//
// std::initializer_list< std::string > refs = {
//     MY_ENUMS(LIST_MACRO_STRING) // becomes "RED", "GREEN", "BLUE",
// };
//
// typedef enum {
//     MY_ENUMS(LIST_MACRO_VALUE) // becomes RED, GREEN, BLUE,
// } my_enum_t;

#endif
