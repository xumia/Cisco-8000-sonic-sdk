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

#ifndef __LEABA_DEVICE_TREE_H__
#define __LEABA_DEVICE_TREE_H__

#include "lld/gibraltar_tree.h"
#include "lld/pacific_tree.h"

#define IS_SIM_BLOCK_ID(block_id)                                                                                                  \
    ((block_id == silicon_one::pacific_tree::lld_block_id_e::LLD_BLOCK_ID_SIM_ACCESS)                                              \
     || (block_id == silicon_one::gibraltar_tree::lld_block_id_e::LLD_BLOCK_ID_SIM_ACCESS))

#endif // __LEABA_DEVICE_TREE_H__
