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

#include <inttypes.h>
#include <string.h>

#include "arc_interrupts.h"
#include "common.h"

int
main()
{
    int val = 0xabc12def;

    identity_reg_data id_reg;
    id_reg.data = _lr(REG_ADDR_IDENTITY);
    uint32_t offset = id_reg.bits.arc_num * 4;

    _vdmemcpy((uncached_ptr_t)(0x8000_0c00 + offset), &val, MEM_ALIGN);
    _vdmemcpy((uncached_ptr_t)(0x0000_0c00 + offset), &val, MEM_ALIGN);

    _brk();

    while (1) {
        // do nothing
    }

    return 0;
}
