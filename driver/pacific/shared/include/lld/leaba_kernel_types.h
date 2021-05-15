// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_KERNEL_TYPES_H__
#define __LEABA_KERNEL_TYPES_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define VENDOR_ID_CISCO 0x1137
#define LEABA_PACIFIC_DEVICE_ID 0xabcd
#define LEABA_GIBRALTAR_DEVICE_ID 0xa001
#define LEABA_ASIC3_DEVICE_ID 0xa003
#define LEABA_ASIC4_DEVICE_ID 0xa004
#define LEABA_ASIC5_DEVICE_ID 0xa005
#define LEABA_ASIC6_DEVICE_ID 0xa006

enum leaba_pci_event_e {
    LEABA_PCI_EVENT_HOTPLUG_REMOVE = 1,
    LEABA_PCI_EVENT_AER_NON_RECOVERABLE = 2,
    LEABA_PCI_EVENT_AER_RECOVERABLE = 3,
    LEABA_PCI_EVENT_AER_RECOVERED = 4,
    LEABA_PCI_EVENT_LAST = LEABA_PCI_EVENT_AER_RECOVERED,
};

typedef uint64_t leaba_pci_event_t;

enum leaba_dma_buffer {
    LEABA_DMA_COH_SZ = 0x10000, // 64K, Size of DMA coherent buffer
};

#endif // __LEABA_KERNEL_TYPES_H__
