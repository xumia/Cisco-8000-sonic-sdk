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

/*
 * Cisco Systems, Inc.
 */

#ifndef __LEABA_MODULE_H__
#define __LEABA_MODULE_H__

#ifdef STANDALONE_TESTING             // REMOVE FOR RELEASE
#include "kernel_mock_data_structs.h" // REMOVE FOR RELEASE
#else                                 // REMOVE FOR RELEASE
#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/uio_driver.h>
#endif // REMOVE FOR RELEASE

#include "leaba_kernel_types.h"

struct net_device;

/* dynamically configurable debug level */
extern uint g_leaba_module_debug_level;

/* per-device driver data. allocated with kzalloc so all fields are initialized to 0 */
struct leaba_device_t {
    char name[64];

    struct pci_dev* pdev;
    const struct pci_device_id* id;

    struct uio_info uinfo;
    unsigned long open_count;
    unsigned long max_open_fd;
    int devno;
    atomic64_t interrupt_count;

    /* PCI mmio virtual address */
    uint8_t __iomem* bar_va;

    /* DMA coherent buffer */
    void* dma_va;      /* Kernel virtual address */
    dma_addr_t dma_pa; /* PCI domain address */

    /* hotplug and AER */
    leaba_pci_event_t pci_event_value;

    /*** per-device NIC data ***/

    /* network interfaces */
    struct net_device** interfaces;
};

struct leaba_nic_t;
ssize_t leaba_nic_store_if(struct device* dev, struct device_attribute* attr, const char* buf, size_t count, unsigned n);
void leaba_check_device_pointers(struct leaba_nic_t* nic);
int leaba_nic_initialize(struct pci_dev* pdev);
void leaba_nic_teardown(struct pci_dev* pdev);
void leaba_nic_stop(struct pci_dev* pdev);

/* PACKET-DMA-WA: copy a packet from device to host. return the actual size of the packet on success, or -1 on failure */
int copy_packet_d2h(uint8_t* dst, const uint8_t* src, uint32_t len, bool add_test_mode_header);
/* PACKET-DMA-WA: copy a packet from device to host in case of wrap-around. return the actual size of the packet on success, or -1
 * on failure */
int copy_packet_d2h_with_wrap_around(uint8_t* dst,
                                     const uint8_t* src0,
                                     uint32_t len0,
                                     const uint8_t* src1,
                                     uint32_t len1,
                                     bool add_test_mode_header);
/* PACKET-DMA-WA: copy a packet from host to device. return the actual size of the packet on success, or -1 on failure */
int copy_packet_h2d(uint8_t* dst, const uint8_t* src, uint32_t len, uint32_t interface);
/* PACKET-DMA-WA: return 1 if the given packet has inject header and 0 otherwise */
int is_inject_packet(const uint8_t* packet, uint32_t len);
/* PACKET-DMA-WA: return the size of inject headers in bytes */
uint32_t get_inject_headers_len(void);
/* PACKET-DMA-WA: return the max size of packet-dma workaround header in bytes */
uint32_t get_max_packet_dma_wa_header_len(void);
/* PACKET-DMA-WA: copy an inject header to the given buffer */
void get_inject_header(uint8_t* buf, uint32_t interface, int is_gibraltar);
/* HW-UNIT-TESTING: return the length of the dummy header in bytes */
uint32_t get_dummy_vlan_tag_header_len(void);
/* HW-UNIT-TESTING: add dummy header */
uint32_t add_dummy_vlan_tag_header(uint8_t* dst, const uint8_t* src);
void add_dummy_vlan_tag_header_gibraltar(uint8_t* dst, const uint8_t* src);
/* SVL: return 1 if the given packet has SVL header and 0 otherwise */
int is_svl_packet(const uint8_t* packet, uint32_t len);

static inline void
leaba_write_sbif_register(struct leaba_device_t* ldev, uint32_t reg, uint32_t val)
{
    __iomem uint8_t* regaddr = ldev->bar_va + reg;
    iowrite32(val, regaddr);
}

static inline uint32_t
leaba_read_sbif_register(struct leaba_device_t* ldev, uint32_t reg)
{
    __iomem uint8_t* regaddr = ldev->bar_va + reg;

    return ioread32(regaddr);
}

#endif // __LEABA_MODULE_H__
