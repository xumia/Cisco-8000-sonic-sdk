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

#ifndef __LEABA_NIC_H__
#define __LEABA_NIC_H__

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/stringify.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <uapi/linux/if.h>

#include "leaba_module.h"

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

#ifndef BYTES_IN_DQWORD
#define BYTES_IN_DQWORD 16
#endif

/* Networking specs */
#define MAX_ETH_FRAME_SIZE 1522

/* device constants */
#define NUM_INTERFACES_PER_DEVICE 6
#define NUM_INTERFACES_PER_DEVICE_ASIC5 16
#define NUM_INTERFACES_PER_DEVICE_ASIC3 8

#define NUM_CONTEXT_PER_IFG 1
#define NUM_CONTEXT_PER_IFG_PL_GR 4
#define NUM_IFGS_PER_SLICE 2
#define NUM_IFGS_PER_SLICE_ASIC5 1

#define INJ_HEADER_SIZE 30
#define MIN_PACKET_SIZE 64

#define BUFFER_PTR_ALIGNMENT 8
#define MAX_DESC_BUFFER_SIZE_BYTES (1 << 16)
#define MAX_DATA_BUFFER_SIZE_BYTES (1 << 31)
#define DESC_BUFFER_WRAP_BIT (1 << 16)
#define DATA_BUFFER_WRAP_BIT (1 << 31)
#define PD_EOP_BIT_INSIDE_SIZE_WORD (1 << 15)

#define MAX_INTERFACE_NAME_LEN 31

/* hold description of packets transfered between the host and device - 16 bytes */
#define PD_SIZE_FIELD_BITS_NR 14
#define PD_ERR_FIELD_BITS_NR 1
#define PD_SOP_FIELD_BITS_NR 1
#define PD_EOP_FIELD_BITS_NR 1
struct leaba_nic_pacific_packet_descriptor_t {
    uint64_t phys_addr;
    union {
        struct {
            uint64_t size : PD_SIZE_FIELD_BITS_NR;
            uint64_t err : PD_ERR_FIELD_BITS_NR;
            uint64_t eop : PD_EOP_FIELD_BITS_NR;
        };
        uint64_t size_err;
    };
} __attribute__((packed));

struct leaba_nic_gibraltar_inject_packet_descriptor_t {
    uint64_t phys_addr;
    union {
        struct {
            uint64_t size : PD_SIZE_FIELD_BITS_NR;
            uint64_t padding0 : sizeof(uint16_t) * CHAR_BIT - PD_SIZE_FIELD_BITS_NR;
            uint64_t sop : PD_SOP_FIELD_BITS_NR;
            uint64_t eop : PD_EOP_FIELD_BITS_NR;
            uint64_t err : PD_ERR_FIELD_BITS_NR;
        };
        uint64_t size_err;
    };
} __attribute__((packed));

struct leaba_nic_gibraltar_ext_packet_descriptor_t {
    uint64_t phys_addr;
    union {
        struct {
            uint64_t size : PD_SIZE_FIELD_BITS_NR;
            uint64_t err : PD_ERR_FIELD_BITS_NR;
        };
        uint64_t size_err;
    };
} __attribute__((packed));

union leaba_nic_packet_descriptor_t {
    struct leaba_nic_pacific_packet_descriptor_t pacific;
    struct leaba_nic_gibraltar_inject_packet_descriptor_t gibraltar_inject;
    struct leaba_nic_gibraltar_ext_packet_descriptor_t gibraltar_ext;
};

#define DESC_BUFFER_ELEMENT_SIZE_BYTES sizeof(union leaba_nic_packet_descriptor_t)
#define DESC_BUFFER_SIZE_BYTES m_desc_buffer_size_bytes
#define NUM_OF_ELEMENTS_IN_DESC_BUFFER                                                                                             \
    (DESC_BUFFER_SIZE_BYTES / DESC_BUFFER_ELEMENT_SIZE_BYTES) /* TODO must be a multiplication of 4 */
                                                              /* hw doesn't maintain read/write pointers for the inject data buffer.
                                                               * use fixed size elements for data to facilitate the buffer management */
#define INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES (10 * 1024)
/* same number of elements in inject desc and data buffers. code takes it as an assumption */
#define DATA_BUFFER_SIZE_BYTES PAGE_ALIGN(NUM_OF_ELEMENTS_IN_DESC_BUFFER* INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES)

/* type of buffers */
enum buffer_type {
    BUFFER_TYPE_DESC,
    BUFFER_TYPE_DATA,
};
/* size of the allocated buffer */
#define REAL_BUFFER_SIZE_BYTES(_t) (((_t) == BUFFER_TYPE_DESC) ? DESC_BUFFER_SIZE_BYTES : DATA_BUFFER_SIZE_BYTES)
/* if write-back is enabled then the 8 bytes right above buffer end hold the read/write pointers.
 * reserve full size of descriptor to facilitate pointer management */
#define WRITEBACK_MEM_SIZE DESC_BUFFER_ELEMENT_SIZE_BYTES
#define BUFFER_SIZE_BYTES(_t) (m_use_write_back ? REAL_BUFFER_SIZE_BYTES(_t) - WRITEBACK_MEM_SIZE : REAL_BUFFER_SIZE_BYTES(_t))

/* asic spcific operations and values */
struct leaba_nic_t;
struct asic_specific {
    int (*interface_init)(struct leaba_nic_t* nic);
    void (*activate_interface)(struct leaba_nic_t* nic);
    void (*deactivate_interface)(struct leaba_nic_t* nic);
    ssize_t (*show_if)(struct leaba_nic_t* nic, struct device_attribute* attr, char* buf, unsigned n);
    struct sk_buff* (*get_ext_skb)(struct leaba_nic_t* nic, union leaba_nic_packet_descriptor_t* desc);
    void (*check_ext_pointers)(struct leaba_nic_t* nic);
    void (*check_inj_pointer)(struct leaba_nic_t* nic);
    int (*nic_tx)(struct sk_buff* skb, struct net_device* ndev);

    uint32_t ext_cfg_0;
    uint32_t inj_cfg_0;
    uint32_t ext_wr_pd_ptr_0;
    uint32_t inj_rd_pd_ptr_0;
    uint32_t inj_wr_pd_ptr_0;

    uint32_t sbif_ext_dma_pd_base_lsb_reg_0;
    uint32_t sbif_ext_dma_pd_base_msb_reg_0;
    uint32_t sbif_ext_dma_pd_length_reg_0;
    uint32_t sbif_ext_dma_allocated_pd_ptr_reg_0;
    uint32_t sbif_inj_dma_pd_base_lsb_reg_0;
    uint32_t sbif_inj_dma_pd_base_msb_reg_0;
    uint32_t sbif_inj_dma_pd_length_reg_0;

    uint32_t ext_field_mask_go;
    uint32_t ext_field_mask_flow_ctrl;
    uint32_t ext_field_flow_ctrl_pd_thr_shift;
    uint32_t ext_field_flow_ctrl_pd_thr_bits_nr;
    uint32_t ext_field_mask_remote;
    uint32_t ext_field_mask_wb;

    uint32_t inject_field_mask_go;
    uint32_t inject_field_mask_remote;
    uint32_t inject_field_mask_wb;
};

/* descriptor for inject buffers - use jump buffer in cases where the skb received from the kernal cannot be used */
struct punt_inject_buffer_desc {
    union {
        struct sk_buff* skb;
        void* data;
    };

    int is_skb;
};

/* per-interface data. kernel allocates this struct using kzalloc, so all fields are initialized with 0 */
struct leaba_nic_t {
    /* asic specific info */
    struct asic_specific asic;
    /* the network device */
    struct net_device* ndev;
    /* the pci device - same for all interfaces but here for convenience */
    struct pci_dev* pdev;
    /* networking statistics */
    struct rtnl_link_stats64 stats;
    /* timer used in polling mode */
    struct hrtimer polling_timer;
    /* mac addresses of the interface
     * the address should match the one of the punt_inject port */
    uint64_t mac_addr;
    /* deferred work */
    struct work_struct deferred_work;
    /* sync interface teardown and deferred work */
    atomic_t is_teardown;
    /* virtual addresses of desc buffers */
    uint8_t* buffer_virt_ext_desc;
    uint8_t* buffer_virt_inj_desc;
    /* physical addresses of desc buffers */
    dma_addr_t buffer_phys_ext_desc;
    dma_addr_t buffer_phys_inj_desc;
    /* virtual addresses of the data buffers */
    uint8_t* buffer_virt_ext_data;
    uint8_t* buffer_virt_inj_data;
    /* skb list for injected packets */
    struct punt_inject_buffer_desc* inj_buffer_list;
    /* skb list for punted packets */
    struct punt_inject_buffer_desc* ext_skb_list;

    /* write pointers - offset in bytes from buffer base + wrap bit*/
    uint32_t write_ptr_ext_desc;
    uint32_t write_ptr_inj_desc;
    /* read pointers - offset in bytes from buffer base + wrap bit*/
    uint32_t read_ptr_ext_desc;
    uint32_t read_ptr_inj_desc;

    /* index of the interface in the interfaces array */
    int index;
    /* 1 if the interface was registered with the kernel's networking sub-system, 0 otherwise */
    int netdev_registered;
    /* guard the device stats */
    spinlock_t stats_spinlock;
    /* guard inject buffer pointers, which are accessed by both user and interrupt contexts.
     * no need to guard the punt buffer pointers because they are accessed by interrupt context only */
    spinlock_t inject_buffer_pointers_spinlock;
    /* interface name */
    char name[MAX_INTERFACE_NAME_LEN + 1];
    /* active/inactive flag */
    int is_active;

    /* asic specific fields */
    union {
        struct { /* pacific only */
            /* physical addresses of the data buffers */
            dma_addr_t buffer_phys_ext_data;
            dma_addr_t buffer_phys_inj_data;
            /* pointers to data buffers */
            uint32_t read_ptr_ext_data;
            uint32_t read_ptr_inj_data;
            uint32_t write_ptr_ext_data;
            uint32_t write_ptr_inj_data;
        };

        struct { /* gibraltar only */
            /* pointer past the last allocated punt descriptor */
            uint32_t alloc_ptr_ext_desc;
        };
    };
};

/* size of descriptors buffer in bytes */
extern uint m_desc_buffer_size_bytes;

/* use polling (as opposed to interrupts) for checking punted packets */
extern int m_use_polling;

/* read write pointers from memory (as opposed to device registers) */
extern int m_use_write_back;

/* enable flow control - limit the IFG when PIER buffers pass threshold */
extern int m_flow_control;

/* flow control threshold - number of free descriptors in the ext buffer at which flow-control is triggered */
extern int m_flow_control_threshold;

/* use system memory(remote) instead of on-chip memory */
extern int m_remote;

/* polling interval */
extern uint m_polling_interval_usec;

/* Add wrapper header
 * For test environment - add wrapper header with SP GID */
extern uint m_add_wrapper_header;

/* GB device still use packet-DMA workaround */
extern uint m_gb_packet_dma_workaround;

/* Check if it is asic5 chip */
bool is_asic5(const struct pci_dev* pdev);

/* Check if it is Asic4 chip */
bool is_asic4(const struct pci_dev* pdev);

/* Check if it is Asic3 chip */
bool is_asic3(const struct pci_dev* pdev);

/* print the given buffer in kernel log */
void print_buffer(const char* func,
                  const char* title,
                  const struct leaba_nic_t* nic,
                  const uint8_t* buf,
                  uint32_t bytes_nr,
                  int is_err);

/* identify and protect against pci errors */
int check_and_handle_pci_errors(struct leaba_nic_t* nic, uint32_t regval);

/* allocate a single DMA buffer for the given interface */
int single_interface_buffer_alloc(struct pci_dev* pdev,
                                  struct leaba_nic_t* nic,
                                  enum buffer_type buf_type,
                                  uint8_t** out_virt,
                                  dma_addr_t* out_phys);

/* Free the data field of the descriptor, allocated as an skb or with kmalloc */
void free_punt_inject_descriptor(struct leaba_nic_t* nic, struct punt_inject_buffer_desc* desc);

/* free the DMA buffers of the given interface */
void interface_buffers_free(struct pci_dev* pdev, struct leaba_nic_t* nic);

/* leaba specific teardown work */
void interface_teardown(struct pci_dev* pdev, struct leaba_nic_t* nic);

/* increment the given buffer pointer by the given amount of bytes (locally, not at the device) */
void do_buffer_ptr_inc(struct leaba_nic_t* nic, uint32_t* ptr, enum buffer_type buf_type, uint32_t increment, int contig_wrap);

/* get the punt write pointer */
uint32_t get_ext_desc_write_pointer(const struct leaba_nic_t* nic);

/* get the inject read pointer */
uint32_t get_inject_desc_read_pointer(const struct leaba_nic_t* nic);

/* return the available space between the pointers */
uint32_t get_desc_buffer_available_space(uint32_t raw_write_ptr, uint32_t raw_read_ptr, uint32_t element_size);

/* print the given descriptor */
void print_descriptor(struct leaba_nic_t* nic, const char* func, const union leaba_nic_packet_descriptor_t* desc);

/* pass the packet to the kernel for processing */
void leaba_nic_rx(struct leaba_nic_t* nic, union leaba_nic_packet_descriptor_t* desc, uint64_t desc_size);

/* check the device pointers */
void leaba_check_device_pointers(struct leaba_nic_t* nic);

/* deferred-work function - calls leaba_check_device_pointers() function
 * instead of doing the work inside the function. needed for userland validation */
void do_check_device_pointers(struct work_struct* work);

/* Number of Interface per Device */
static inline int
get_num_intf_per_dev(const struct pci_dev* pdev)
{
    if (is_asic5(pdev)) {
        return NUM_INTERFACES_PER_DEVICE_ASIC5;
    }

    if (is_asic3(pdev)) {
        return NUM_INTERFACES_PER_DEVICE_ASIC3;
    }

    return NUM_INTERFACES_PER_DEVICE;
}

/* Number of IFGs per Slice */
static inline int
get_num_ifgs_per_slice(const struct pci_dev* pdev)
{
    return (is_asic5(pdev) ? NUM_IFGS_PER_SLICE_ASIC5 : NUM_IFGS_PER_SLICE);
}

/* Number of context per IFG */
static inline int
get_num_context_per_ifg(const struct pci_dev* pdev)
{
    return ((is_asic4(pdev) || is_asic3(pdev)) ? NUM_CONTEXT_PER_IFG_PL_GR : NUM_CONTEXT_PER_IFG);
}

/* read the given command register */
static inline uint32_t
read_sbif_dma_register(struct pci_dev* pdev, uint32_t reg, uint32_t index)
{
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    uint32_t ctx = index * get_num_ifgs_per_slice(pdev) * get_num_context_per_ifg(pdev);

    return leaba_read_sbif_register(ldev, reg + ctx * sizeof(uint32_t));
}

/* write the given command register */
static inline void
write_sbif_dma_register(struct pci_dev* pdev, uint32_t reg, uint32_t index, uint32_t val)
{
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    uint32_t ctx = index * get_num_ifgs_per_slice(pdev) * get_num_context_per_ifg(pdev);

    leaba_write_sbif_register(ldev, reg + ctx * sizeof(uint32_t), val);
}

/* mark the given descriptor (in dma memory) as invalid */
static inline void
invalidate_descriptor(union leaba_nic_packet_descriptor_t* desc)
{
    /* there's an assumption in the code that a descriptor is made invalid by zero'ing
     * its 'size' field. specifically - the descriptor buffers are allocated with GFP_ZERO
     * so that there's no need to invalidate the newly allocated descriptors one by one */
    memset(desc, 0, sizeof(*desc));
}

#endif // __LEABA_NIC_H__
