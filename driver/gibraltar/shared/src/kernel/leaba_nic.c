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
 *
 */

#include "leaba_nic.h"
#include "leaba_registers.h"

/* It can be up to 8096 in Asic5 */
uint m_desc_buffer_size_bytes = (4096);
module_param(m_desc_buffer_size_bytes, uint, 0444);
MODULE_PARM_DESC(m_desc_buffer_size_bytes, "Size of descriptors buffer in bytes");

int m_use_polling = 1;
module_param(m_use_polling, int, 0444);
MODULE_PARM_DESC(m_use_polling, "Use polling for checking punted packets");

int m_use_write_back = 0;
module_param(m_use_write_back, int, 0444);
MODULE_PARM_DESC(m_use_write_back, "Read write pointers from memory");

int m_flow_control = 1;
module_param(m_flow_control, int, 0444);
MODULE_PARM_DESC(m_flow_control, "Enable flow control");

int m_flow_control_threshold = 48;
module_param(m_flow_control_threshold, int, 0444);
MODULE_PARM_DESC(m_flow_control_threshold, "Flow control threshold");

int m_remote = 1;
module_param(m_remote, int, 0444);
MODULE_PARM_DESC(m_remote, "Use system memory");

/* interface base name. the full name of the interface will
 * be "%s%d_%d" % (m_interface_base_name, uio device minor, interface#).
 * the size of the full name is limited to IFNAMSIZ (16). it is truncated
 * if needed (that is - if the base name is too long). no checks are done! */
static char* m_interface_base_name = "leaba";
module_param(m_interface_base_name, charp, 0444);
MODULE_PARM_DESC(m_interface_base_name, "Interface base name");

uint m_polling_interval_usec = 1000;
module_param(m_polling_interval_usec, uint, 0644);
MODULE_PARM_DESC(m_polling_interval_usec, "Polling interval in micro-seconds");

uint m_add_wrapper_header = 0;
module_param(m_add_wrapper_header, uint, 0444);
MODULE_PARM_DESC(m_add_wrapper_header, "Wrap packets with an extra header identifying DSP (test mode feature)");

uint m_gb_packet_dma_workaround = 1;
module_param(m_gb_packet_dma_workaround, uint, 0444);
MODULE_PARM_DESC(m_gb_packet_dma_workaround, "GB device still use packet-DMA workaround");

uint g_leaba_module_debug_level = 0;
module_param(g_leaba_module_debug_level, uint, 0644);
MODULE_PARM_DESC(g_leaba_module_debug_level, "Debug level. 0: no debug prints; 1: basic debug prints; 7: full debug prints.");

bool
is_asic5(const struct pci_dev* pdev)
{
    return (pdev->device == LEABA_ASIC5_DEVICE_ID);
}

bool
is_asic3(const struct pci_dev* pdev)
{
    return (pdev->device == LEABA_ASIC3_DEVICE_ID);
}

bool
is_asic4(const struct pci_dev* pdev)
{
    return (pdev->device == LEABA_ASIC4_DEVICE_ID);
}

void
print_buffer(const char* func, const char* title, const struct leaba_nic_t* nic, const uint8_t* buf, uint32_t bytes_nr, int is_err)
{
    char dbg_buff[512];
    char* p = dbg_buff;
    int remaining = sizeof(dbg_buff);
    size_t curlen;
    uint32_t jj;

#define LEABA_PRINT_BUFFER(_FMT, _ARG)                                                                                             \
    do {                                                                                                                           \
        snprintf(p, remaining, _FMT, (_ARG));                                                                                      \
        curlen = strlen(p);                                                                                                        \
        remaining -= curlen;                                                                                                       \
        if (remaining <= 0) {                                                                                                      \
            break;                                                                                                                 \
        }                                                                                                                          \
        p += curlen;                                                                                                               \
    } while (0);

    for (jj = 0; jj < bytes_nr; jj++) {
        if ((jj % 16) == 0) {
            LEABA_PRINT_BUFFER("\n  %p: ", buf + jj);
        }

        LEABA_PRINT_BUFFER("%02x ", buf[jj]);
    }
#undef LEABA_PRINT_BUFFER

    if (is_err) {
        dev_err(&nic->pdev->dev, "%s: %s: %s: len=%d data=%s\n", nic->name, func, title, bytes_nr, dbg_buff);
    } else {
        dev_info(&nic->pdev->dev, "%s: %s: %s: len=%d data=%s\n", nic->name, func, title, bytes_nr, dbg_buff);
    }
}

int
check_and_handle_pci_errors(struct leaba_nic_t* nic, uint32_t regval)
{
    if (regval == 0xffffffff) {
        dev_warn(&nic->pdev->dev, "%s: %s: PCI error detected - deactivating interface\n", nic->name, __func__);
        /* deactivate_interface() will not work since pci is down */
        nic->is_active = 0;
        return 1;
    }

    return 0;
}

int
single_interface_buffer_alloc(struct pci_dev* pdev,
                              struct leaba_nic_t* nic,
                              enum buffer_type buf_type,
                              uint8_t** out_virt,
                              dma_addr_t* out_phys)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    *out_virt = dma_zalloc_coherent(&pdev->dev, REAL_BUFFER_SIZE_BYTES(buf_type), out_phys, GFP_KERNEL);
#else
    *out_virt = dma_alloc_coherent(&pdev->dev, REAL_BUFFER_SIZE_BYTES(buf_type), out_phys, GFP_KERNEL);
#endif
    if (*out_virt == NULL) {
        dev_err(&pdev->dev, "%s: %s: dma_alloc_coherent failed\n", nic->name, __func__);
        return -ENOMEM;
    }

    if (!PAGE_ALIGNED(*out_virt)) {
        dev_err(&pdev->dev, "%s: %s: got unaligned address %p\n", nic->name, __func__, *out_virt);
        dma_free_coherent(&pdev->dev, REAL_BUFFER_SIZE_BYTES(buf_type), *out_virt, *out_phys);
        *out_virt = NULL;
        return -ENOMEM;
    }

    dev_info(&pdev->dev, "%s: %s: %p/%llx\n", nic->name, __func__, *out_virt, *out_phys);

    return 0;
}

void
free_punt_inject_descriptor(struct leaba_nic_t* nic, struct punt_inject_buffer_desc* desc)
{
    if (!desc->data) { /* 'skb' and 'data' are the same, a union */
        return;
    }

    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev, "%s: %s: desc=%p is_skb=%d data=%p\n", nic->name, __func__, desc, desc->is_skb, desc->data);
    }

    if (desc->is_skb) {
        dev_kfree_skb(desc->skb);
    } else {
        kfree(desc->data);
    }
    desc->data = NULL;
}

void
interface_buffers_free(struct pci_dev* pdev, struct leaba_nic_t* nic)
{
#define FREE_BUFFER(_n, _t)                                                                                                        \
    do {                                                                                                                           \
        if (nic->buffer_virt_##_n != NULL) {                                                                                       \
            dma_free_coherent(&pdev->dev, REAL_BUFFER_SIZE_BYTES(_t), nic->buffer_virt_##_n, nic->buffer_phys_##_n);               \
            nic->buffer_virt_##_n = NULL;                                                                                          \
            nic->buffer_phys_##_n = 0;                                                                                             \
            nic->write_ptr_##_n = 0;                                                                                               \
            nic->read_ptr_##_n = 0;                                                                                                \
        }                                                                                                                          \
    } while (0)

    FREE_BUFFER(ext_desc, BUFFER_TYPE_DESC);
    FREE_BUFFER(inj_desc, BUFFER_TYPE_DESC);
    FREE_BUFFER(ext_data, BUFFER_TYPE_DATA);
    FREE_BUFFER(inj_data, BUFFER_TYPE_DATA);
#undef FREE_BUFFER

#define FREE_BUFFER_LIST(_list)                                                                                                    \
    do {                                                                                                                           \
        if (_list) {                                                                                                               \
            size_t i;                                                                                                              \
            for (i = 0; i < NUM_OF_ELEMENTS_IN_DESC_BUFFER; i++) {                                                                 \
                free_punt_inject_descriptor(nic, &_list[i]);                                                                       \
            }                                                                                                                      \
            kfree(_list);                                                                                                          \
            _list = NULL;                                                                                                          \
        }                                                                                                                          \
    } while (0)

    FREE_BUFFER_LIST(nic->ext_skb_list);
    FREE_BUFFER_LIST(nic->inj_buffer_list);
#undef FREE_BUFFER_LIST
}

void
interface_teardown(struct pci_dev* pdev, struct leaba_nic_t* nic)
{
    nic->asic.deactivate_interface(nic);

    interface_buffers_free(pdev, nic);
}

void
do_buffer_ptr_inc(struct leaba_nic_t* nic, uint32_t* ptr, enum buffer_type buf_type, uint32_t increment, int contig_wrap)
{
    const uint32_t wrap_bit = (buf_type == BUFFER_TYPE_DESC) ? DESC_BUFFER_WRAP_BIT : DATA_BUFFER_WRAP_BIT;
    uint32_t newptr = (*ptr & ~wrap_bit) + increment;
    uint32_t ptr_wrap_bit = *ptr & wrap_bit;
    uint32_t buffer_size = (increment == 1) ? NUM_OF_ELEMENTS_IN_DESC_BUFFER : BUFFER_SIZE_BYTES(buf_type);

    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev,
                 "%s: %s: ptr=%x buf_type=%d increment=%d contig_wrap=%d\n",
                 nic->name,
                 __func__,
                 *ptr,
                 buf_type,
                 increment,
                 contig_wrap);
        dev_info(&nic->pdev->dev,
                 "%s: %s: wrap_bit=%x newptr=%x ptr_wrap_bit %x, buffer_size=%d\n",
                 nic->name,
                 __func__,
                 wrap_bit,
                 newptr,
                 ptr_wrap_bit,
                 buffer_size);
    }

    if (newptr >= buffer_size) {
        ptr_wrap_bit ^= wrap_bit;
        if (contig_wrap) {
            newptr -= buffer_size;
        } else {
            newptr = 0;
        }

        if (g_leaba_module_debug_level > 6) {
            dev_info(
                &nic->pdev->dev, "%s: %s: wrapping around: newptr=%x ptr_wrap_bit=%x\n", nic->name, __func__, newptr, ptr_wrap_bit);
        }
    }

    *ptr = ptr_wrap_bit | newptr;
    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev, "%s: %s: ptr=%x\n", nic->name, __func__, *ptr);
    }
}

uint32_t
get_ext_desc_write_pointer(const struct leaba_nic_t* nic)
{
    if (m_use_write_back) {
        uint32_t* ptr = (uint32_t*)(nic->buffer_virt_ext_desc + BUFFER_SIZE_BYTES(BUFFER_TYPE_DESC));
        return *ptr;
    } else {
        uint32_t reg = nic->asic.ext_wr_pd_ptr_0;
        uint32_t regval = read_sbif_dma_register(nic->pdev, reg, nic->index);
        return regval;
    }
}

uint32_t
get_inject_desc_read_pointer(const struct leaba_nic_t* nic)
{
    if (m_use_write_back) {
        uint32_t* ptr = (uint32_t*)(nic->buffer_virt_inj_desc + BUFFER_SIZE_BYTES(BUFFER_TYPE_DESC));

        return *ptr;
    } else {
        uint32_t reg = nic->asic.inj_rd_pd_ptr_0;
        uint32_t regval = read_sbif_dma_register(nic->pdev, reg, nic->index);
        return regval;
    }
}

uint32_t
get_desc_buffer_available_space(uint32_t raw_write_ptr, uint32_t raw_read_ptr, uint32_t element_size)
{
    uint32_t buffer_size = NUM_OF_ELEMENTS_IN_DESC_BUFFER * element_size;
    uint32_t write_ptr = raw_write_ptr & ~DESC_BUFFER_WRAP_BIT;
    uint32_t write_wrap = raw_write_ptr & DESC_BUFFER_WRAP_BIT;
    uint32_t read_ptr = raw_read_ptr & ~DESC_BUFFER_WRAP_BIT;
    uint32_t read_wrap = raw_read_ptr & DESC_BUFFER_WRAP_BIT;

    return (write_wrap == read_wrap) ? buffer_size - (write_ptr - read_ptr) : read_ptr - write_ptr;
}

void
print_descriptor(struct leaba_nic_t* nic, const char* func, const union leaba_nic_packet_descriptor_t* desc)
{
    dev_info(&nic->pdev->dev,
             "%s: %s: desc=%p : %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
             nic->name,
             func,
             desc,
             *(((uint8_t*)desc) + 0),
             *(((uint8_t*)desc) + 1),
             *(((uint8_t*)desc) + 2),
             *(((uint8_t*)desc) + 3),
             *(((uint8_t*)desc) + 4),
             *(((uint8_t*)desc) + 5),
             *(((uint8_t*)desc) + 6),
             *(((uint8_t*)desc) + 7),
             *(((uint8_t*)desc) + 8),
             *(((uint8_t*)desc) + 9),
             *(((uint8_t*)desc) + 10),
             *(((uint8_t*)desc) + 11),
             *(((uint8_t*)desc) + 12),
             *(((uint8_t*)desc) + 13),
             *(((uint8_t*)desc) + 14),
             *(((uint8_t*)desc) + 15));
}

void
leaba_nic_rx(struct leaba_nic_t* nic, union leaba_nic_packet_descriptor_t* desc, uint64_t desc_size)
{
    unsigned long flags = 0;
    struct sk_buff* skb;

    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev, " %s: entering \n", __func__);
    }

    if (!nic->is_active) {
        return;
    }

    skb = nic->asic.get_ext_skb(nic, desc);
    if (skb == NULL) {
        return;
    }

    /* send the packet */
    netif_rx(skb);

    /* update stats */
    spin_lock_irqsave(&nic->stats_spinlock, flags);
    nic->stats.rx_packets++;
    nic->stats.rx_bytes += desc_size;
    spin_unlock_irqrestore(&nic->stats_spinlock, flags);
}

void
leaba_check_device_pointers(struct leaba_nic_t* nic)
{
    ktime_t kt = ktime_set(0, m_polling_interval_usec * NSEC_PER_USEC); /* ktime is given in nsec */

    nic->asic.check_inj_pointer(nic);
    nic->asic.check_ext_pointers(nic);

    hrtimer_start(&nic->polling_timer, kt, HRTIMER_MODE_REL); /* don't care about the return value */
}

void
do_check_device_pointers(struct work_struct* work)
{
    struct leaba_nic_t* nic = container_of(work, struct leaba_nic_t, deferred_work);
    int is_teardown = atomic_read(&nic->is_teardown);
    if (is_teardown) {
        return;
    }

    leaba_check_device_pointers(nic);
}

// ################

/* called by the kernel when the interface is up */
static int
leaba_nic_open(struct net_device* ndev)
{
    struct leaba_nic_t* nic = netdev_priv(ndev);

    memcpy(ndev->dev_addr, &nic->mac_addr, ETH_ALEN);
    netif_start_queue(ndev);
    return 0;
}

/* called by the kernel when the interface is down */
static int
leaba_nic_release(struct net_device* ndev)
{
    struct leaba_nic_t* nic = netdev_priv(ndev);

    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev, "%s: %s: netif_stop\n", nic->name, __func__);
    }

    netif_stop_queue(ndev);
    return 0;
}

/* called by the kernel when a packet is passed to the device for transmission */
static int
leaba_nic_tx(struct sk_buff* skb, struct net_device* ndev)
{
    struct leaba_nic_t* nic = netdev_priv(ndev);
    unsigned long flags = 0;

    if (!nic->is_active) {
        return NETDEV_TX_OK; /* don't retry */
    }

    /* no support for large packets */
    if (round_up(skb->len, BYTES_IN_DQWORD) > INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES) {
        dev_err_ratelimited(&ndev->dev, "%s: %s: input buffer too big\n", nic->name, __func__);
        spin_lock_irqsave(&nic->stats_spinlock, flags);
        nic->stats.tx_errors++;
        spin_unlock_irqrestore(&nic->stats_spinlock, flags);
        return NETDEV_TX_OK; /* don't retry */
    }

    if (skb_put_padto(skb, MIN_PACKET_SIZE))
        return NETDEV_TX_OK;

    if (g_leaba_module_debug_level > 0) {
        print_buffer(__func__, "orig packet", nic, skb->data, skb->len, 0);
    }

    return nic->asic.nic_tx(skb, ndev);
}

/* called by the kernel when an application queries the interface */
/* vanilla kernels expect the function to return a value. CentOS7 kernel
 * doens't. Using KERNEL_VERSION macro as a workaround. */
static inline void
__leaba_nic_stats(struct net_device* ndev, struct rtnl_link_stats64* stats)
{
    struct leaba_nic_t* nic = netdev_priv(ndev);
    unsigned long flags = 0;

    spin_lock_irqsave(&nic->stats_spinlock, flags);
    memcpy(stats, &nic->stats, sizeof(*stats));
    spin_unlock_irqrestore(&nic->stats_spinlock, flags);
}

// NOTE:
// Linux kernel changed ndo_get_stats64 API signature between 3.10 and 4.11
// We need to implement both to fit any kernel version
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0) && LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
/* called by the kernel when an application queries the interface */
static struct rtnl_link_stats64*
leaba_nic_stats(struct net_device* ndev, struct rtnl_link_stats64* stats)
{
    __leaba_nic_stats(ndev, stats);
    return stats;
}
#else
static void
leaba_nic_stats(struct net_device* ndev, struct rtnl_link_stats64* stats)
{
    __leaba_nic_stats(ndev, stats);
}
#endif

/* polling function, called periodically by the kernel */
static enum hrtimer_restart
leaba_nic_polling_func(struct hrtimer* timer)
{
    struct leaba_nic_t* nic = container_of(timer, struct leaba_nic_t, polling_timer);
    int is_teardown = atomic_read(&nic->is_teardown);
    if (is_teardown) {
        return HRTIMER_NORESTART;
    }

    if (nic->is_active) {
        /* do the rest outside of interrupt context */
        schedule_work(&nic->deferred_work);
    }

    /* if nic is active then timer will be restarted by the deferred-work
     * if nic is not active then the timer will be restarted on activation */
    return HRTIMER_NORESTART;
}

/* initialize the polling timer */
static void
initialize_polling_timer(struct leaba_nic_t* nic)
{
    ktime_t kt = ktime_set(0, m_polling_interval_usec * NSEC_PER_USEC); /* ktime is given in nsec */

    hrtimer_init(&nic->polling_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    nic->polling_timer.function = leaba_nic_polling_func;
    hrtimer_start(&nic->polling_timer, kt, HRTIMER_MODE_REL); /* don't care about the return value */
}

/* teardown an interface */
static void
remove_interface(struct pci_dev* pdev, int n)
{
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    struct leaba_nic_t* nic;

    if (ldev->interfaces[n] == NULL) {
        dev_warn(&pdev->dev, "leaba%d: %s: interface %d is not active\n", ldev->devno, __func__, n);
        return;
    }

    nic = netdev_priv(ldev->interfaces[n]);
    dev_info(&pdev->dev, "%s: removing\n", nic->name);

    /* sync bottom-half and teardown flows
     * sequence is:
     *   1) is_teardown <- true
     *   2) cancel timer
     *   3) cancel bh
     *   4) cancel timer
     * driver is either executing in bottom-half or waiting for the timer to expire.
     * if step 1 is executed while the driver is waiting for the timer then
     * steps 2 and 3 are needed for sync, and step 4 is superfluous.
     * if step 1 is executed while the driver is inside the bh then step 1 is superfluous,
     * and steps 3 and 4 are needed.  */
    atomic_set(&nic->is_teardown, 1);
    if (m_use_polling) {
        hrtimer_cancel(&nic->polling_timer); /* don't care about the return value */
    } else {
        // TODO - mask interrupts
    }
    cancel_work_sync(&nic->deferred_work);
    if (m_use_polling) {
        hrtimer_cancel(&nic->polling_timer); /* don't care about the return value */
    }

    if (nic->netdev_registered) {
        unregister_netdev(ldev->interfaces[n]);
    }

    interface_teardown(pdev, nic);
    free_netdev(ldev->interfaces[n]);
    ldev->interfaces[n] = NULL;
}

static void
stop_interface(struct net_device* netdev)
{
    struct leaba_nic_t* nic = netdev_priv(netdev);

    dev_info(&nic->pdev->dev, "%s: stopping\n", nic->name);

    nic->asic.deactivate_interface(nic);

    dev_info(&nic->pdev->dev, "%s: stopped\n", nic->name);
}

/* callback functions needed by the networking sub-system */
static const struct net_device_ops m_leaba_netdev_ops = {
    .ndo_open = leaba_nic_open,    /* ifconfig up */
    .ndo_stop = leaba_nic_release, /* ifconfig down */
    .ndo_start_xmit = leaba_nic_tx,
    .ndo_get_stats64 = leaba_nic_stats,
};

/* initialize the netdevice */
static void
leaba_nic_setup(struct net_device* ndev)
{
    ether_setup(ndev);
}

/* initialize asic specific fields in the nic interface struct */
extern struct asic_specific m_pacific_spec;
extern struct asic_specific m_gibraltar_spec;

static int
init_asic_specific_fields(struct leaba_nic_t* nic)
{
    if (nic->pdev->device == LEABA_PACIFIC_DEVICE_ID) {
        dev_info(&nic->pdev->dev, "%s: initilized for PACIFIC\n", nic->name);
        nic->asic = m_pacific_spec;

        return 0;
    } else if (nic->pdev->device == LEABA_GIBRALTAR_DEVICE_ID) {
        dev_info(&nic->pdev->dev, "%s: initilized for GIBRALTAR\n", nic->name);
        nic->asic = m_gibraltar_spec;

        return 0;
    }

    // Unknown device
    return -ENODEV;
}

/* add an interface */
static int
add_interface(struct pci_dev* pdev, int n)
{
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    int result = -1;
    struct net_device* newdev = NULL;
    struct leaba_nic_t* nic = NULL;
    char interface_name[IFNAMSIZ];

    if (ldev->interfaces[n] != NULL) {
        dev_warn(&pdev->dev, "leaba%d: %s: interface %d already active", ldev->devno, __func__, n);
        return 0;
    }

    /* net-device initialization */
    snprintf(interface_name, sizeof(interface_name), "%s%d_%d", m_interface_base_name, ldev->devno, n);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
    newdev = alloc_netdev(sizeof(struct leaba_nic_t), interface_name, leaba_nic_setup);
#else
    newdev = alloc_netdev(sizeof(struct leaba_nic_t), interface_name, NET_NAME_USER, leaba_nic_setup);
#endif
    if (newdev == NULL) {
        result = -ENOMEM;
        dev_err(&pdev->dev, "leaba%d: %s: alloc_etherdev failed\n", ldev->devno, __func__);
        goto out;
    }

    newdev->watchdog_timeo = 0; /* disable watchdog */
    newdev->netdev_ops = &m_leaba_netdev_ops;
    newdev->flags |= IFF_NOARP;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
    newdev->min_mtu = ETH_MIN_MTU;
    newdev->max_mtu = INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES;
#endif

    /* leaba specific initialization */
    ldev->interfaces[n] = newdev;
    nic = netdev_priv(newdev);
    nic->index = n;
    nic->ndev = newdev;
    nic->pdev = pdev;
    strncpy(nic->name, newdev->name, MAX_INTERFACE_NAME_LEN);
    result = init_asic_specific_fields(nic);
    if (result != 0) {
        dev_err(&pdev->dev, "%s: %s: init_device_specific_fields failed %d\n", nic->name, __func__, result);
        goto err_free_netdev;
    }

    result = nic->asic.interface_init(nic);
    if (result != 0) {
        dev_err(&pdev->dev, "%s: %s: interface_init failed %d\n", nic->name, __func__, result);
        goto err_free_netdev;
    }

    /* device initialiation succeeded. now register the driver with the kernel */
    result = register_netdev(newdev);
    if (result != 0) {
        dev_err(&pdev->dev, "%s: %s: register_netdev failed %d\n", nic->name, __func__, result);
        goto err_interface_teardown;
    }

    /* mark the device for un-registration on teardown */
    nic->netdev_registered = 1;

    dev_info(&pdev->dev, "%s: added\n", nic->name);

    /* start the polling timer if needed */
    if (m_use_polling) {
        initialize_polling_timer(nic);
    }

    result = 0;
out:
    return result;

err_interface_teardown:
    interface_teardown(pdev, nic);
err_free_netdev:
    free_netdev(ldev->interfaces[n]);
    ldev->interfaces[n] = NULL;
    goto out;
}

/* expose interface attributes thru sysfs */
static int
parse_mac_addr_str(const char* str, uint64_t* out_mac_addr)
{
    int i;
    unsigned shift = 0;
    uint8_t macaddr[ETH_ALEN];
    size_t len = sscanf(
        str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &macaddr[0], &macaddr[1], &macaddr[2], &macaddr[3], &macaddr[4], &macaddr[5]);

    *out_mac_addr = 0;
    for (i = ARRAY_SIZE(macaddr) - 1; i >= 0; i--) {
        *out_mac_addr += (uint64_t)macaddr[i] << shift;
        shift += 8;
    }

    return len == ETH_ALEN;
}

/* read user interface-specific commands */
ssize_t
leaba_nic_store_if(struct device* dev, struct device_attribute* attr, const char* buf, size_t count, unsigned n)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);

    if ((count >= 2) && (buf[0] == '1') && (buf[1] == '\0')) {
        /* enable */
        int ret = 0;
        if (ldev->interfaces[n] != NULL) {
            /* nothing to do */
            return count;
        }

        ret = add_interface(pdev, n);
        if (ret) {
            dev_err(&pdev->dev, "leaba%d: %s: add_interface %d failed\n", ldev->devno, __func__, n);
        }
    } else if ((count >= 2) && (buf[0] == '0') && (buf[1] == '\0')) {
        /* disable */
        remove_interface(pdev, n);
    } else if ((count >= 2) && (buf[0] == 'A') && (buf[1] == '\0')) {
        /* activate */
        if (ldev->interfaces[n] != NULL) {
            struct leaba_nic_t* nic = netdev_priv(ldev->interfaces[n]);
            nic->asic.activate_interface(nic);
        }
    } else if ((count >= 2) && (buf[0] == 'D') && (buf[1] == '\0')) {
        /* de-activate */
        if (ldev->interfaces[n] != NULL) {
            struct leaba_nic_t* nic = netdev_priv(ldev->interfaces[n]);
            nic->asic.deactivate_interface(nic);
        }
    } else if ((count >= 21) && (buf[0] == 'm') && (buf[1] == 'a') && (buf[2] == 'c') && (buf[3] == '=') && (buf[21] == '\0')) {
        /* set the mac address */
        if (ldev->interfaces[n] != NULL) {
            struct leaba_nic_t* nic = netdev_priv(ldev->interfaces[n]);
            uint64_t mac_addr;
            const char* p = buf + strlen("mac=");
            int is_valid_mac_addr = parse_mac_addr_str(p, &mac_addr);
            if (is_valid_mac_addr) {
                memcpy(ldev->interfaces[n]->dev_addr, &mac_addr, ETH_ALEN);
                nic->mac_addr = mac_addr;
                dev_info(&pdev->dev, "%s: %s: MAC address set %s %s\n", nic->name, __func__, nic->name, p);
            } else {
                dev_warn(&pdev->dev, "%s: %s: illegal mac address string '%s'\n", nic->name, __func__, p);
            }
        }
    } else {
        /* unexpected input from user. ignore */
    }

    return count;
}

/* show interface info */
static ssize_t
leaba_nic_show_if(struct device* dev, struct device_attribute* attr, char* buf, unsigned n)
{
    struct leaba_nic_t* nic = NULL;
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    if (ldev->interfaces[n] == NULL) {
        // SDK code relies on this output. see la_device_impl::reconnect_pci_ports_after_warm_boot()
        return sprintf(buf, "Interface %d is not enabled\n", n);
    }

    nic = netdev_priv(ldev->interfaces[n]);

    return nic->asic.show_if(nic, attr, buf, n);
}

#define SYSFS_FUNCTIONS(_n)                                                                                                        \
    static ssize_t leaba_nic##_n##_show(struct device* dev, struct device_attribute* attr, char* buf)                              \
    {                                                                                                                              \
        return leaba_nic_show_if(dev, attr, buf, _n);                                                                              \
    }                                                                                                                              \
                                                                                                                                   \
    /* sysfs control on interface add/remove */                                                                                    \
    static ssize_t leaba_nic##_n##_store(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)         \
    {                                                                                                                              \
        return leaba_nic_store_if(dev, attr, buf, count, _n);                                                                      \
    }

SYSFS_FUNCTIONS(0)
SYSFS_FUNCTIONS(1)
SYSFS_FUNCTIONS(2)
SYSFS_FUNCTIONS(3)
SYSFS_FUNCTIONS(4)
SYSFS_FUNCTIONS(5)
SYSFS_FUNCTIONS(6)
SYSFS_FUNCTIONS(7)
SYSFS_FUNCTIONS(8)
SYSFS_FUNCTIONS(9)
SYSFS_FUNCTIONS(10)
SYSFS_FUNCTIONS(11)
SYSFS_FUNCTIONS(12)
SYSFS_FUNCTIONS(13)
SYSFS_FUNCTIONS(14)
SYSFS_FUNCTIONS(15)

static DEVICE_ATTR_RW(leaba_nic0);
static DEVICE_ATTR_RW(leaba_nic1);
static DEVICE_ATTR_RW(leaba_nic2);
static DEVICE_ATTR_RW(leaba_nic3);
static DEVICE_ATTR_RW(leaba_nic4);
static DEVICE_ATTR_RW(leaba_nic5);
static DEVICE_ATTR_RW(leaba_nic6);
static DEVICE_ATTR_RW(leaba_nic7);
static DEVICE_ATTR_RW(leaba_nic8);
static DEVICE_ATTR_RW(leaba_nic9);
static DEVICE_ATTR_RW(leaba_nic10);
static DEVICE_ATTR_RW(leaba_nic11);
static DEVICE_ATTR_RW(leaba_nic12);
static DEVICE_ATTR_RW(leaba_nic13);
static DEVICE_ATTR_RW(leaba_nic14);
static DEVICE_ATTR_RW(leaba_nic15);

/* get nic reset command from the user */
static ssize_t
leaba_nic_reset_store(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    int num_intf_per_device = get_num_intf_per_dev(pdev);

    if ((count >= 2) && (buf[0] == 'R') && (buf[1] == '\0')) {
        /* NIC reset */
        struct leaba_device_t* ldev = pci_get_drvdata(pdev);
        int j;

        dev_info(dev, "leaba%d: %s invoked", ldev->devno, __func__);

        for (j = 0; j < num_intf_per_device; j++) {
            if (ldev->interfaces[j] != NULL) {
                remove_interface(pdev, j);
            }
        }
    }

    return count;
}

static DEVICE_ATTR_WO(leaba_nic_reset);

/* sysfs management */
static int
add_sysfs_files(struct pci_dev* pdev)
{
    int result = device_create_file(&pdev->dev, &dev_attr_leaba_nic0);
    result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic1);
    result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic2);
    result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic3);
    result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic4);
    result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic5);

    if (is_asic3(pdev) || is_asic5(pdev)) {
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic6);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic7);
    }

    if (is_asic5(pdev)) {
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic8);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic9);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic10);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic11);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic12);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic13);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic14);
        result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic15);
    }

    result |= device_create_file(&pdev->dev, &dev_attr_leaba_nic_reset);

    if (result != 0) {
        struct leaba_device_t* ldev = pci_get_drvdata(pdev);
        dev_err(&pdev->dev, "leaba%d: %s: device_create_file failed %d\n", ldev->devno, __func__, result);
    }

    return result;
}

static void
remove_sysfs_files(struct pci_dev* pdev)
{
    device_remove_file(&pdev->dev, &dev_attr_leaba_nic_reset);

    device_remove_file(&pdev->dev, &dev_attr_leaba_nic0);
    device_remove_file(&pdev->dev, &dev_attr_leaba_nic1);
    device_remove_file(&pdev->dev, &dev_attr_leaba_nic2);
    device_remove_file(&pdev->dev, &dev_attr_leaba_nic3);
    device_remove_file(&pdev->dev, &dev_attr_leaba_nic4);
    device_remove_file(&pdev->dev, &dev_attr_leaba_nic5);

    if (is_asic3(pdev) || is_asic5(pdev)) {
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic6);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic7);
    }

    if (is_asic5(pdev)) {
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic8);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic9);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic10);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic11);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic12);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic13);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic14);
        device_remove_file(&pdev->dev, &dev_attr_leaba_nic15);
    }
}

/* initialize the NIC part of the driver. called by leaba_module on probe */
int
leaba_nic_initialize(struct pci_dev* pdev)
{
    int result;
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    int num_intf_per_device = get_num_intf_per_dev(pdev);

    if (ldev->interfaces) {
        return 0;
    }

    if (DESC_BUFFER_SIZE_BYTES > MAX_DESC_BUFFER_SIZE_BYTES) {
        dev_err(&pdev->dev, "leaba%d: %s: invalid desc buffer size%d\n", ldev->devno, __func__, (uint32_t)DATA_BUFFER_SIZE_BYTES);
        return -EINVAL;
    }

    if (DATA_BUFFER_SIZE_BYTES > (unsigned int)MAX_DATA_BUFFER_SIZE_BYTES) {
        dev_err(&pdev->dev, "leaba%d: %s: invalid data buffer size%d\n", ldev->devno, __func__, (uint32_t)DATA_BUFFER_SIZE_BYTES);
        return -EINVAL;
    }

    BUILD_BUG_ON(INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES < MAX_ETH_FRAME_SIZE + INJ_HEADER_SIZE);

    ldev->interfaces = kzalloc(sizeof(struct net_device*) * num_intf_per_device, GFP_KERNEL);
    if (!ldev->interfaces) {
        dev_err(&pdev->dev, "leaba%d: %s: kmalloc failed\n", ldev->devno, __func__);
        return -ENOMEM;
    }

    /* add sysfs interface to the driver */
    result = add_sysfs_files(pdev);
    if (result != 0) {
        goto err;
    }

    return 0;

err:
    leaba_nic_teardown(pdev);

    return result;
}

/* teardown the NIC part of the driver. called by leaba_module on device removal */
void
leaba_nic_teardown(struct pci_dev* pdev)
{
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    int num_intf_per_device = get_num_intf_per_dev(pdev);
    int j;

    if (!ldev || !ldev->interfaces) {
        return;
    }

    remove_sysfs_files(pdev);

    for (j = 0; j < num_intf_per_device; j++) {
        if (ldev->interfaces[j] != NULL) {
            remove_interface(pdev, j);
        }
    }

    kfree(ldev->interfaces);
    ldev->interfaces = NULL;
}

void
leaba_nic_stop(struct pci_dev* pdev)
{
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    int num_intf_per_device = get_num_intf_per_dev(pdev);
    int j;

    if (!ldev || !ldev->interfaces) {
        return;
    }

    for (j = 0; j < num_intf_per_device; j++) {
        if (ldev->interfaces[j]) {
            stop_interface(ldev->interfaces[j]);
        }
    }
}
