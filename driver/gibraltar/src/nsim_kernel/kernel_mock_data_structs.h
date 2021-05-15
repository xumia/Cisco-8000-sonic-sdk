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

#ifndef __KERNEL_MOCK_DATA_STRUCTS_H__
#define __KERNEL_MOCK_DATA_STRUCTS_H__

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define PAGE_SIZE 4096ull
#define ALIGN(_v, _a) (((_v) + (_a)-1) & ~((_a)-1))
#define PAGE_ALIGN(_v) ALIGN((_v), PAGE_SIZE)
#define PAGE_ALIGNED(_v) (ALIGN(((uint64_t)(_v)), PAGE_SIZE) == (uint64_t)(_v))
#define GFP_KERNEL 0
#define GFP_DMA 0
#define ETH_ALEN 6
#define NETDEV_TX_OK 0
#define CHECKSUM_UNNECESSARY 0
#define IFF_NOARP 0
#define NSEC_PER_USEC 1000L
#define NSEC_PER_SEC 1000000000L
#define KTIME_MAX ((s64) ~((u64)1 << 63))
#define KTIME_SEC_MAX (KTIME_MAX / NSEC_PER_SEC)
#define IFNAMSIZ 16

// needed because in kernel compilation using llu for printing uint64_t, and user space wanted lx
typedef unsigned long long user_space_uint64_t;
#define uint64_t user_space_uint64_t

typedef uint64_t resource_size_t;
typedef uint64_t dma_addr_t;
typedef uint32_t uint;
#ifndef __cplusplus
typedef uint8_t bool;
#endif
typedef char* charp;

struct device_attribute {
    int a;
};

struct device;

#define __iomem
#define kfree(mem) free(mem)

#define DEVICE_ATTR_RW(_name) struct device_attribute dev_attr_##_name;
#define DEVICE_ATTR_WO(_name) struct device_attribute dev_attr_##_name;

enum hrtimer_restart {
    HRTIMER_NORESTART, /* Timer is not restarted */
    HRTIMER_RESTART,   /* Timer must be restarted */
};

enum hrtimer_mode {
    HRTIMER_MODE_ABS = 0x0,     /* Time value is absolute */
    HRTIMER_MODE_REL = 0x1,     /* Time value is relative to now */
    HRTIMER_MODE_PINNED = 0x02, /* Timer is bound to CPU */
    HRTIMER_MODE_ABS_PINNED = 0x02,
    HRTIMER_MODE_REL_PINNED = 0x03,
};

typedef long long s64;
typedef unsigned long long u64;
union ktime {
    s64 tv64;
};
typedef union ktime ktime_t;

static inline ktime_t
ktime_set(const s64 secs, const unsigned long nsecs)
{
    if (secs >= KTIME_SEC_MAX)
        return (ktime_t){.tv64 = KTIME_MAX};

    return (ktime_t){.tv64 = secs * NSEC_PER_SEC + (s64)nsecs};
}

struct uinfo_mem {
    void* internal_addr;
};

struct uio_info {
    struct uinfo_mem mem[1];
};

struct pci_dev {
    int dev;
    void* priv;
    int device;
};

#define container_of(ptr, type, member) (type*)((char*)(ptr) - (char*)&((type*)0)->member)

#define to_pci_dev(n) container_of(n, struct pci_dev, dev)

struct net_device_stats {
    unsigned rx_packets;
    unsigned rx_bytes;
    unsigned rx_errors;
    unsigned rx_dropped;
    unsigned tx_packets;
    unsigned tx_bytes;
    unsigned tx_errors;
    unsigned tx_dropped;
};

struct rtnl_link_stats64 {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_errors;
    uint64_t rx_dropped;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_dropped;
};

typedef int spinlock_t;

struct sk_buff {
    uint8_t* head;
    unsigned int end;
    uint8_t* data;
    unsigned int tail;
    unsigned len;
    struct net_device* dev;
    int protocol;
    int ip_summed;
};

struct net_device;
struct net_device_ops {
    int (*ndo_open)(struct net_device* dev);
    int (*ndo_stop)(struct net_device* dev);
    int (*ndo_start_xmit)(struct sk_buff* skb, struct net_device* dev);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0) && LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device* dev, struct rtnl_link_stats64* storage);
#else
    void (*ndo_get_stats64)(struct net_device* dev, struct rtnl_link_stats64* storage);
#endif
};

struct net_device {
    int index;
    int dev;
    void* priv;
    int is_stopped;
    int watchdog_timeo;
    const struct net_device_ops* netdev_ops;
    uint8_t dev_addr[ETH_ALEN];
    int flags;
    char name[16];
    unsigned int min_mtu;
    unsigned int max_mtu;
};

struct timer_list {
    enum hrtimer_restart (*function)(struct timer_list*);
    unsigned long data;
    unsigned expires;
    timer_t timer_id;
};

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define printk printf
#define KERN_DEBUG "2,"

#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init) int name;
static int
__ratelimit(int* a)
{
    return 0;
}

extern void netif_rx(struct sk_buff* skb);

struct work_struct {
    void (*func)(struct work_struct*);
};

typedef struct {
    int counter;
} atomic_t;

typedef struct {
    long long counter;
} atomic64_t;

#endif // __KERNEL_MOCK_DATA_STRUCTS_H__
