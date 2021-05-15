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

#ifndef __KERNEL_MOCK_H__
#define __KERNEL_MOCK_H__

#include <arpa/inet.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <linux/version.h>
#include <malloc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "kernel_mock_data_structs.h"

#define NUM_INTERFACES_TO_CREATE 6

#define ETH_MIN_MTU 68

#define module_param_array(p1, p2, p3, p4)
#define module_param(p1, p2, p3)                                                                                                   \
    void set_module_param_##p1(p2 val)                                                                                             \
    {                                                                                                                              \
        p1 = val;                                                                                                                  \
    }
#define MODULE_PARM_DESC(p1, p2)
#define ARRAY_SIZE(_a) (sizeof(_a) / sizeof(_a[0]))

#define dev_err(_dev, _fmt, ...) fprintf(stderr, _fmt, __VA_ARGS__)
#define dev_warn(_dev, _fmt, ...) fprintf(stderr, _fmt, __VA_ARGS__)
#define dev_err_ratelimited dev_err
#define dev_info(_dev, _fmt, ...)                                                                                                  \
    if (g_leaba_module_debug_level > 0) {                                                                                          \
        fprintf(stdout, _fmt, __VA_ARGS__);                                                                                        \
    }
#define dev_warn_ratelimited(_dev, _fmt, ...) fprintf(stderr, _fmt, __VA_ARGS__)

#define jiffies 0
#define virt_to_phys(_p) (uint64_t)(_p)

typedef uint32_t __le32;

#define le16_to_cpu
#define le16_to_cpus(_p)
#define cpu_to_le16
#define cpu_to_le16s(_p)
#define le32_to_cpu
#define cpu_to_le32
#define le64_to_cpu
#define le64_to_cpus(_p)
#define cpu_to_le64
#define cpu_to_le64s(_p)
#define BITS_PER_BYTE 8

void iowrite32(uint32_t val, uint8_t* addr);
uint32_t ioread32(uint8_t* addr);

#define memcpy_toio memcpy

static struct leaba_device_t*
pci_get_drvdata(struct pci_dev* dev)
{
    return (struct leaba_device_t*)dev->priv;
}

static void*
dma_alloc_coherent(int* dev, unsigned size, dma_addr_t* ppaddr, int flags)
{
    void* p = memalign(PAGE_SIZE, size);
    *ppaddr = (dma_addr_t)p;

    // In newer kernels dma_alloc_coherent init the memory to 0, so we want to act the same
    if (p != NULL) {
        memset(p, 0, size);
    }
    return p;
}

static uint8_t*
dma_zalloc_coherent(int* dev, unsigned size, dma_addr_t* ppaddr, int flags)
{
    return (uint8_t*)dma_alloc_coherent(dev, size, ppaddr, flags);
}

static void
dma_free_coherent(int* dev, unsigned size, void* addr, dma_addr_t ppaddr)
{
    free(addr);
}

static void
spin_lock_init(spinlock_t* l)
{
    *l = 0;
}
static void
spin_lock(volatile spinlock_t* l)
{
    while (__sync_lock_test_and_set(l, 1) != 0)
        ;
}
static void
spin_unlock(volatile spinlock_t* l)
{
    __sync_lock_release(l);
}
static void
spin_lock_irqsave(volatile spinlock_t* l, unsigned long flags)
{
    while (__sync_lock_test_and_set(l, 1) != 0)
        ;
}
static void
spin_unlock_irqrestore(volatile spinlock_t* l, unsigned long flags)
{
    __sync_lock_release(l);
}
static void
mb()
{
    __sync_synchronize();
}

#define WARN_ON_ONCE(_e) assert(!(_e))
#define BUILD_BUG_ON(_e) assert(!(_e))

static struct sk_buff*
dev_alloc_skb(unsigned size)
{
    struct sk_buff* skb = (struct sk_buff*)malloc(sizeof(*skb));
    if (skb != NULL) {
        skb->head = (uint8_t*)malloc(size);
        if (skb->head == NULL) {
            free(skb);
            skb = NULL;
        }
        skb->data = skb->head;
        skb->len = 0;
        skb->end = size;
        skb->tail = 0;
    }

    return skb;
}
#define dev_kfree_skb(_skb)                                                                                                        \
    {                                                                                                                              \
        free(_skb->head);                                                                                                          \
        free(_skb);                                                                                                                \
    }
static int
eth_type_trans(struct sk_buff* skb, struct net_device* dev)
{
    return 0;
}
static uint8_t*
skb_put(struct sk_buff* skb, unsigned int len)
{
    uint8_t* tmp = skb->head + skb->tail;
    skb->tail += len;
    skb->len += len;
    assert(skb->tail <= skb->end);
    return tmp;
}
static uint8_t*
skb_push(struct sk_buff* skb, unsigned int len)
{
    skb->data -= len;
    assert(skb->data >= skb->head);
    skb->len += len;
    return skb->data;
}
static void
skb_reserve(struct sk_buff* skb, int len)
{
    skb->data += len;
    skb->tail += len;
}
static unsigned char*
skb_pull(struct sk_buff* skb, unsigned int len)
{
    skb->len -= len;
    return skb->data += len;
}

// We ensure packet size is enough before calling leaba_nic_tx
static int
skb_put_padto(struct sk_buff* skb, unsigned size)
{
    return 0;
}

static struct leaba_nic_t*
netdev_priv(struct net_device* ndev)
{
    return (struct leaba_nic_t*)ndev->priv;
}
static void
netif_start_queue(struct net_device* ndev)
{
    ndev->is_stopped = 0;
}
static void
netif_wake_queue(struct net_device* ndev)
{
    ndev->is_stopped = 0;
}
static void
netif_stop_queue(struct net_device* ndev)
{
    ndev->is_stopped = 1;
}
static int
netif_queue_stopped(struct net_device* ndev)
{
    return ndev->is_stopped;
}
static struct net_device*
alloc_etherdev(unsigned size)
{
    struct net_device* ndev = (struct net_device*)malloc(sizeof(*ndev));
    if (ndev != NULL) {
        memset(ndev, 0, sizeof(*ndev));
        ndev->priv = malloc(size);
        if (ndev->priv == NULL) {
            free(ndev);
            ndev = NULL;
        }
        memset(ndev->priv, 0, size);
    }

    return ndev;
}

static int
device_create_file(int* device, const struct device_attribute* entry)
{
    return 0;
};
static void device_remove_file(int* dev, const struct device_attribute* attr){};
extern struct net_device s_ndev[];

static int
register_netdev(struct net_device* ndev)
{
    //    g_ndev[ndev_index++] = ndev;
    return 0;
}
static void
unregister_netdev(struct net_device* ndev)
{
    return;
}
#define free_netdev(_ndev)                                                                                                         \
    {                                                                                                                              \
        free(_ndev->priv);                                                                                                         \
    }
//        free(_ndev); \ // We use static allocation. No need to free

static struct net_device*
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
alloc_netdev(int sizeof_priv, const char* name, void (*setup)(struct net_device*))
#else
#define NET_NAME_USER 0
alloc_netdev(int sizeof_priv, const char* name, int net_name_user, void (*setup)(struct net_device*))
#endif
{
    static int ndev_index = 0;

    if (ndev_index == NUM_INTERFACES_TO_CREATE) {
        ndev_index = 0;
    }
    s_ndev[ndev_index].priv = malloc(sizeof_priv);
    if (s_ndev[ndev_index].priv == NULL) {
        fprintf(stderr, "alloc netdev - malloc failed\n");
        return NULL;
    }
    memset(s_ndev[ndev_index].priv, 0, sizeof_priv);
    return &s_ndev[ndev_index++];
}

static struct net_device**
kzalloc(uint size, int param)
{
    struct net_device** ret = (struct net_device**)malloc(size);

    if (ret != NULL) {
        bzero(ret, size);
    }
    return ret;
}

static void ether_setup(struct net_device* ndev){};

static unsigned
msecs_to_jiffies(unsigned msec)
{
    return msec;
}

#define hrtimer timer_list

static struct timer_list* m_timer;

static void
handler(int sig)
{
    m_timer->function(0);
}

static void
hrtimer_init(struct hrtimer* timer, clockid_t which_clock, enum hrtimer_mode mode)
{
    int ret;

    __sighandler_t prev = signal(SIGALRM, handler);
    assert(prev != SIG_ERR);
    (void)prev; // suppress unused variable warning in NDEBUG build

    ret = timer_create(CLOCK_MONOTONIC, NULL, &timer->timer_id);
    assert(ret == 0);
    (void)ret; // suppress unused variable warning in NDEBUG build

    m_timer = timer;
}

static inline void
hrtimer_start(struct hrtimer* timer, ktime_t tim, const enum hrtimer_mode mode)
{
}
static inline u64
hrtimer_forward_now(struct hrtimer* timer, ktime_t interval)
{
    return 0;
}
static int
hrtimer_cancel(struct hrtimer* timer)
{
    return 0;
}

#define cancel_work_sync(_w)
#define INIT_WORK(_w, _f)                                                                                                          \
    do {                                                                                                                           \
        (_w)->func = _f;                                                                                                           \
    } while (0)
#define schedule_work(_w)                                                                                                          \
    do {                                                                                                                           \
        (_w)->func(_w);                                                                                                            \
    } while (0)
#define atomic_cmpxchg(atom_p, oldval, newval) __sync_val_compare_and_swap(&((atom_p)->counter), oldval, newval)
#define atomic_set(atom_p, newval)                                                                                                 \
    do {                                                                                                                           \
        (atom_p)->counter = newval;                                                                                                \
    } while (0)
#define atomic_read(atom_p) (atom_p)->counter

#define cpu_relax()
#define BUG_ON(_c) assert(!_c)

#endif // __KERNEL_MOCK_H__
