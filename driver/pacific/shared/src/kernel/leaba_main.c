// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include <linux/aer.h>
#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "leaba_module.h"
#include "leaba_registers.h"

#define LEABA_MODULE_DEV_NAME "leaba_module_device"
#define LEABA_MODULE_VERSION "dev"

#define leaba_printk(fmt, arg...) printk(LEABA_MODULE_DEV_NAME " " fmt, ##arg)

/* Use 64bit or 32bit bar. On device side, both bars map to the same resource */
static int m_use_64bit_bar = 1;
module_param(m_use_64bit_bar, int, 0444);
MODULE_PARM_DESC(m_use_64bit_bar, "Use 64bit BAR for memory-mapped access");

/*
 * Use leaba or uio mmap:
 * -1 choose automatically, based on kernel version.
 *  0 use leaba mmap.
 *  1 use uio mmap.
 */
static int m_use_uio_mmap = -1;
module_param(m_use_uio_mmap, int, 0444);
MODULE_PARM_DESC(m_use_uio_mmap, "Use leaba or uio mmap");

/* Indices of 64bit and 32bit bars */
#define LEABA_BAR_64BIT 0
#define LEABA_BAR_32BIT 2

/*---------------------------------------------------------------------------------------*/
/* PCI stuff */
#ifndef PCI_VENDOR_ID_SYNOPSYS
#define PCI_VENDOR_ID_SYNOPSYS 0x16c3
#endif
static const struct pci_device_id leaba_pci_ids[] = {
    {PCI_DEVICE(0x1747, 0x2)},
    {PCI_DEVICE(PCI_VENDOR_ID_SYNOPSYS, LEABA_PACIFIC_DEVICE_ID)}, /* Pacific A0 */
    {PCI_DEVICE(PCI_VENDOR_ID_CISCO, LEABA_PACIFIC_DEVICE_ID)},    /* Pacific B0 and later */
    {PCI_DEVICE(PCI_VENDOR_ID_CISCO, LEABA_GIBRALTAR_DEVICE_ID)},
    {PCI_DEVICE(PCI_VENDOR_ID_CISCO, LEABA_ASIC3_DEVICE_ID)},
    {PCI_DEVICE(PCI_VENDOR_ID_CISCO, LEABA_ASIC4_DEVICE_ID)},
    {PCI_DEVICE(PCI_VENDOR_ID_CISCO, LEABA_ASIC5_DEVICE_ID)},
    {PCI_DEVICE(PCI_VENDOR_ID_CISCO, LEABA_ASIC6_DEVICE_ID)},
    {/* All zeros -> end */},
};

static bool
is_gibraltar(const struct pci_dev* pdev)
{
    return (pdev->vendor == PCI_VENDOR_ID_CISCO && pdev->device == LEABA_GIBRALTAR_DEVICE_ID);
}

static bool
is_asic4(const struct pci_dev* pdev)
{
    return (pdev->vendor == PCI_VENDOR_ID_CISCO && pdev->device == LEABA_ASIC4_DEVICE_ID);
}

static bool
is_asic5(const struct pci_dev* pdev)
{
    return (pdev->vendor == PCI_VENDOR_ID_CISCO && pdev->device == LEABA_ASIC5_DEVICE_ID);
}

static bool
is_asic3(const struct pci_dev* pdev)
{
    return (pdev->vendor == PCI_VENDOR_ID_CISCO && pdev->device == LEABA_ASIC3_DEVICE_ID);
}

#ifndef SZ_1K
#define SZ_1K 0x0000400
#endif

#ifndef SZ_2K
#define SZ_2K 0x0000800
#endif

#ifndef SZ_4K
#define SZ_4K 0x0001000
#endif

#ifndef SZ_8K
#define SZ_8K 0x0002000
#endif

#ifndef SZ_16K
#define SZ_16K 0x0004000
#endif

#ifndef SZ_32K
#define SZ_32K 0x0008000
#endif

#ifndef SZ_64K
#define SZ_64K 0x0010000
#endif

#ifndef SZ_128K
#define SZ_128K 0x0020000
#endif

#ifndef SZ_256K
#define SZ_256K 0x0040000
#endif

static const char*
leaba_pci_event_str(leaba_pci_event_t event)
{
    return (event == LEABA_PCI_EVENT_HOTPLUG_REMOVE ? "HOTPLUG_REMOVE"
                                                    : //
                event == LEABA_PCI_EVENT_AER_NON_RECOVERABLE ? "AER_NON_RECOVERABLE"
                                                             : //
                    event == LEABA_PCI_EVENT_AER_RECOVERABLE ? "AER_RECOVERABLE"
                                                             :                     //
                        event == LEABA_PCI_EVENT_AER_RECOVERED ? "AER_RECOVERED" : //
                            "UNKNOWN");
}

static const char*
pci_channel_state_str(pci_channel_state_t state)
{
    return (state == pci_channel_io_normal ? "io_normal"
                                           : //
                state == pci_channel_io_frozen ? "io_frozen"
                                               :                               //
                    state == pci_channel_io_perm_failure ? "io_perm_failure" : //
                        "UNKNOWN");
}

static ssize_t
leaba_max_open_fd_store(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* leaba_data = pci_get_drvdata(pdev);
    unsigned long val;
    ssize_t rc = kstrtoul(buf, 0, &val);

    if (rc < 0) {
        return rc;
    }
    if (val < 1) {
        // We allow at least one open file descriptor
        return -EINVAL;
    }

    dev_info(dev, "max_open_fd: was=%ld, now=%ld\n", leaba_data->max_open_fd, val);
    leaba_data->max_open_fd = val;

    return rc < 0 ? rc : count;
}

static ssize_t
leaba_max_open_fd_show(struct device* dev, struct device_attribute* attr, char* buf)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* leaba_data = pci_get_drvdata(pdev);

    return snprintf(buf, PAGE_SIZE, "%lu\n", leaba_data->max_open_fd);
}

static ssize_t
leaba_pci_event_show(struct device* dev, struct device_attribute* attr, char* buf)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* leaba_data = pci_get_drvdata(pdev);

    // binary data
    *(leaba_pci_event_t*)buf = leaba_data->pci_event_value;

    return sizeof(leaba_pci_event_t);
}

static ssize_t
leaba_dma_pa_show(struct device* dev, struct device_attribute* attr, char* buf)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* leaba_data = pci_get_drvdata(pdev);

    // binary data
    *(uint64_t*)buf = leaba_data->dma_pa;

    return sizeof(uint64_t);
}

static ssize_t
leaba_interrupt_count_show(struct device* dev, struct device_attribute* attr, char* buf)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* leaba_data = pci_get_drvdata(pdev);

    return snprintf(buf, PAGE_SIZE, "%lu\n", atomic64_read(&leaba_data->interrupt_count));
}

static ssize_t
leaba_interrupt_count_clear_store(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
    struct pci_dev* pdev = to_pci_dev(dev);
    struct leaba_device_t* leaba_data = pci_get_drvdata(pdev);

    atomic64_set(&leaba_data->interrupt_count, 0);

    return count;
}

static DEVICE_ATTR_RW(leaba_max_open_fd);
static DEVICE_ATTR_RO(leaba_pci_event);
static DEVICE_ATTR_RO(leaba_dma_pa);
static DEVICE_ATTR_RO(leaba_interrupt_count);
static DEVICE_ATTR_WO(leaba_interrupt_count_clear);

static struct device_attribute* leaba_device_attrs[] = {&dev_attr_leaba_max_open_fd,
                                                        &dev_attr_leaba_pci_event,
                                                        &dev_attr_leaba_dma_pa,
                                                        &dev_attr_leaba_interrupt_count,
                                                        &dev_attr_leaba_interrupt_count_clear,
                                                        NULL};

#ifdef UDRV_HOTPLUG_SUPPORT

extern int udrv_hp_probe(struct pci_dev* pdev, const struct pci_device_id* id);
extern void udrv_hp_remove(struct pci_dev* pdev, const struct pci_device_id* id);

#else

static inline int
udrv_hp_probe(struct pci_dev* pdev, const struct pci_device_id* id)
{
    return 0;
}

static inline void
udrv_hp_remove(struct pci_dev* pdev, const struct pci_device_id* id)
{
}

#endif

static void
device_sysfs_notify(struct leaba_device_t* leaba_data, const struct device_attribute* attr)
{
    struct kobject* kobj = &(leaba_data->pdev->dev.kobj);
    const char* dir = NULL;
    const char* attr_name = attr->attr.name;

    sysfs_notify(kobj, dir, attr_name);
}

static void
notify_hotplug_insert(struct leaba_device_t* leaba_data)
{
    // No point to notify through sysfs, because we are called from 'probe' and the sysfs file has just been created.
    // Hence, there is no listener on this file yet.

    udrv_hp_probe(leaba_data->pdev, leaba_data->id);
}

static void
notify_hotplug_remove(struct leaba_device_t* leaba_data)
{
    leaba_data->pci_event_value = LEABA_PCI_EVENT_HOTPLUG_REMOVE;
    device_sysfs_notify(leaba_data, &dev_attr_leaba_pci_event);

    udrv_hp_remove(leaba_data->pdev, leaba_data->id);
}

static void
notify_aer(struct pci_dev* pdev, leaba_pci_event_t event)
{
    struct device* dev = &pdev->dev;
    struct leaba_device_t* leaba_data;

    if (PCI_FUNC(pdev->devfn) != 0) {
        dev_info(dev, "%s: ignore non-zero PCI function\n", __func__);
        return;
    }

    leaba_data = pci_get_drvdata(pdev);
    dev_info(&pdev->dev, "notify_aer: event=%d (%s)\n", (int)event, leaba_pci_event_str(event));

    leaba_data->pci_event_value = event;
    device_sysfs_notify(leaba_data, &dev_attr_leaba_pci_event);
}

static irqreturn_t
leaba_pci_msi_handler(int irq, void* irq_data)
{
    struct leaba_device_t* ldev = irq_data;

    // MSI/MSI-X interrupt is not shared, it can only be us, no need to read interrupt register
    atomic64_inc(&ldev->interrupt_count);
    uio_event_notify(&ldev->uinfo);

    return IRQ_HANDLED;
}

static irqreturn_t
leaba_pci_irq_handler(int irq, void* irq_data)
{
    struct leaba_device_t* ldev = irq_data;
    uint32_t device_has_an_interrupt;
    uint32_t msi_addr;

    // Read interrupt register
    if (is_asic4(ldev->pdev)) {
        msi_addr = ASIC4_LLD_REGISTER_SBIF_MSI_MASTER_INTERRUPT_REG;
    } else if (is_asic5(ldev->pdev)) {
        msi_addr = ASIC5_LLD_REGISTER_SBIF_MSI_MASTER_INTERRUPT_REG;
    } else if (is_gibraltar(ldev->pdev)) {
        msi_addr = GIBRALTAR_LLD_REGISTER_SBIF_MSI_MASTER_INTERRUPT_REG;
    } else if (is_asic3(ldev->pdev)) {
        msi_addr = ASIC3_LLD_REGISTER_SBIF_MSI_MASTER_INTERRUPT_REG;
    } else {
        msi_addr = PACIFIC_LLD_REGISTER_SBIF_MSI_MASTER_INTERRUPT_REG;
    }

    device_has_an_interrupt = leaba_read_sbif_register(ldev, msi_addr);

    if (!device_has_an_interrupt) {
        return IRQ_NONE; /* Interrupt was not from this device */
    }

    return leaba_pci_msi_handler(irq, irq_data);
    ;
}

static void
leaba_device_put(struct leaba_device_t* ldev)
{
    if (ldev->open_count > 0 || ldev->pdev) {
        leaba_printk("uio%d: %s: open_count=%ld, pci_dev is %s\n",
                     ldev->devno,
                     __func__,
                     ldev->open_count,
                     ldev->pdev ? "present" : "removed");
    } else {
        leaba_printk("uio%d: %s: free\n", ldev->devno, __func__);
        ldev->uinfo.priv = NULL;
        kfree(ldev);
    }
}

static int
leaba_uio_open(struct uio_info* uinfo, struct inode* inode)
{
    struct leaba_device_t* ldev = (struct leaba_device_t*)uinfo->priv;

    // Check corner case - userspace already holds an open 'fd', then pci_dev is removed, then userspace calls open().
    if (!ldev->pdev) {
        leaba_printk("uio%d: open: attempt to open a file descriptor after pci_remove\n", ldev->devno);
        return -ENODEV;
    }
    if (ldev->open_count >= ldev->max_open_fd) {
        dev_err(&ldev->pdev->dev, "open: error, open_count=%ld has reached the max limit\n", ldev->max_open_fd);
        return -EBUSY;
    }
    dev_info(&ldev->pdev->dev, "open: open_count=%ld, max=%ld\n", ldev->open_count, ldev->max_open_fd);
    ldev->open_count++;

    return 0;
}

static int
leaba_uio_release(struct uio_info* uinfo, struct inode* inode)
{
    struct leaba_device_t* ldev = (struct leaba_device_t*)uinfo->priv;

    leaba_printk("uio%d: release: open_count=%ld\n", ldev->devno, ldev->open_count);

    ldev->open_count--;
    leaba_device_put(ldev);

    return 0;
}

static const struct vm_operations_struct leaba_uio_physical_vm_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
    .access = generic_access_phys,
#endif
};

static int
leaba_uio_mmap_physical(struct uio_mem* mem, struct vm_area_struct* vma)
{
    if (mem->addr & ~PAGE_MASK) {
        return -ENODEV;
    }
    if (vma->vm_end - vma->vm_start > mem->size) {
        return -EINVAL;
    }

    vma->vm_ops = &leaba_uio_physical_vm_ops;
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    return remap_pfn_range(vma, vma->vm_start, mem->addr >> PAGE_SHIFT, vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
typedef int vm_fault_t;
#endif

static vm_fault_t
_leaba_uio_vma_fault(struct vm_area_struct* vma, struct vm_fault* vmf)
{
    struct leaba_device_t* ldev = vma->vm_private_data;
    struct page* page;
    unsigned long offset;
    void* addr;
    int mi = (int)vma->vm_pgoff;

    if (!ldev->pdev) {
        leaba_printk("uio%d: vma_fault: mi=%d, a mapped memory is accessed after pci_remove\n", ldev->devno, mi);
        return VM_FAULT_SIGBUS;
    }
    if (mi >= MAX_UIO_MAPS || ldev->uinfo.mem[mi].size == 0) {
        return VM_FAULT_SIGBUS;
    }

    // We need to subtract mi because userspace uses offset = N*PAGE_SIZE to use mem[N].
    offset = (vmf->pgoff - mi) << PAGE_SHIFT;
    addr = (void*)(unsigned long)ldev->uinfo.mem[mi].addr + offset;

    if (ldev->uinfo.mem[mi].memtype == UIO_MEM_LOGICAL) {
        page = virt_to_page(addr);
    } else {
        page = vmalloc_to_page(addr);
    }
    get_page(page);
    vmf->page = page;

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static vm_fault_t
leaba_uio_vma_fault(struct vm_fault* vmf)
{
    return _leaba_uio_vma_fault(vmf->vma, vmf);
}
#else
static vm_fault_t
leaba_uio_vma_fault(struct vm_area_struct* vma, struct vm_fault* vmf)
{
    return _leaba_uio_vma_fault(vma, vmf);
}
#endif

static const struct vm_operations_struct leaba_uio_logical_vm_ops = {
    .fault = leaba_uio_vma_fault,
};

static int
leaba_uio_mmap_logical(struct vm_area_struct* vma)
{
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_ops = &leaba_uio_logical_vm_ops;

    return 0;
}

static int
leaba_uio_mmap(struct uio_info* uinfo, struct vm_area_struct* vma)
{
    // leaba_uio_mmap() callback is called after UIO has validated vma->vm_pgoff.
    struct uio_mem* mem = &uinfo->mem[vma->vm_pgoff];

    vma->vm_private_data = uinfo->priv; // leaba_device_t

    switch (mem->memtype) {
    case UIO_MEM_PHYS:
        return leaba_uio_mmap_physical(mem, vma);
    case UIO_MEM_LOGICAL:
    case UIO_MEM_VIRTUAL:
        return leaba_uio_mmap_logical(vma);
    default:
        return -EINVAL;
    }
}

static int
leaba_init_pci(struct leaba_device_t* leaba_data, int* enabled_bar)
{
    int err;
    struct pci_dev* pdev = leaba_data->pdev;
    struct device* dev = &pdev->dev;
    int disabled_bar;

    if (m_use_64bit_bar) {
        *enabled_bar = LEABA_BAR_64BIT;
        disabled_bar = LEABA_BAR_32BIT;
    } else {
        *enabled_bar = LEABA_BAR_32BIT;
        disabled_bar = LEABA_BAR_64BIT;
    }

    pdev->resource[disabled_bar].start = 0;
    pdev->resource[disabled_bar].end = 0;
    pdev->resource[disabled_bar].flags = IORESOURCE_DISABLED;

    /* Enable PCI */
    if ((err = pci_enable_device(pdev))) {
        dev_info(dev, "pci_enable_device (attempt 1): error %d. Fixing up resources ...\n", err);
        if ((err = pci_assign_resource(pdev, *enabled_bar))) {
            dev_err(dev, "pci_assign_resource, bar=%d, error %d\n", *enabled_bar, err);
            return err;
        }

        if ((err = pci_enable_device(pdev))) {
            dev_err(dev, "pci_enable_device (attempt 2): error %d. Giving up.\n", err);
            return err;
        }
    }

    if ((err = pci_request_regions(pdev, LEABA_MODULE_DEV_NAME)) < 0) {
        dev_err(dev, "pci_request_regions error %d\n", err);
        goto out_pci_disable_device;
    }

    // ASIC is capable of 64-bit DMA. Try to set mask accordingly, with a fallback to 32-bit.
    if ((err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64)) == 0)) {
        dev_info(dev, "Coherent 64b DMA available\n");
    } else if ((err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32))) == 0) {
        dev_info(dev, "Coherent 32b DMA available\n");
    } else {
        dev_err(dev, "No suitable DMA available\n");
        goto out_pci_release_regions;
    }

    // AER (Advanced Error Reporting) hooks
    pci_enable_pcie_error_reporting(pdev);

    // Enable bus master DMA
    pci_set_master(pdev);

    if ((err = pci_enable_msi(pdev))) {
        // An error can be either HW or OS-level, e.g. CONFIG_PCI_MSI=n, or kernel booted with pci=nomsi
        dev_err(dev, "Failed enabling msi, error %d. Ignore and fallback to legacy IRQ\n", err);
    }

    pci_save_state(pdev);

    leaba_data->bar_va = pci_ioremap_bar(pdev, *enabled_bar);
    if (!leaba_data->bar_va) {
        dev_err(dev, "Failed mapping PCI memory, bar=%d\n", *enabled_bar);
        err = -EIO;
        goto out_pci_disable_msi;
    }

    leaba_data->dma_va = dma_alloc_coherent(dev, LEABA_DMA_COH_SZ, &leaba_data->dma_pa, GFP_KERNEL);
    if (!leaba_data->dma_va) {
        dev_err(dev, "Could not allocate external coherent memory\n");
        err = -EIO;
        goto out_pci_unmap;
    }

    return 0;

out_pci_unmap:
    iounmap(leaba_data->bar_va);
out_pci_disable_msi:
    if (pdev->msi_enabled) {
        pci_disable_msi(pdev);
    }
out_pci_release_regions:
    pci_release_regions(pdev);
out_pci_disable_device:
    pci_disable_device(pdev);

    return err;
}

static void
leaba_uninit_pci(struct leaba_device_t* ldev)
{
    dma_free_coherent(&ldev->pdev->dev, LEABA_DMA_COH_SZ, ldev->dma_va, ldev->dma_pa);
    ldev->dma_va = NULL;
    ldev->dma_pa = 0;

    iounmap(ldev->bar_va);
    ldev->bar_va = NULL;

    if (ldev->pdev->msi_enabled) {
        pci_disable_msi(ldev->pdev);
    }
    pci_release_regions(ldev->pdev);
    if (atomic_read(&ldev->pdev->enable_cnt) > 0) {
        pci_disable_device(ldev->pdev);
    }
    ldev->pdev = NULL;
}

static int
leaba_add_sysfs(struct device* dev)
{
    int err, i;

    for (i = 0; leaba_device_attrs[i]; i++) {
        err = device_create_file(dev, leaba_device_attrs[i]);
        if (err) {
            goto error;
        }
    }

    return 0;

error:
    while (--i >= 0) {
        device_remove_file(dev, leaba_device_attrs[i]);
    }

    return err;
}

static void
leaba_remove_sysfs(struct device* dev)
{
    int i;

    for (i = 0; leaba_device_attrs[i]; i++) {
        device_remove_file(dev, leaba_device_attrs[i]);
    }
}

static void
leaba_pci_dump_error_capability(struct pci_dev* pdev)
{
    int pos;
    u32 cor_status, cor_mask, uncor_status, uncor_mask;

    pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
    if (!pos) {
        return;
    }

    pci_read_config_dword(pdev, pos + PCI_ERR_COR_STATUS, &cor_status);
    pci_read_config_dword(pdev, pos + PCI_ERR_COR_MASK, &cor_mask);
    pci_read_config_dword(pdev, pos + PCI_ERR_UNCOR_STATUS, &uncor_status);
    pci_read_config_dword(pdev, pos + PCI_ERR_UNCOR_STATUS, &uncor_mask);

    dev_info(
        &pdev->dev, "cor status=0x%x, mask=0x%x; uncor status=0x%x, mask=0x%x\n", cor_status, cor_mask, uncor_status, uncor_mask);
}

static int
leaba_pci_probe(struct pci_dev* pdev, const struct pci_device_id* pdev_id)
{
    struct device* dev = &pdev->dev;
    struct leaba_device_t* leaba_data;
    int enabled_bar;
    int err;

    if (PCI_FUNC(pdev->devfn) != 0) {
        dev_info(dev, "%s: ignore non-zero PCI function\n", __func__);
        return 0;
    }

    dev_info(dev, "%s: start\n", __func__);

    // Check if PCI device node remembers an error state (AER) from previous probe/remove session.
    if (pdev->error_state != pci_channel_io_normal) {
        dev_err(dev, "%s: channel error_state=%d (%s)\n", __func__, pdev->error_state, pci_channel_state_str(pdev->error_state));
        return -EINVAL;
    }

    leaba_pci_dump_error_capability(pdev);

    /* device private context */
    leaba_data = kzalloc(sizeof(struct leaba_device_t), GFP_KERNEL);
    if (!leaba_data) {
        dev_err(dev, "failed to allocate memory.\n");
        return -ENOMEM;
    }

    pci_set_drvdata(pdev, leaba_data);
    leaba_data->pdev = pdev;
    leaba_data->id = pdev_id;
    leaba_data->max_open_fd = 1;
    atomic64_set(&leaba_data->interrupt_count, 0);

    snprintf(leaba_data->name,
             sizeof(leaba_data->name),
             "%s_%x:%x.%x_%hx:%hx", /* leaba_module_device_B:D.F_VENDOR:DEVICE */
             LEABA_MODULE_DEV_NAME,
             pdev->bus->number,
             PCI_SLOT(pdev->devfn),
             PCI_FUNC(pdev->devfn),
             pdev->vendor,
             pdev->device);
    dev_info(dev, "name %s\n", leaba_data->name);

    err = leaba_init_pci(leaba_data, &enabled_bar);
    if (err) {
        goto out_free_leaba_data;
    }

    err = leaba_add_sysfs(dev);
    if (err) {
        goto out_uninit_pci;
    }

    /* Initialize UIO */
    leaba_data->uinfo.mem[0].addr = pci_resource_start(pdev, enabled_bar);
    leaba_data->uinfo.mem[0].internal_addr = leaba_data->bar_va;
    leaba_data->uinfo.mem[0].size = pci_resource_len(pdev, enabled_bar);
    leaba_data->uinfo.mem[0].memtype = UIO_MEM_PHYS;
    leaba_data->uinfo.mem[0].name = "Device MMIO";

    leaba_data->uinfo.mem[1].addr = (phys_addr_t)leaba_data->dma_va;
    leaba_data->uinfo.mem[1].size = LEABA_DMA_COH_SZ;
    leaba_data->uinfo.mem[1].memtype = UIO_MEM_LOGICAL;
    leaba_data->uinfo.mem[1].name = "Coherent DMA buffer";

    leaba_data->uinfo.name = leaba_data->name;
    leaba_data->uinfo.version = LEABA_MODULE_VERSION;
    leaba_data->uinfo.irq = UIO_IRQ_CUSTOM;
    leaba_data->uinfo.open = leaba_uio_open;
    leaba_data->uinfo.release = leaba_uio_release;
    leaba_data->uinfo.mmap = (m_use_uio_mmap ? NULL : leaba_uio_mmap);
    leaba_data->uinfo.priv = leaba_data;

    if ((err = uio_register_device(&pdev->dev, &leaba_data->uinfo))) {
        dev_err(dev, "uio_register_device error %d\n", err);
        goto out_remove_sysfs;
    }

    leaba_data->devno = leaba_data->uinfo.uio_dev->minor;

    if (pdev->msi_enabled) {
        err = request_irq(pdev->irq, leaba_pci_msi_handler, 0 /* flags */, leaba_data->name, leaba_data);
    } else {
        err = request_irq(pdev->irq, leaba_pci_irq_handler, IRQF_SHARED /* flags */, leaba_data->name, leaba_data);
    }
    if (err) {
        dev_err(dev, "request_irq error %d\n", err);
        goto out_uio_unregister;
    }

    if ((err = leaba_nic_initialize(pdev)) < 0) {
        dev_err(dev, "leaba_nic_initialize error %d\n", err);
        goto out_free_irq;
    }

    notify_hotplug_insert(leaba_data);

    dev_info(dev, "MSI enabled %d, pdev->irq %d\n", pdev->msi_enabled, pdev->irq);
    dev_info(dev,
             "BAR %d: start=0x%llx, internal_addr=%p, len=0x%llx, flags=0x%lx\n",
             enabled_bar,
             leaba_data->uinfo.mem[0].addr,
             leaba_data->uinfo.mem[0].internal_addr,
             leaba_data->uinfo.mem[0].size,
             pci_resource_flags(pdev, enabled_bar));
    dev_info(dev,
             "DMA Memory: dma_pa=0x%llx, dma_va=%p, len=0x%llx\n",
             leaba_data->dma_pa,
             leaba_data->dma_va,
             leaba_data->uinfo.mem[1].size);
    dev_info(dev, "%s: end\n", __func__);

    return 0;

out_free_irq:
    free_irq(pdev->irq, leaba_data);
out_uio_unregister:
    uio_unregister_device(&leaba_data->uinfo);
out_remove_sysfs:
    leaba_remove_sysfs(dev);
out_uninit_pci:
    leaba_uninit_pci(leaba_data);
out_free_leaba_data:
    pci_set_drvdata(pdev, NULL);
    kfree(leaba_data);

    return err;
}

static void
leaba_pci_remove(struct pci_dev* pdev)
{
    struct device* dev = &pdev->dev;
    struct leaba_device_t* leaba_data;

    if (PCI_FUNC(pdev->devfn) != 0) {
        dev_info(dev, "%s: ignore non-zero PCI function\n", __func__);
        return;
    }

    leaba_data = pci_get_drvdata(pdev);
    dev_info(dev, "%s: open_count=%ld\n", __func__, leaba_data->open_count);

    notify_hotplug_remove(leaba_data);

    dev_info(dev, "%s: nic tear down, pdev=%p, dev=%p\n", __func__, pdev, dev);
    leaba_nic_teardown(pdev);

    dev_info(dev, "%s: free_irq\n", __func__);
    free_irq(pdev->irq, leaba_data);

    dev_info(dev, "%s: uio_unregister_device\n", __func__);
    uio_unregister_device(&leaba_data->uinfo);

    dev_info(dev, "%s: remove sysfs attributes\n", __func__);
    leaba_remove_sysfs(dev);

    dev_info(dev, "%s: uninit pci\n", __func__);
    leaba_uninit_pci(leaba_data);
    pci_set_drvdata(pdev, NULL);

    dev_info(dev, "%s: release context\n", __func__);
    leaba_device_put(leaba_data);

    dev_info(dev, "%s: end\n", __func__);
}

static pci_ers_result_t
leaba_pci_error_detected(struct pci_dev* pdev, pci_channel_state_t state)
{
    dev_err(&pdev->dev, "error_detected: channel state=%d (%s)\n", state, pci_channel_state_str(state));

    // Stop network interfaces
    leaba_nic_stop(pdev);

    // Disable PCIe device in response to any AER event.
    // The usermode process may want to reset (or otherwise cleanup) the ASIC.
    if (atomic_read(&pdev->enable_cnt) > 0) {
        pci_disable_device(pdev);
    }

    switch (state) {
    case pci_channel_io_perm_failure: // link is broken, non-recoverable
    case pci_channel_io_frozen:       // link is broken, recoverable
        notify_aer(pdev, LEABA_PCI_EVENT_AER_NON_RECOVERABLE);

        // non-recoverable, tear down nic to avoid cpu hog between this action and kernel remove command
        leaba_nic_teardown(pdev);

        return PCI_ERS_RESULT_DISCONNECT; // Request a disconnect, next state is "remove".

    case pci_channel_io_normal:
        // uncorrectable/nonfatal error, link state is "normal" but traffic was corrupted
        notify_aer(pdev, LEABA_PCI_EVENT_AER_RECOVERABLE);
        return PCI_ERS_RESULT_CAN_RECOVER; // Request no action, next state is "resume".
    }

    // unreachable
    dev_err(&pdev->dev, "error_detected: unexpected channel state=%d\n", state);

    return PCI_ERS_RESULT_NONE;
}

static pci_ers_result_t
leaba_pci_mmio_enabled(struct pci_dev* pdev)
{
    dev_info(&pdev->dev, "mmio_enabled\n");

    // Next state is "resume".
    return PCI_ERS_RESULT_RECOVERED;
}

static pci_ers_result_t
leaba_pci_slot_reset(struct pci_dev* pdev)
{
    dev_info(&pdev->dev, "slot_reset\n");

    return PCI_ERS_RESULT_DISCONNECT; // Request a disconnect, next state is "pci_remove".
}

static void
leaba_pci_resume(struct pci_dev* pdev)
{
    dev_info(&pdev->dev, "resume, enable_cnt=%d, msi_enabled=%d\n", atomic_read(&pdev->enable_cnt), pdev->msi_enabled);

    notify_aer(pdev, LEABA_PCI_EVENT_AER_RECOVERED);
}

static const struct pci_error_handlers leaba_pci_err_handler = {
    // PCI bus error detected on this device
    .error_detected = leaba_pci_error_detected,

    // MMIO enabled.
    .mmio_enabled = leaba_pci_mmio_enabled,

    // PCI slot has been reset. Restart the PCI device from scratch, as if from a cold-boot.
    .slot_reset = leaba_pci_slot_reset,

    // May resume normal operations, PCIe traffic can start flowing again.
    .resume = leaba_pci_resume,
};

MODULE_DEVICE_TABLE(pci, leaba_pci_ids);

static struct pci_driver leaba_pci_info = {
    .name = LEABA_MODULE_DEV_NAME,
    .id_table = leaba_pci_ids,
    .probe = leaba_pci_probe,
    .remove = leaba_pci_remove,
    .err_handler = &leaba_pci_err_handler,
};

/*---------------------------------------------------------------------------------------*/
/* Module init */
static int __init
leaba_module_init(void)
{
    int err;

    // On older kernels, UIO mmap incorrectly handles the case when uio_unregister_device() is invoked
    // while userspace still has an open file descriptor and active mmapped regions.
    //
    // Specifically, in older kernels, UIO vma_fault callback would crash if userspace accesses
    // a mapped UIO_MEM_LOGICAL region after pci_remove.
    if (m_use_uio_mmap == -1) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
        m_use_uio_mmap = 1;
#else
        m_use_uio_mmap = 0;
#endif
    }

    leaba_printk("init: version " LEABA_MODULE_VERSION ", use_64bit_bar=%d, use_uio_mmap=%d\n", m_use_64bit_bar, m_use_uio_mmap);

    /* PCI */
    err = pci_register_driver(&leaba_pci_info);
    if (err) {
        leaba_printk("init: pci_register_driver() returned %d\n", err);
    }

    return err;
}

/* Module exit */
static void __exit
leaba_module_exit(void)
{
    leaba_printk("exit\n");

    /* PCI */
    pci_unregister_driver(&leaba_pci_info);
}

/* module settings */
module_init(leaba_module_init);
module_exit(leaba_module_exit);

/* module macros */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cisco Systems");
MODULE_DESCRIPTION("Leaba PCIe device driver");
MODULE_VERSION(LEABA_MODULE_VERSION);
