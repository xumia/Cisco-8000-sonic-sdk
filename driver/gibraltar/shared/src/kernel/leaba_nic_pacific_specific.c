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

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

/*****************************************************************************/
/**********************    PACIFIC specific    *******************************/
/*****************************************************************************/

/* allocate DMA buffers for the given interface */
static int
pacific_interface_buffers_alloc(struct pci_dev* pdev, struct leaba_nic_t* nic)
{
    int ret = 0;

    ret |= single_interface_buffer_alloc(pdev, nic, BUFFER_TYPE_DESC, &nic->buffer_virt_ext_desc, &nic->buffer_phys_ext_desc);
    ret |= single_interface_buffer_alloc(pdev, nic, BUFFER_TYPE_DESC, &nic->buffer_virt_inj_desc, &nic->buffer_phys_inj_desc);
    ret |= single_interface_buffer_alloc(pdev, nic, BUFFER_TYPE_DATA, &nic->buffer_virt_ext_data, &nic->buffer_phys_ext_data);
    ret |= single_interface_buffer_alloc(pdev, nic, BUFFER_TYPE_DATA, &nic->buffer_virt_inj_data, &nic->buffer_phys_inj_data);

    if (ret != 0) {
        interface_buffers_free(pdev, nic);
    }

    return ret;
}

#define PACIFIC_EXT_FIELD_MASK_GO (0x1 << 0)
#define PACIFIC_EXT_FIELD_MASK_FLOW_CTRL (0x1 << 1)
#define PACIFIC_EXT_FIELD_MASK_FLOW_CTRL_PD_THR (0x1f << 2)
#define PACIFIC_EXT_FIELD_MASK_FLOW_CTRL_DATA_THR (0x3ff << 7)
#define PACIFIC_EXT_FIELD_MASK_REMOTE (0x1 << 17)
#define PACIFIC_EXT_FIELD_MASK_WB (0x1 << 18)

#define PACIFIC_INJECT_FIELD_MASK_GO (0x1 << 0)
#define PACIFIC_INJECT_FIELD_MASK_REMOTE (0x1 << 1)
#define PACIFIC_INJECT_FIELD_MASK_WB (0x1 << 2)

/* leaba specific initialization */
static int
pacific_interface_init(struct leaba_nic_t* nic)
{
    int ret = 0;
    uint32_t reg;
    uint32_t regval;
    int index = nic->index;
    struct pci_dev* pdev = nic->pdev;
    const uint32_t ext_config_reg_mask_and = PACIFIC_EXT_FIELD_MASK_FLOW_CTRL_PD_THR | PACIFIC_EXT_FIELD_MASK_FLOW_CTRL_DATA_THR;
    const uint32_t ext_config_reg_or = (m_remote ? PACIFIC_EXT_FIELD_MASK_REMOTE : 0)
                                       | (m_use_write_back ? PACIFIC_EXT_FIELD_MASK_WB : 0)
                                       | (m_flow_control ? PACIFIC_EXT_FIELD_MASK_FLOW_CTRL : 0);
    const uint32_t inj_config_reg_val
        = (m_remote ? PACIFIC_INJECT_FIELD_MASK_REMOTE : 0) | (m_use_write_back ? PACIFIC_INJECT_FIELD_MASK_WB : 0);

    spin_lock_init(&nic->stats_spinlock);
    spin_lock_init(&nic->inject_buffer_pointers_spinlock);
    INIT_WORK(&nic->deferred_work, (void (*)(struct work_struct*))do_check_device_pointers);

    /* allocate dma buffers */

    ret = pacific_interface_buffers_alloc(pdev, nic);
    if (ret != 0) {
        goto err;
    }

    /* punt descriptor buffer */

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_BASE_LSB_REG_0;
    regval = (uint32_t)(nic->buffer_phys_ext_desc);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_BASE_MSB_REG_0;
    regval = (uint32_t)(nic->buffer_phys_ext_desc >> 32);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_LENGTH_REG_0;
    regval = BUFFER_SIZE_BYTES(BUFFER_TYPE_DESC);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_PTR_REG_0;
    regval = 0;
    write_sbif_dma_register(pdev, reg, index, regval);

    /* punt data buffer */

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_DATA_BASE_LSB_REG_0;
    regval = (uint32_t)(nic->buffer_phys_ext_data);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_DATA_BASE_MSB_REG_0;
    regval = (uint32_t)(nic->buffer_phys_ext_data >> 32);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_DATA_LENGTH_REG_0;
    regval = BUFFER_SIZE_BYTES(BUFFER_TYPE_DATA);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_RD_DATA_PTR_REG_0;
    regval = 0;
    write_sbif_dma_register(pdev, reg, index, regval);

    /* punt config */

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_CFG_REG_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval = (regval & ext_config_reg_mask_and) | ext_config_reg_or;
    write_sbif_dma_register(pdev, reg, index, regval);

    /* inject descriptor buffer */

    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_PD_BASE_LSB_REG_0;
    regval = (uint32_t)(nic->buffer_phys_inj_desc);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_PD_BASE_MSB_REG_0;
    regval = (uint32_t)(nic->buffer_phys_inj_desc >> 32);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_PD_LENGTH_REG_0;
    regval = BUFFER_SIZE_BYTES(BUFFER_TYPE_DESC);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_WR_PD_PTR_REG_0;
    regval = 0;
    write_sbif_dma_register(pdev, reg, index, regval);

    /* inject config */

    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_CFG_REG_0;
    regval = inj_config_reg_val;
    write_sbif_dma_register(pdev, reg, index, regval);

    return ret;

err:
    interface_teardown(pdev, nic);
    return ret;
}

/* activate interface */
static void
pacific_activate_interface(struct leaba_nic_t* nic)
{
    uint32_t reg;
    uint32_t regval;
    int index = nic->index;
    struct pci_dev* pdev = nic->pdev;
    ktime_t kt = ktime_set(0, m_polling_interval_usec * NSEC_PER_USEC); /* ktime is given in nsec */

    if (nic->is_active) {
        return;
    }

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_CFG_REG_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval |= PACIFIC_EXT_FIELD_MASK_GO;
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_CFG_REG_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval |= PACIFIC_INJECT_FIELD_MASK_GO;
    write_sbif_dma_register(pdev, reg, index, regval);

    if (g_leaba_module_debug_level > 6) {
        dev_info(&pdev->dev, "%s: %s: netif_wake\n", nic->name, __func__);
    }

    netif_wake_queue(nic->ndev);
    hrtimer_start(&nic->polling_timer, kt, HRTIMER_MODE_REL); /* don't care about the return value */
    nic->is_active = 1;
    dev_info(&pdev->dev, "%s: activated\n", nic->name);
}

/* de-activate interface */
static void
pacific_deactivate_interface(struct leaba_nic_t* nic)
{
    uint32_t reg;
    uint32_t regval;
    int index = nic->index;
    struct pci_dev* pdev = nic->pdev;

    if (!nic->is_active) {
        return;
    }

    if (g_leaba_module_debug_level > 6) {
        dev_info(&pdev->dev, "%s: %s: netif_stop\n", nic->name, __func__);
    }

    netif_stop_queue(nic->ndev);

    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_CFG_REG_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval &= ~PACIFIC_EXT_FIELD_MASK_GO;
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_CFG_REG_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval &= ~PACIFIC_INJECT_FIELD_MASK_GO;
    write_sbif_dma_register(pdev, reg, index, regval);

    nic->is_active = 0;
    dev_info(&pdev->dev, "%s: de-activated\n", nic->name);
}

/* prepare skb with a packet coming from the device */
static struct sk_buff*
pacific_get_ext_skb(struct leaba_nic_t* nic, union leaba_nic_packet_descriptor_t* desc)
{
    /* get the address of the punted packet */
    uint64_t offset = desc->pacific.phys_addr - nic->buffer_phys_ext_data;
    uint8_t* packet = nic->buffer_virt_ext_data + offset;
    uint16_t desc_size = desc->pacific.size;
    uint16_t size = MIN(desc_size, DATA_BUFFER_SIZE_BYTES - offset);
    int is_wrap_around = (size != desc_size);
    unsigned long flags = 0;
    struct sk_buff* skb = NULL;
    int ret;
    uint8_t* skb_data = NULL;
    unsigned actual_size;

    if (offset >= DATA_BUFFER_SIZE_BYTES) {
        dev_err_ratelimited(&nic->pdev->dev,
                            "%s: %s: invalid data address. desc=%p size_err=%llx phys_addr=%llx buffer=%llx offset=%llx "
                            "DATA_BUFFER_SIZE_BYTES=%x\n",
                            nic->name,
                            __func__,
                            desc,
                            desc->pacific.size_err,
                            desc->pacific.phys_addr,
                            nic->buffer_phys_ext_data,
                            offset,
                            (uint32_t)DATA_BUFFER_SIZE_BYTES);
        spin_lock_irqsave(&nic->stats_spinlock, flags);
        nic->stats.rx_errors++;
        spin_unlock_irqrestore(&nic->stats_spinlock, flags);

        return NULL;
    }

    if (g_leaba_module_debug_level > 0) {
        dev_info(&nic->pdev->dev,
                 "%s: %s: desc.phys_addr=%llx desc.size_err=%llx\n",
                 nic->name,
                 __func__,
                 desc->pacific.phys_addr,
                 desc->pacific.size_err);
        dev_info(&nic->pdev->dev, "%s: %s: is_wrap_around=%d\n", nic->name, __func__, is_wrap_around);
        print_buffer(__func__, "orig packet", nic, packet, desc_size, 0);
    }

    /* allocate an skb */
    skb = dev_alloc_skb(desc_size + BYTES_IN_DQWORD);
    if (skb == NULL) {
        dev_err_ratelimited(&nic->pdev->dev, "%s: %s: dev_alloc_skb failed\n", nic->name, __func__);
        spin_lock_irqsave(&nic->stats_spinlock, flags);
        nic->stats.rx_dropped++;
        spin_unlock_irqrestore(&nic->stats_spinlock, flags);

        return NULL;
    }

    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev, "%s: %s:%p\n", nic->name, __func__, skb);
    }

    /* reserve data for the packet */
    skb_data = skb_put(skb, round_up(desc_size, BYTES_IN_DQWORD));

    /* copy the packet to the skb */
    if (is_wrap_around) {
        ret = copy_packet_d2h_with_wrap_around(
            skb_data, packet, size, nic->buffer_virt_ext_data, desc_size - size, m_add_wrapper_header);
    } else {
        ret = copy_packet_d2h(skb_data, packet, size, m_add_wrapper_header);
    }

    if (ret < 0) {
        static DEFINE_RATELIMIT_STATE(_rs, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
        uint64_t rx_errors, rx_packets;

        dev_kfree_skb(skb);
        spin_lock_irqsave(&nic->stats_spinlock, flags);
        nic->stats.rx_errors++;
        rx_errors = nic->stats.rx_errors;
        rx_packets = nic->stats.rx_packets;
        spin_unlock_irqrestore(&nic->stats_spinlock, flags);

        if (__ratelimit(&_rs)) {
            dev_err(&nic->pdev->dev,
                    "%s: %s: copy_packet_d2h failed %d. desc=%p phys_addr=%llx offset=%llu size=%u desc_size=%u rx_packets=%llu "
                    "rx_errors=%llu\n",
                    nic->name,
                    __func__,
                    ret,
                    desc,
                    desc->pacific.phys_addr,
                    offset,
                    size,
                    desc_size,
                    rx_packets,
                    rx_errors);
            print_buffer(__func__, "failing packet", nic, packet, desc_size, 1);
        }

        return NULL;
    }

    actual_size = ret;

    if (g_leaba_module_debug_level > 0) {
        print_buffer(__func__, "actual packet", nic, skb_data, actual_size, 0);
    }

    /* initialize the skb */
    skb->dev = nic->ndev;
    skb->len = actual_size;
    skb->protocol = eth_type_trans(skb, nic->ndev);
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    return skb;
}

/* show interface info, attribute buffer is PAGE_SIZE bytes */
static ssize_t
pacific_show_if(struct leaba_nic_t* nic, struct device_attribute* attr, char* buf, unsigned n)
{
    uint8_t* ap = NULL;
    char* p = buf;

    sprintf(p, "name=%s\n", nic->name);
    p += strlen(p);

    sprintf(p, "%sActive\n", (nic->is_active) ? "" : "Not ");
    p += strlen(p);

    sprintf(p, "Netif queue %s\n", netif_queue_stopped(nic->ndev) ? "Stopped" : "Started");
    p += strlen(p);

    ap = (uint8_t*)&nic->mac_addr;
    sprintf(p, "mac_addr=%02x:%02x:%02x:%02x:%02x:%02x\n", *(ap + 5), *(ap + 4), *(ap + 3), *(ap + 2), *(ap + 1), *(ap + 0));
    p += strlen(p);

    p += strlen(p);

    sprintf(p,
            "write_ptr EXT_DATA=N/A\tEXT_DESC=%x\tINJ_DATA=%x\tINJ_DESC=%x\n",
            /* not used and hence not shown: nic->write_ptr_ext_data,*/
            nic->write_ptr_ext_desc,
            nic->write_ptr_inj_data,
            nic->write_ptr_inj_desc);
    p += strlen(p);

    sprintf(p,
            "read_ptr  EXT_DATA=%x\tEXT_DESC=%x\tINJ_DATA=%x\tINJ_DESC=%x\n",
            nic->read_ptr_ext_data,
            nic->read_ptr_ext_desc,
            nic->read_ptr_inj_data,
            nic->read_ptr_inj_desc);
    p += strlen(p);

#define LEABA_PRINT_REG(_r, _n)                                                                                                    \
    do {                                                                                                                           \
        uint32_t regval;                                                                                                           \
        regval = read_sbif_dma_register(nic->pdev, _r, _n);                                                                        \
        sprintf(p, "%s=%x\n", #_r, regval);                                                                                        \
        p += strlen(p);                                                                                                            \
    } while (0);

    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_CFG_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_DATA_BASE_LSB_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_DATA_BASE_MSB_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_DATA_LENGTH_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_BASE_LSB_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_BASE_MSB_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_LENGTH_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_RD_DATA_PTR_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_WR_DATA_PTR_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_PTR_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_WR_PD_PTR_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_CFG_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_PD_BASE_LSB_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_PD_BASE_MSB_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_PD_LENGTH_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_RD_PD_PTR_REG_0, n);
    LEABA_PRINT_REG(PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_WR_PD_PTR_REG_0, n);
#undef LEABA_PRINT_REG

    return strlen(buf);
}

/* check the write punt pointers that the device updates */
static void
pacific_check_ext_pointers(struct leaba_nic_t* nic)
{
    uint32_t reg;
    uint32_t regval;
    uint32_t dev_desc_wr_ptr = get_ext_desc_write_pointer(nic);
    uint32_t new_elements_nr = 0;
    struct leaba_nic_pacific_packet_descriptor_t* desc;
    unsigned long flags = 0;

    /* compare the device's pointer with cached pointer */
    if (dev_desc_wr_ptr == nic->write_ptr_ext_desc) {
        /* nothing changed, nothing to do. */
        return;
    }

    /* check for pci errors */
    if (check_and_handle_pci_errors(nic, dev_desc_wr_ptr)) {
        /* error detected */
        return;
    }

    /* pointer changed */

    do {
        uint32_t raw_dev_desc_rd_ptr = nic->read_ptr_ext_desc;
        uint32_t dev_desc_rd_ptr = raw_dev_desc_rd_ptr & ~DESC_BUFFER_WRAP_BIT;
        desc = (struct leaba_nic_pacific_packet_descriptor_t*)(nic->buffer_virt_ext_desc + dev_desc_rd_ptr);

        if (g_leaba_module_debug_level > 0) {
            print_descriptor(nic, __func__, (union leaba_nic_packet_descriptor_t*)desc);
        }

        /* the descriptor might be invalid in case the dma transaction to host memory is not finished when we read the device's
         * write ptr. if this is the case then it's sure to be the last packet */
        if ((desc->size_err == 0) || (desc->phys_addr == 0)) {
            break;
        }

        /* the hw updates the desc ptr AFTER it finished with the data ptr, so we're sure to have the data buffer ready */

        if (desc->err == 0) {
            /* send the packet to the kernel for processing */
            leaba_nic_rx(nic, (union leaba_nic_packet_descriptor_t*)desc, desc->size);
        } else {
            /* skip this packet */
            dev_err_ratelimited(&nic->pdev->dev, "%s: %s: error bit is set\n", nic->name, __func__);
            spin_lock_irqsave(&nic->stats_spinlock, flags);
            nic->stats.rx_errors++;
            spin_unlock_irqrestore(&nic->stats_spinlock, flags);
        }

        /* update the read pointers */
        do_buffer_ptr_inc(nic, &nic->read_ptr_ext_desc, BUFFER_TYPE_DESC, DESC_BUFFER_ELEMENT_SIZE_BYTES, 1 /*contig_wrap*/);
        do_buffer_ptr_inc(
            nic, &nic->read_ptr_ext_data, BUFFER_TYPE_DATA, ALIGN((uint32_t)(desc->size), BUFFER_PTR_ALIGNMENT), 1 /*contig_wrap*/);

        /* invalidate the desciptor */
        invalidate_descriptor((union leaba_nic_packet_descriptor_t*)desc);

        new_elements_nr++;

    } while (nic->read_ptr_ext_desc != dev_desc_wr_ptr);

    /* update the cached write pointer (EXT_DATA write pointer is not needed anywhere, so don't update) */
    do_buffer_ptr_inc(
        nic, &nic->write_ptr_ext_desc, BUFFER_TYPE_DESC, DESC_BUFFER_ELEMENT_SIZE_BYTES * new_elements_nr, 1 /*contig_wrap*/);

    mb(); /* make sure everything is in place before updating the device */

    /* update the data read pointer at the device */
    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_RD_DATA_PTR_REG_0;
    regval = nic->read_ptr_ext_data;
    write_sbif_dma_register(nic->pdev, reg, nic->index, regval);

    /* update the desc read pointer at the device */
    reg = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_PD_PTR_REG_0;
    regval = nic->read_ptr_ext_desc;
    write_sbif_dma_register(nic->pdev, reg, nic->index, regval);
}

/* check the inject read pointer that the device updates */
static void
pacific_check_inj_pointer(struct leaba_nic_t* nic)
{
    uint32_t regval;
    uint32_t dev_desc_ptr;
    uint32_t dev_desc_wrap;
    unsigned long flags = 0;
    uint32_t new_pos;

    // Get regval in lock, so delayed work + inject don't both try to update it.
    spin_lock_irqsave(&nic->inject_buffer_pointers_spinlock, flags);
    regval = get_inject_desc_read_pointer(nic);

    /* compare the device's pointer with cached pointer */
    if (regval == nic->read_ptr_inj_desc) {
        /* nothing changed, nothing to do. */
        spin_unlock_irqrestore(&nic->inject_buffer_pointers_spinlock, flags);
        return;
    }

    /* update cached desc pointer */
    nic->read_ptr_inj_desc = regval;

    dev_desc_ptr = (regval & ~DESC_BUFFER_WRAP_BIT);
    dev_desc_wrap = (regval & DESC_BUFFER_WRAP_BIT);
    /* update cached data pointer. assuming same number of elements in desc and data buffers */
    new_pos = dev_desc_ptr / DESC_BUFFER_ELEMENT_SIZE_BYTES;
    nic->read_ptr_inj_data = dev_desc_wrap | new_pos * INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES;

    spin_unlock_irqrestore(&nic->inject_buffer_pointers_spinlock, flags);

    /* check for pci errors */
    if (check_and_handle_pci_errors(nic, regval)) {
        /* error detected */
        return;
    }

    /* restart the interface if needed */
    if (netif_queue_stopped(nic->ndev)) {
        if (g_leaba_module_debug_level > 6) {
            dev_info(&nic->pdev->dev, "%s: %s: netif_wake\n", nic->name, __func__);
        }

        netif_wake_queue(nic->ndev);
    }
}

static int
pacific_nic_tx(struct sk_buff* skb, struct net_device* ndev)
{
    struct leaba_nic_t* nic = netdev_priv(ndev);
    int index = nic->index;
    uint8_t* data = NULL;
    struct leaba_nic_pacific_packet_descriptor_t* desc = NULL;
    unsigned long flags = 0;
    uint32_t reg;
    uint32_t regval;
    uint32_t raw_data_wr_ptr;
    uint32_t raw_desc_wr_ptr;
    uint32_t new_raw_desc_wr_ptr;
    uint32_t data_wr_ptr;
    uint32_t desc_wr_ptr;
    uint32_t raw_desc_rd_ptr;
    uint32_t available_space;
    int actual_size;

    spin_lock_irqsave(&nic->inject_buffer_pointers_spinlock, flags);

    /* get the pointers */
    raw_data_wr_ptr = nic->write_ptr_inj_data;
    raw_desc_wr_ptr = nic->write_ptr_inj_desc;
    raw_desc_rd_ptr = nic->read_ptr_inj_desc;

    /* receiving pakcets when buffer is full - shouldn't happen */
    if (get_desc_buffer_available_space(raw_desc_wr_ptr, raw_desc_rd_ptr, DESC_BUFFER_ELEMENT_SIZE_BYTES) == 0) {
        dev_err_ratelimited(&nic->pdev->dev, "%s: %s: received packets while buffer is full\n", nic->name, __func__);
    }

    /* increment pointers */
    do_buffer_ptr_inc(nic, &nic->write_ptr_inj_desc, BUFFER_TYPE_DESC, DESC_BUFFER_ELEMENT_SIZE_BYTES, 0 /*contig_wrap*/);
    new_raw_desc_wr_ptr = nic->write_ptr_inj_desc;
    do_buffer_ptr_inc(nic, &nic->write_ptr_inj_data, BUFFER_TYPE_DATA, INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES, 0 /*contig_wrap*/);

    /* same number of elements in desc and data buffers - checking available space of only one of them is enough.
     * the check is done AFTER the pointers are incremented. it should always be possible to inject the current packet.
     * the check is done for next packets */
    available_space
        = get_desc_buffer_available_space(nic->write_ptr_inj_desc, nic->read_ptr_inj_desc, DESC_BUFFER_ELEMENT_SIZE_BYTES);
    if (available_space == 0) {
        /* buffers are full - stop transmission */
        if (g_leaba_module_debug_level > 6) {
            dev_info(&nic->pdev->dev, "%s: %s: netif_stop\n", nic->name, __func__);
        }

        netif_stop_queue(ndev);
    }

    spin_unlock_irqrestore(&nic->inject_buffer_pointers_spinlock, flags);

    desc_wr_ptr = raw_desc_wr_ptr & ~DESC_BUFFER_WRAP_BIT;
    data_wr_ptr = raw_data_wr_ptr & ~DATA_BUFFER_WRAP_BIT;

    data = nic->buffer_virt_inj_data + data_wr_ptr;

    /* copy the packet to the dma buffer */
    actual_size = copy_packet_h2d(data, skb->data, skb->len, nic->index);
    if (actual_size < 0) {
        dev_err_ratelimited(&nic->pdev->dev, "%s: %s: copy_packet_h2d failed\n", nic->name, __func__);
        /* error */
        spin_lock_irqsave(&nic->stats_spinlock, flags);
        nic->stats.tx_errors++;
        spin_unlock_irqrestore(&nic->stats_spinlock, flags);
        dev_kfree_skb(skb);

        return NETDEV_TX_OK; /* don't retry */
    }

    if (g_leaba_module_debug_level > 0) {
        print_buffer(__func__, "actual packet", nic, data, actual_size, 0);
    }

    /* populate the descriptor */
    desc = (struct leaba_nic_pacific_packet_descriptor_t*)(nic->buffer_virt_inj_desc + desc_wr_ptr);
    desc->phys_addr = nic->buffer_phys_inj_data + data_wr_ptr;
    desc->size_err = 0;
    desc->size = actual_size;
    desc->eop = 1;

    if (g_leaba_module_debug_level > 0) {
        print_descriptor(nic, __func__, (union leaba_nic_packet_descriptor_t*)desc);
    }

    /* signal hw */
    mb(); /* make sure everything is in place */
    reg = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_WR_PD_PTR_REG_0;
    regval = new_raw_desc_wr_ptr;
    write_sbif_dma_register(nic->pdev, reg, index, regval);

    /* update stats */
    spin_lock_irqsave(&nic->stats_spinlock, flags);
    nic->stats.tx_packets++;
    nic->stats.tx_bytes += skb->len;
    spin_unlock_irqrestore(&nic->stats_spinlock, flags);

    /* the skb is no longer needed */
    dev_kfree_skb(skb);

    /* check device pointers */
    nic->asic.check_inj_pointer(nic);

    return NETDEV_TX_OK;
}

struct asic_specific m_pacific_spec = {
    .interface_init = pacific_interface_init,
    .activate_interface = pacific_activate_interface,
    .deactivate_interface = pacific_deactivate_interface,
    .show_if = pacific_show_if,
    .get_ext_skb = pacific_get_ext_skb,
    .check_ext_pointers = pacific_check_ext_pointers,
    .check_inj_pointer = pacific_check_inj_pointer,
    .nic_tx = pacific_nic_tx,

    .ext_cfg_0 = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_CFG_REG_0,
    .inj_cfg_0 = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_CFG_REG_0,
    .ext_wr_pd_ptr_0 = PACIFIC_LLD_REGISTER_SBIF_EXT_DMA_WR_PD_PTR_REG_0,
    .inj_rd_pd_ptr_0 = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_RD_PD_PTR_REG_0,
    .inj_wr_pd_ptr_0 = PACIFIC_LLD_REGISTER_SBIF_INJ_DMA_WR_PD_PTR_REG_0,
};
