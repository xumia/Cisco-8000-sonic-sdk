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

#include "gibraltar_leaba_registers.h"

#include "leaba_nic.h"

/*****************************************************************************/
/**********************    V2 common    **************************************/
/*****************************************************************************/

/* allocate DMA buffers for the given interface */
static int
v2_common_interface_buffers_alloc(struct pci_dev* pdev, struct leaba_nic_t* nic)
{
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    int ret;

    ret = single_interface_buffer_alloc(pdev, nic, BUFFER_TYPE_DESC, &nic->buffer_virt_ext_desc, &nic->buffer_phys_ext_desc);
    ret |= single_interface_buffer_alloc(pdev, nic, BUFFER_TYPE_DESC, &nic->buffer_virt_inj_desc, &nic->buffer_phys_inj_desc);
    if (ret != 0) {
        goto err;
    }

    ret = -ENOMEM;
    nic->ext_skb_list
        = (struct punt_inject_buffer_desc*)kzalloc(sizeof(nic->ext_skb_list[0]) * NUM_OF_ELEMENTS_IN_DESC_BUFFER, GFP_KERNEL);
    if (!nic->ext_skb_list) {
        dev_err(&pdev->dev, "leaba%d: %s: kmalloc failed\n", ldev->devno, __func__);
        goto err;
    }

    nic->inj_buffer_list
        = (struct punt_inject_buffer_desc*)kzalloc(sizeof(nic->inj_buffer_list[0]) * NUM_OF_ELEMENTS_IN_DESC_BUFFER, GFP_KERNEL);
    if (!nic->inj_buffer_list) {
        dev_err(&pdev->dev, "leaba%d: %s: kmalloc failed\n", ldev->devno, __func__);
        goto err;
    }

    if (g_leaba_module_debug_level > 0) {
        dev_info(&pdev->dev, "%s: %s: ext_skb_list=%p\n", nic->name, __func__, nic->ext_skb_list);
        dev_info(&pdev->dev, "%s: %s: inj_buffer_list=%p\n", nic->name, __func__, nic->inj_buffer_list);
    }

    return 0;

err:
    interface_buffers_free(pdev, nic);
    return ret;
}

static int
v2_common_allocate_ext_skb(struct pci_dev* pdev, struct leaba_nic_t* nic)
{
    const uint32_t max_packet_len_bytes
        = INJ_DATA_BUFFER_ELEMENT_SIZE_BYTES +                                    /* MTU */
          (m_gb_packet_dma_workaround ? get_max_packet_dma_wa_header_len() : 0) + /* packet dma workaround header */
          (m_add_wrapper_header ? get_dummy_vlan_tag_header_len() : 0);           /* unit-testing wrapper header */

    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    uint32_t desc_index = nic->alloc_ptr_ext_desc & ~DESC_BUFFER_WRAP_BIT;
    struct leaba_nic_gibraltar_ext_packet_descriptor_t* desc
        = (struct leaba_nic_gibraltar_ext_packet_descriptor_t*)nic->buffer_virt_ext_desc + desc_index;
    if (m_gb_packet_dma_workaround && m_add_wrapper_header) {
        /* need to manipulate the punted packet, cannot use skb directly */
        void* data = kzalloc(round_up(max_packet_len_bytes, 16), GFP_KERNEL);
        if (!data) {
            dev_err(&nic->pdev->dev, "leaba%d: %s: kmalloc failed\n", ldev->devno, __func__);
            return -ENOMEM;
        }

        /* store data */
        nic->ext_skb_list[desc_index].is_skb = 0;
        nic->ext_skb_list[desc_index].data = data;

        /* update the punt descriptor list */
        desc->phys_addr = virt_to_phys(data);

        if (g_leaba_module_debug_level > 0) {
            dev_info(&pdev->dev, "%s: %s: desc_index=%u data=%p/%llx\n", nic->name, __func__, desc_index, data, desc->phys_addr);
        }
    } else {
        struct sk_buff* skb = dev_alloc_skb(max_packet_len_bytes);
        if (skb == NULL) {
            dev_err(&pdev->dev, "leaba%d: %s: dev_alloc_skb failed\n", ldev->devno, __func__);
            return -ENOMEM;
        }

        if (m_add_wrapper_header) {
            /* reserve space for the wrapper header */
            skb_reserve(skb, get_dummy_vlan_tag_header_len());
        }

        /* make space for the packet */
        skb_put(skb, max_packet_len_bytes); /* ignore return value */

        /* initialize the skb */
        skb->dev = nic->ndev;
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        /* store skb */
        nic->ext_skb_list[desc_index].is_skb = 1;
        nic->ext_skb_list[desc_index].skb = skb;

        /* update the punt descriptor list */
        desc->phys_addr = virt_to_phys(skb->data);

        if (g_leaba_module_debug_level > 0) {
            dev_info(&pdev->dev,
                     "%s: %s: desc_index=%u skb=%p skb_data=%p/%llx\n",
                     nic->name,
                     __func__,
                     desc_index,
                     skb,
                     skb->data,
                     desc->phys_addr);
        }
    }

    desc->size = 0; /* will be overwritten by the device */
    do_buffer_ptr_inc(nic, &nic->alloc_ptr_ext_desc, BUFFER_TYPE_DESC, 1 /*increment*/, 1 /*contig_wrap*/);

    return 0;
}

/* pass data from host to device */
static int
v2_common_h2d(struct leaba_nic_t* nic, struct sk_buff* skb, void** out_data, int* out_actual_size, int* out_data_copied)
{
    struct leaba_device_t* ldev = pci_get_drvdata(nic->pdev);
    int need_to_add_inject_header = !(is_inject_packet(skb->data, skb->len) || is_svl_packet(skb->data, skb->len));
    int is_data_well_aligned = (((uint64_t)skb->data & 0x7ull) == 0);
    int need_copy = (need_to_add_inject_header || !is_data_well_aligned);

    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev,
                 "%s: %s: need_to_add_inject_header=%d is_data_well_aligned=%d skb.data=%p\n",
                 nic->name,
                 __func__,
                 need_to_add_inject_header,
                 is_data_well_aligned,
                 skb->data);
    }

    if (need_copy) {
        uint32_t extra_bytes = need_to_add_inject_header ? get_inject_headers_len() : 0;
        uint8_t* dp;
        uint32_t len = skb->len + extra_bytes;

        void* data = kzalloc(round_up(len, 16), GFP_KERNEL);
        if (!data) {
            dev_err(&nic->pdev->dev, "leaba%d: %s: kmalloc failed\n", ldev->devno, __func__);
            return -ENOMEM;
        }

        if (g_leaba_module_debug_level > 6) {
            dev_info(&nic->pdev->dev, "%s: %s: data=%p\n", nic->name, __func__, data);
        }

        dp = data;
        if (need_to_add_inject_header) {
            get_inject_header(data, nic->index, 1 /*is_gibraltar*/);
            dp += extra_bytes;
        }

        memcpy(dp, skb->data, skb->len);

        *out_data = data;
        *out_actual_size = len;
    } else {
        *out_data = skb->data;
        *out_actual_size = skb->len;
    }

    *out_data_copied = need_copy;

    if (g_leaba_module_debug_level > 0) {
        print_buffer(__func__, "actual packet", nic, *out_data, *out_actual_size, 0);
    }

    return 0;
}

/* called by the kernel when a packet is passed to the device for transmission */
static int
v2_common_nic_tx(struct sk_buff* skb, struct net_device* ndev, uint32_t reg)
{
    struct leaba_nic_t* nic = netdev_priv(ndev);
    union leaba_nic_packet_descriptor_t* desc = NULL;
    unsigned long flags = 0;
    uint32_t new_raw_desc_wr_ptr;
    uint32_t raw_desc_rd_ptr;
    uint32_t raw_desc_wr_ptr;
    uint32_t desc_wr_ptr;
    uint32_t desc_index;
    uint32_t available_space;
    int actual_size;
    int data_copied;
    int ret;
    void* data = NULL;

    spin_lock_irqsave(&nic->inject_buffer_pointers_spinlock, flags);
    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev, "%s: Entering\n", __func__);
    }

    /* get the cached pointers */
    raw_desc_rd_ptr = nic->read_ptr_inj_desc;
    raw_desc_wr_ptr = nic->write_ptr_inj_desc;

    /* receiving packets when buffer is full - shouldn't happen */
    if (get_desc_buffer_available_space(raw_desc_wr_ptr, raw_desc_rd_ptr, 1 /*element_size*/) == 0) {
        spin_unlock_irqrestore(&nic->inject_buffer_pointers_spinlock, flags);
        dev_err_ratelimited(&nic->pdev->dev, "%s: %s: received packets while buffer is full\n", nic->name, __func__);
        goto err;
    }

    /* increment pointers */
    do_buffer_ptr_inc(nic, &nic->write_ptr_inj_desc, BUFFER_TYPE_DESC, 1 /*increment*/, 1 /*contig_wrap*/);
    new_raw_desc_wr_ptr = nic->write_ptr_inj_desc;

    spin_unlock_irqrestore(&nic->inject_buffer_pointers_spinlock, flags);

    /* stop transmission if buffers are full */
    available_space = get_desc_buffer_available_space(new_raw_desc_wr_ptr, raw_desc_rd_ptr, 1 /*element_size*/);
    if (available_space == 0) {
        dev_warn_ratelimited(&nic->pdev->dev, "%s: %s: no more available space\n", nic->name, __func__);
        if (g_leaba_module_debug_level > 6) {
            dev_info(&nic->pdev->dev, "%s: %s: netif_stop\n", nic->name, __func__);
        }

        netif_stop_queue(nic->ndev);
    }

    /* get the data */
    ret = v2_common_h2d(nic, skb, &data, &actual_size, &data_copied);
    if (ret < 0) {
        dev_err_ratelimited(&nic->pdev->dev, "%s: %s: v2_common_h2d failed\n", nic->name, __func__);
        goto err;
    }

    desc_wr_ptr = raw_desc_wr_ptr & ~DESC_BUFFER_WRAP_BIT;
    desc_index = desc_wr_ptr;

    /* Keep the skb or the allocated data, will be freed after the device consumes it */
    if (data_copied) {
        dev_kfree_skb(skb);
        nic->inj_buffer_list[desc_index].data = data;
        nic->inj_buffer_list[desc_index].is_skb = 0;
    } else {
        nic->inj_buffer_list[desc_index].skb = skb;
        nic->inj_buffer_list[desc_index].is_skb = 1;
    }

    /* populate the descriptor */
    desc = (union leaba_nic_packet_descriptor_t*)nic->buffer_virt_inj_desc + desc_wr_ptr;
    desc->gibraltar_inject.phys_addr = virt_to_phys(data);
    desc->gibraltar_inject.size_err = 0;
    desc->gibraltar_inject.size = actual_size;
    desc->gibraltar_inject.sop = 1;
    desc->gibraltar_inject.eop = 1;

    if (g_leaba_module_debug_level > 0) {
        print_descriptor(nic, __func__, desc);
    }

    /* make sure everything is in place */
    mb();

    /* signal hw */
    write_sbif_dma_register(nic->pdev, reg, nic->index, new_raw_desc_wr_ptr);

    /* update stats */
    spin_lock_irqsave(&nic->stats_spinlock, flags);
    nic->stats.tx_packets++;
    nic->stats.tx_bytes += skb->len;
    spin_unlock_irqrestore(&nic->stats_spinlock, flags);

    /* check device pointers */
    nic->asic.check_inj_pointer(nic);

    return NETDEV_TX_OK;

err:
    dev_kfree_skb(skb);
    dev_err(&nic->pdev->dev, "%s: %s: free skb=%p on error\n", nic->name, __func__, skb);
    if (g_leaba_module_debug_level > 6) {
        dev_info(&nic->pdev->dev, "%s: %s: netif_stop\n", nic->name, __func__);
    }

    netif_stop_queue(nic->ndev);

    return NETDEV_TX_OK; /* don't retry */
}

/* check the inject read pointer that the device updates */
static void
v2_common_check_inj_pointer(struct leaba_nic_t* nic)
{
    uint32_t regval;
    uint32_t new_index;
    uint32_t old_index;
    unsigned long flags = 0;
    uint32_t i;

    // Only free data if the read pointer has moved.
    // check_inj_pointer is called during TX and by work_task.  Prevent race by checking index in critical section.
    spin_lock_irqsave(&nic->inject_buffer_pointers_spinlock, flags);

    // Get current read pointer (potential NEW index).
    regval = get_inject_desc_read_pointer(nic);
    new_index = (regval & ~DESC_BUFFER_WRAP_BIT);

    // If the new value is the same as the OLD index, do nothing.
    if (regval == nic->read_ptr_inj_desc) {
        /* nothing changed, nothing to do. */
        spin_unlock_irqrestore(&nic->inject_buffer_pointers_spinlock, flags);
        return;
    }

    // Otherwise, update the old cache and continue.
    old_index = nic->read_ptr_inj_desc & ~DESC_BUFFER_WRAP_BIT;
    nic->read_ptr_inj_desc = regval; /* update cached desc pointer */
    spin_unlock_irqrestore(&nic->inject_buffer_pointers_spinlock, flags);

    /* check for pci errors */
    if (check_and_handle_pci_errors(nic, regval)) {
        /* error detected */
        return;
    }

    /* free skb that were already consumed by the device */
    for (i = old_index; i != new_index; i = (i + 1) % NUM_OF_ELEMENTS_IN_DESC_BUFFER) {
        struct punt_inject_buffer_desc* desc = &nic->inj_buffer_list[i];
        if (g_leaba_module_debug_level > 6) {
            dev_info(&nic->pdev->dev, "%s: %s: i=%d is_skb=%d skb/data=%p\n", nic->name, __func__, i, desc->is_skb, desc->data);
        }

        free_punt_inject_descriptor(nic, desc);
    }

    /* restart the interface if needed */
    if (netif_queue_stopped(nic->ndev)) {
        if (g_leaba_module_debug_level > 6) {
            dev_info(&nic->pdev->dev, "%s: %s: netif_wake\n", nic->name, __func__);
        }

        netif_wake_queue(nic->ndev);
    }
}

/* check the write punt pointers that the device updates */
static void
v2_common_check_ext_pointers(struct leaba_nic_t* nic, uint32_t reg)
{
    uint32_t dev_desc_wr_ptr = get_ext_desc_write_pointer(nic);
    unsigned long flags = 0;
    uint32_t regval;

    /* compare the device's pointer with cached pointer */
    if (dev_desc_wr_ptr == nic->read_ptr_ext_desc) {
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
        uint32_t desc_index = dev_desc_rd_ptr;
        struct leaba_nic_gibraltar_ext_packet_descriptor_t* desc
            = (struct leaba_nic_gibraltar_ext_packet_descriptor_t*)nic->buffer_virt_ext_desc + desc_index;

        if (g_leaba_module_debug_level > 0) {
            print_descriptor(nic, __func__, (union leaba_nic_packet_descriptor_t*)desc);
        }

        /* the descriptor might be invalid in case the dma transaction to host memory is not finished when we read the device's
         * write ptr. if this is the case then it's sure to be the last packet */
        if ((desc->size_err == 0) || (desc->phys_addr == 0)) {
            break;
        }

        if (desc->err) {
            /* skip this packet */
            dev_err_ratelimited(&nic->pdev->dev, "%s: %s: error bit is set\n", nic->name, __func__);
            spin_lock_irqsave(&nic->stats_spinlock, flags);
            nic->stats.rx_errors++;
            spin_unlock_irqrestore(&nic->stats_spinlock, flags);
            /* skb's of good packets are freed by the kernel, skb's of bad packets need to be freed by the driver.
             * data of good packets is freed in v2_common_get_ext_skb(), data of bad packets should be freed here. */
            free_punt_inject_descriptor(nic, &nic->ext_skb_list[desc_index]);
        } else {
            /* send the packet to the kernel for processing */
            leaba_nic_rx(nic, (union leaba_nic_packet_descriptor_t*)desc, desc->size);
        }

        /* update the read pointers */
        do_buffer_ptr_inc(nic, &nic->read_ptr_ext_desc, BUFFER_TYPE_DESC, 1 /*increment*/, 1 /*contig_wrap*/);

        /* invalidate the desciptor */
        invalidate_descriptor((union leaba_nic_packet_descriptor_t*)desc);

        /* allocate a new skb instead the one that was just used */
        v2_common_allocate_ext_skb(nic->pdev, nic); /* updates alloc_ptr_ext_desc */

    } while (nic->read_ptr_ext_desc != dev_desc_wr_ptr);

    mb(); /* make sure everything is in place before updating the device */

    /* update read pointers at the device */
    regval = nic->alloc_ptr_ext_desc;
    write_sbif_dma_register(nic->pdev, reg, nic->index, regval);
}

/* prepare skb with a packet coming from the device */
static struct sk_buff*
v2_common_get_ext_skb(struct leaba_nic_t* nic, union leaba_nic_packet_descriptor_t* desc)
{
    uint32_t desc_index;
    struct sk_buff* skb;

    desc_index = desc - (union leaba_nic_packet_descriptor_t*)nic->buffer_virt_ext_desc;
    if (nic->ext_skb_list[desc_index].is_skb) {
        /* skb was allocated beforehand */
        skb = nic->ext_skb_list[desc_index].skb;

        /* skb was initialized at allocation time. only missing info is the packet length */
        skb->len = desc->gibraltar_ext.size;

        if (g_leaba_module_debug_level > 0) {
            dev_info(&nic->pdev->dev,
                     "%s: %s: desc.phys_addr=%llx desc.size_err=%llx skb: head=%p data=%p tail=%u end=%u len=%u\n",
                     nic->name,
                     __func__,
                     desc->gibraltar_ext.phys_addr,
                     desc->gibraltar_ext.size_err,
                     skb->head,
                     skb->data,
                     skb->tail,
                     skb->end,
                     skb->len);
            print_buffer(__func__, "orig packet", nic, skb->data, desc->gibraltar_ext.size, 0);
        }

        if (m_gb_packet_dma_workaround) {
            unsigned packet_dma_header_len = *(uint8_t*)skb->data;
            skb_pull(skb, packet_dma_header_len);
        }

        if (g_leaba_module_debug_level > 0) {
            print_buffer(__func__, "actual packet", nic, skb->data, skb->len, 0);
        }

        skb->protocol = eth_type_trans(skb, nic->ndev);

        return skb;
    } else {
        /* allocate skb and copy the data from the received packet to it */
        void* data = nic->ext_skb_list[desc_index].data;
        unsigned packet_dma_header_len = *(uint8_t*)data;

        if (g_leaba_module_debug_level > 0) {
            dev_info(&nic->pdev->dev,
                     "%s: %s: desc.phys_addr=%llx desc.size_err=%llx\n",
                     nic->name,
                     __func__,
                     desc->gibraltar_ext.phys_addr,
                     desc->gibraltar_ext.size_err);
            print_buffer(__func__, "orig packet", nic, data, desc->gibraltar_ext.size, 0);
        }

        skb = dev_alloc_skb(desc->gibraltar_ext.size + get_dummy_vlan_tag_header_len() + BYTES_IN_DQWORD);
        if (skb == NULL) {
            unsigned long flags = 0;
            dev_err_ratelimited(&nic->pdev->dev, "%s: %s: dev_alloc_skb failed\n", nic->name, __func__);
            spin_lock_irqsave(&nic->stats_spinlock, flags);
            nic->stats.rx_dropped++;
            spin_unlock_irqrestore(&nic->stats_spinlock, flags);

            return NULL;
        }

        if (g_leaba_module_debug_level > 6) {
            dev_info(&nic->pdev->dev, "%s: %s: skb=%p \n", nic->name, __func__, skb);
        }

        /* populate the skb */
        skb_put(skb, round_up(desc->gibraltar_ext.size + get_dummy_vlan_tag_header_len(), BYTES_IN_DQWORD));
        skb->len = get_dummy_vlan_tag_header_len() + desc->gibraltar_ext.size - packet_dma_header_len;
        add_dummy_vlan_tag_header_gibraltar(skb->data, data);
        memcpy(skb->data + get_dummy_vlan_tag_header_len(),
               data + packet_dma_header_len,
               desc->gibraltar_ext.size - packet_dma_header_len);

        if (g_leaba_module_debug_level > 0) {
            print_buffer(__func__, "actual packet", nic, skb->data, skb->len, 0);
        }

        skb->dev = nic->ndev;
        skb->protocol = eth_type_trans(skb, nic->ndev);
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        /* free the packet used by the device */
        free_punt_inject_descriptor(nic, &nic->ext_skb_list[desc_index]);

        return skb;
    }
}

/*****************************************************************************/
/**********************    GIBRALTAR specific    *****************************/
/*****************************************************************************/

#define GIBRALTAR_EXT_FIELD_MASK_GO (0x1 << 0)
#define GIBRALTAR_EXT_FIELD_MASK_FLOW_CTRL (0x1 << 1)
#define GIBRALTAR_EXT_FIELD_FLOW_CTRL_PD_THR_SHIFT 2
#define GIBRALTAR_EXT_FIELD_FLOW_CTRL_PD_THR_BITS_NR 6
#define GIBRALTAR_EXT_FIELD_FLOW_CTRL_PD_THR_MASK(_t)                                                                              \
    (((_t) & ((1 << GIBRALTAR_EXT_FIELD_FLOW_CTRL_PD_THR_BITS_NR) - 1)) << GIBRALTAR_EXT_FIELD_FLOW_CTRL_PD_THR_SHIFT)
#define GIBRALTAR_EXT_FIELD_MASK_REMOTE (0x1 << 8)
#define GIBRALTAR_EXT_FIELD_MASK_WB (0x1 << 9)

#define GIBRALTAR_INJECT_FIELD_MASK_GO (0x1 << 0)
#define GIBRALTAR_INJECT_FIELD_MASK_REMOTE (0x1 << 1)
#define GIBRALTAR_INJECT_FIELD_MASK_WB (0x1 << 2)

static uint32_t
v2_get_ext_field_flow_ctrl_pd_thr_mask(uint32_t t, struct leaba_nic_t* nic)
{
    return (t & ((1 << nic->asic.ext_field_flow_ctrl_pd_thr_bits_nr) - 1)) << nic->asic.ext_field_flow_ctrl_pd_thr_shift;
}

static int
v2_interface_init(struct leaba_nic_t* nic)
{
    struct pci_dev* pdev = nic->pdev;
    struct leaba_device_t* ldev = pci_get_drvdata(pdev);
    int ret = 0;
    uint32_t reg;
    uint32_t regval;
    int index = nic->index;
    unsigned i;
    const uint32_t ext_config_reg_val = (m_flow_control ? nic->asic.ext_field_mask_flow_ctrl : 0)
                                        | v2_get_ext_field_flow_ctrl_pd_thr_mask(m_flow_control_threshold, nic)
                                        | (m_remote ? nic->asic.ext_field_mask_remote : 0)
                                        | (m_use_write_back ? nic->asic.ext_field_mask_wb : 0);
    const uint32_t inj_config_reg_val
        = (m_remote ? nic->asic.inject_field_mask_remote : 0) | (m_use_write_back ? nic->asic.inject_field_mask_wb : 0);

    spin_lock_init(&nic->stats_spinlock);
    spin_lock_init(&nic->inject_buffer_pointers_spinlock);
    INIT_WORK(&nic->deferred_work, (void (*)(struct work_struct*))do_check_device_pointers);

    /* allocate buffers */
    ret = v2_common_interface_buffers_alloc(pdev, nic);
    if (ret < 0) {
        goto out;
    }

    /* allocate skb's for punt */
    for (i = 0; i < NUM_OF_ELEMENTS_IN_DESC_BUFFER; i++) {
        ret = v2_common_allocate_ext_skb(pdev, nic);
        if (ret != 0) {
            dev_err(&pdev->dev, "leaba%d: %s: dev_alloc_skb failed\n", ldev->devno, __func__);
            goto err;
        }
    }

    /* punt descriptor buffer */

    reg = nic->asic.sbif_ext_dma_pd_base_lsb_reg_0;
    regval = ((uint32_t)(nic->buffer_phys_ext_desc)) >> 12;
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.sbif_ext_dma_pd_base_msb_reg_0;
    regval = (uint32_t)(nic->buffer_phys_ext_desc >> 32);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.sbif_ext_dma_pd_length_reg_0;
    regval = NUM_OF_ELEMENTS_IN_DESC_BUFFER;
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.sbif_ext_dma_allocated_pd_ptr_reg_0;
    regval = nic->alloc_ptr_ext_desc;
    write_sbif_dma_register(pdev, reg, index, regval);

    /* punt config register */

    reg = nic->asic.ext_cfg_0;
    regval = ext_config_reg_val;
    write_sbif_dma_register(pdev, reg, index, regval);

    /* inject descriptor buffer */

    reg = nic->asic.sbif_inj_dma_pd_base_lsb_reg_0;
    regval = ((uint32_t)(nic->buffer_phys_inj_desc)) >> 12;
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.sbif_inj_dma_pd_base_msb_reg_0;
    regval = (uint32_t)(nic->buffer_phys_inj_desc >> 32);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.sbif_inj_dma_pd_length_reg_0;
    regval = NUM_OF_ELEMENTS_IN_DESC_BUFFER;
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.inj_wr_pd_ptr_0;
    regval = 0;
    write_sbif_dma_register(pdev, reg, index, regval);

    /* inject config register */

    reg = nic->asic.inj_cfg_0;
    regval = inj_config_reg_val;
    write_sbif_dma_register(pdev, reg, index, regval);

    ret = 0;
out:
    return ret;

err:
    interface_teardown(pdev, nic);
    goto out;
}

/* activate interface */
static void
v2_activate_interface(struct leaba_nic_t* nic)
{
    uint32_t reg;
    uint32_t regval;
    int index = nic->index;
    struct pci_dev* pdev = nic->pdev;
    ktime_t kt = ktime_set(0, m_polling_interval_usec * NSEC_PER_USEC); /* ktime is given in nsec */

    if (nic->is_active) {
        return;
    }

    reg = nic->asic.ext_cfg_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval |= nic->asic.ext_field_mask_go;
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.inj_cfg_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval |= nic->asic.inject_field_mask_go;
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
v2_deactivate_interface(struct leaba_nic_t* nic)
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

    reg = nic->asic.ext_cfg_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval &= ~(nic->asic.ext_field_mask_go);
    write_sbif_dma_register(pdev, reg, index, regval);

    reg = nic->asic.inj_cfg_0;
    regval = read_sbif_dma_register(pdev, reg, index);
    regval &= ~(nic->asic.inject_field_mask_go);
    write_sbif_dma_register(pdev, reg, index, regval);

    nic->is_active = 0;
    dev_info(&pdev->dev, "%s: de-activated\n", nic->name);
}

/* show interface info, attribute buffer is PAGE_SIZE bytes */
static ssize_t
v2_show_if(struct leaba_nic_t* nic, struct device_attribute* attr, char* buf, unsigned n)
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

    sprintf(p, "alloc_ptr_ext_desc=%x\n", nic->alloc_ptr_ext_desc);
    p += strlen(p);

    sprintf(p, "write_ptr_inj_desc=%x\n", nic->write_ptr_inj_desc);
    p += strlen(p);

    sprintf(p, "read_ptr_ext_desc=%x\n", nic->read_ptr_ext_desc);
    p += strlen(p);

    sprintf(p, "read_ptr_inj_desc=%x\n", nic->read_ptr_inj_desc);
    p += strlen(p);

#define LEABA_PRINT_REG(_r, _n)                                                                                                    \
    do {                                                                                                                           \
        uint32_t regval;                                                                                                           \
        regval = read_sbif_dma_register(nic->pdev, _r, _n);                                                                        \
        sprintf(p, "%s=%x\n", #_r, regval);                                                                                        \
        p += strlen(p);                                                                                                            \
    } while (0);

    LEABA_PRINT_REG(nic->asic.ext_cfg_0, n);
    LEABA_PRINT_REG(nic->asic.sbif_ext_dma_pd_base_lsb_reg_0, n);
    LEABA_PRINT_REG(nic->asic.sbif_ext_dma_pd_base_msb_reg_0, n);
    LEABA_PRINT_REG(nic->asic.sbif_ext_dma_pd_length_reg_0, n);
    LEABA_PRINT_REG(nic->asic.sbif_ext_dma_allocated_pd_ptr_reg_0, n);
    LEABA_PRINT_REG(nic->asic.ext_wr_pd_ptr_0, n);
    LEABA_PRINT_REG(nic->asic.inj_cfg_0, n);
    LEABA_PRINT_REG(nic->asic.sbif_inj_dma_pd_base_lsb_reg_0, n);
    LEABA_PRINT_REG(nic->asic.sbif_inj_dma_pd_base_msb_reg_0, n);
    LEABA_PRINT_REG(nic->asic.sbif_inj_dma_pd_length_reg_0, n);
    LEABA_PRINT_REG(nic->asic.inj_rd_pd_ptr_0, n);
    LEABA_PRINT_REG(nic->asic.inj_wr_pd_ptr_0, n);
#undef LEABA_PRINT_REG

    return strlen(buf);
}

/* called by the kernel when a packet is passed to the device for transmission */
static int
v2_nic_tx(struct sk_buff* skb, struct net_device* ndev)
{
    struct leaba_nic_t* nic = netdev_priv(ndev);
    return v2_common_nic_tx(skb, ndev, nic->asic.inj_wr_pd_ptr_0);
}

/* check the write punt pointers that the device updates */
static void
v2_check_ext_pointers(struct leaba_nic_t* nic)
{
    return v2_common_check_ext_pointers(nic, nic->asic.sbif_ext_dma_allocated_pd_ptr_reg_0);
}

/*****************************************************************************/
/**********************    END specific   ************************************/
/*****************************************************************************/

struct asic_specific m_gibraltar_spec = {
    .interface_init = v2_interface_init,
    .activate_interface = v2_activate_interface,
    .deactivate_interface = v2_deactivate_interface,
    .show_if = v2_show_if,
    .get_ext_skb = v2_common_get_ext_skb,
    .check_ext_pointers = v2_check_ext_pointers,
    .check_inj_pointer = v2_common_check_inj_pointer,
    .nic_tx = v2_nic_tx,

    .ext_cfg_0 = GIBRALTAR_LLD_REGISTER_SBIF_EXT_DMA_CFG_REG_0,
    .inj_cfg_0 = GIBRALTAR_LLD_REGISTER_SBIF_INJ_DMA_CFG_REG_0,
    .ext_wr_pd_ptr_0 = GIBRALTAR_LLD_REGISTER_SBIF_EXT_DMA_WR_PD_PTR_REG_0,
    .inj_rd_pd_ptr_0 = GIBRALTAR_LLD_REGISTER_SBIF_INJ_DMA_RD_PD_PTR_REG_0,
    .inj_wr_pd_ptr_0 = GIBRALTAR_LLD_REGISTER_SBIF_INJ_DMA_WR_PD_PTR_REG_0,

    .sbif_ext_dma_pd_base_lsb_reg_0 = GIBRALTAR_LLD_REGISTER_SBIF_EXT_DMA_PD_BASE_LSB_REG_0,
    .sbif_ext_dma_pd_base_msb_reg_0 = GIBRALTAR_LLD_REGISTER_SBIF_EXT_DMA_PD_BASE_MSB_REG_0,
    .sbif_ext_dma_pd_length_reg_0 = GIBRALTAR_LLD_REGISTER_SBIF_EXT_DMA_PD_LENGTH_REG_0,
    .sbif_ext_dma_allocated_pd_ptr_reg_0 = GIBRALTAR_LLD_REGISTER_SBIF_EXT_DMA_ALLOCATED_PD_PTR_REG_0,
    .sbif_inj_dma_pd_base_lsb_reg_0 = GIBRALTAR_LLD_REGISTER_SBIF_INJ_DMA_PD_BASE_LSB_REG_0,
    .sbif_inj_dma_pd_base_msb_reg_0 = GIBRALTAR_LLD_REGISTER_SBIF_INJ_DMA_PD_BASE_MSB_REG_0,
    .sbif_inj_dma_pd_length_reg_0 = GIBRALTAR_LLD_REGISTER_SBIF_INJ_DMA_PD_LENGTH_REG_0,

    .ext_field_mask_go = GIBRALTAR_EXT_FIELD_MASK_GO,
    .ext_field_mask_flow_ctrl = GIBRALTAR_EXT_FIELD_MASK_FLOW_CTRL,
    .ext_field_flow_ctrl_pd_thr_shift = GIBRALTAR_EXT_FIELD_FLOW_CTRL_PD_THR_SHIFT,
    .ext_field_flow_ctrl_pd_thr_bits_nr = GIBRALTAR_EXT_FIELD_FLOW_CTRL_PD_THR_BITS_NR,
    .ext_field_mask_remote = GIBRALTAR_EXT_FIELD_MASK_REMOTE,
    .ext_field_mask_wb = GIBRALTAR_EXT_FIELD_MASK_WB,

    .inject_field_mask_go = GIBRALTAR_INJECT_FIELD_MASK_GO,
    .inject_field_mask_remote = GIBRALTAR_INJECT_FIELD_MASK_REMOTE,
    .inject_field_mask_wb = GIBRALTAR_INJECT_FIELD_MASK_WB,
};

