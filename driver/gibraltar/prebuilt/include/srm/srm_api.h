/** @file srm.h
 ****************************************************************************
 *
 * @brief
 *     This module describes the high level API methods provided
 *     by the SRM API.
 *
 ****************************************************************************
 * @author
 *    This file contains information that is proprietary and confidential to
 *    ABCD_CORP.
 *
 *    This file can be used under the terms of the ABCD_LICENSE
 *    Agreement. You should have received a copy of the license with this file,
 *    if not please contact your ABCD_SUPPORT staff.
 *
 *    Copyright (C) 2006-2021 ABCD_CORP, Inc. All rights reserved.
 *
 *    API Version Number: 0.33.0.1670
 ***************************************************************************/
#ifndef __SRM_H__
#define __SRM_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "ip_rtos.h"
#include "srm_config.h"
#include "srm_registers.h"
#include "srm_rules.h"

// MACROS - START
#define MASK(NAME)            (NAME##__MASK << NAME##__OFFSET)
#define OFFSET(NAME)          (NAME##__OFFSET)
#define VAL(NAME, val)        (((val) & NAME##__MASK) << NAME##__OFFSET)
#define ADDRESS(NAME)         (NAME##__ADDRESS)
#define MASK_UNALIGNED(NAME)  (NAME##__MASK)
#define ADDR_DIFF(A0, A1)     (A1##__ADDRESS - A0##__ADDRESS)
//MACROS - END

#define SRM_MCU_IRAM_BASE_ADDR       0x5ffa0000
#define SRM_MCU_IRAM_SIZE            0x8000 //128 kB in 32bit words
#define SRM_MCU_DRAM_BASE_ADDR       0x5ff80000
#define SRM_MCU_DRAM_SIZE            0x4000 //64 kB in 32bit words


#if defined(IP_HAS_STC_CHANNEL_MAPPING) && (IP_HAS_STC_CHANNEL_MAPPING==1)
#    define STC_REMAP(die,channel) if(channel > 2){ die += 1; channel -= 3;}
#else
#    define STC_REMAP(die,channel)
#endif


/// To broadcast a register write to all channels, do not use in API methods, just in direct register accesses
#define SRM_BROADCAST_CHANNEL 0xff

// Maximum time to wait for a ACK response from the FW, units are seconds
#define SRM_ACK_WAIT_MAX      300 // seconds
//
// Maximum time to wait for the PLL to sync, units are seconds
#define SRM_PLL_SYNC_WAIT_MAX 300 // seconds

/** the maximum number of AN/LT followers */
#define SRM_ANLT_MAX_NUM_FOLLOWERS

/**
 * @h2 Hardware Detection
 * =======================================================
 * The following methods are used to manage the detection
 * of the underlying ASIC hardware to manage differences
 * between the hardware revisions.
 *
 * @brief
 * This enumerator is used to manage the difference betwenn
 * the different hardware revisions
 *
 * @since 0.1
 */
typedef enum
{
    /** Revision A0 of the hardware */
    SRM_HW_REVA = 0x76700210,
    /** Revision B0 of the hardware */
    SRM_HW_REVB = 0x76710210,
}e_srm_hw_rev;


/**
 * This method is used to query and return the revision of the
 * underlying hardware.
 *
 * @param die  [I] - The physical ASIC die being accessed.
 *
 * @return The hardware revision information.
 *
 * @since 0.1
 */
e_srm_hw_rev srm_hw_rev(uint32_t die);


/**
 * These enums identify the data-path interface and direction
 */
typedef enum
{
    /** identifies the serial Rx interface */
    SRM_INTF_SERIAL_RX  = 1 << 0,
    /** identifies the serial Tx interface */
    SRM_INTF_SERIAL_TX  = 1 << 1,
    /** identifies the core Rx interface */
    SRM_INTF_CORE_RX    = 1 << 2,
    /** identifies the core Tx interface */
    SRM_INTF_CORE_TX    = 1 << 3,

    /** identifies the serial side of the device */
    SRM_INTF_SERIAL_ALL = SRM_INTF_SERIAL_RX | SRM_INTF_SERIAL_TX,
    /** identifies the core side of the device */
    SRM_INTF_CORE_ALL   = SRM_INTF_CORE_RX | SRM_INTF_CORE_TX,

    /** identifies the serial to core data-path direction */
    SRM_INTF_DIR_RX     = SRM_INTF_SERIAL_RX | SRM_INTF_CORE_RX,
    /** identifies the core to serial data-path direction */
    SRM_INTF_DIR_TX     = SRM_INTF_SERIAL_TX | SRM_INTF_CORE_TX,

} e_srm_intf;


/**
 * This enumeration bit map defines the list of acknowledge types
 * asserted by the FW
 */
typedef enum
{
    /** Chip Initialization acknowledgement */
    SRM_ACK_CHP_INIT   = 1 << 0,
    /** PLL Initialization acknowledgement */
    SRM_ACK_PLL_INIT   = 1 << 1,
    /** Tx Initialization acknowledgement */
    SRM_ACK_TX_INIT    = 1 << 2,
    /** Rx Initialization acknowledgement */
    SRM_ACK_RX_INIT    = 1 << 3,
    /** AN Initialization acknowledgement */
    SRM_ACK_ANLT_INIT  = 1 << 4,

    SRM_ACK_MAX        = SRM_ACK_ANLT_INIT,

} e_srm_ack_type;

/**
 * @h2 Register Access Methods
 * =======================================================
 * The following methods must be defined by the customer
 * to provide access to the underlying register interface
 * of the ASIC depending on the customer platform.
 *
 * @h3 Low Level Interface Methods
 * ================================
 * The srm_reg_get/srm_reg_set methods provide access to
 * the ASIC registers. They must be implemented outside the
 * API in the customers software as the interface may be
 * different for each user. The API provides the following
 * protoypes for these methods.
 *
 * @brief
 * Lowest level register get function, must be implemented
 * by the end user for 16bit-only accesses.
 *
 * NOTE: Do not use srm_reg_get directly in your code, use
 * srm_reg_read instead.
 *
 * @param die  [I] - The ASIC die being accessed.
 * @param addr [I] - The address of the register being accessed.
 * @param data [O] - The data read from the register.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_reg_get(
    uint32_t  die,
    uint32_t  addr,
    uint32_t* data);

/**
 * @brief
 * Lowest level register set function, must be implemented
 * by the end user for 16bit-only accesses.
 *
 * NOTE: Do not use srm_reg_set directly in your code, use
 * srm_reg_write instead.
 *
 * @param die  [I] - The ASIC die being accessed.
 * @param addr [I] - The address of the register being
 *                   accessed.
 * @param data [I] - The data to write to the register.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_reg_set(
    uint32_t die,
    uint32_t addr,
    uint32_t data);


/**
 * @h3 API Register Access Methods
 * ===============================
 * These are higher layer methods that build upon the
 * srm_reg_get/srm_reg_set methods. These should be used
 * when accessing the registers in the event that any special
 * handling needs to be implemented when accessing particular
 * registers.
 *
 * @brief
 * This method is used to write a register on the device. The
 * registers are actually only 16 bits but 32b is used for
 * internal validation purposes. The extra bits about 0xffff
 * are ignored.
 *
 * @param die  [I] - The ASIC die being accessed.
 * @param addr [I] - The address of the register being accessed.
 * @param data [I] - The data to write to the register.
 *
 * @since 0.1
 */
void srm_reg_write(
    uint32_t die, 
    uint32_t addr, 
    uint32_t data);

/**
 * This method is called to read an ASIC register.
 *
 * @param die  [I] - The ASIC die being accessed.
 * @param addr [I] - The address of the register being accessed.
 * 
 * @return The data read back from the register.
 *
 * @since 0.1
 */
uint32_t srm_reg_read(
    uint32_t die, 
    uint32_t addr);

/**
 * This method is called to perform a read/modify/write operation
 * on an ASIC register. This is used to modify bitfields within
 * a register.
 *
 * @param die  [I] - The ASIC die being accessed.
 * @param addr [I] - The address of the register being accessed.
 * @param data [I] - The data to write to the register.
 * @param mask [I] - A mask to ignore unsed bits.
 * 
 * @return The modified register value.
 *
 * @since 0.1
 */
uint32_t srm_reg_rmw(
    uint32_t die, 
    uint32_t addr, 
    uint32_t data, 
    uint32_t mask);


/**
 * @h4 Per-Channel Register Access Methods
 * =======================================
 * These methods are used to access a particular channel through the
 * ASIC. They automatically map the channel to the correct register instance
 * based on the ASIC type.
 *
 * @brief
 * This method is called to read a register for a particular channel through
 * the ASIC.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel being accessed.
 * @param addr    [I] - The address of the register being accessed.
 * 
 * @return The data read back from the register.
 *
 * @since 0.1
 */
uint32_t srm_reg_channel_read(
    uint32_t die, 
    uint32_t channel, 
    uint32_t addr);

/**
 * This method is used for writing to a register associated with a particular
 * channel. The registers are actually only 16 bits but 32b is
 * used for internal validation purposes. The extra bits about 0xffff
 * are ignored.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel being accessed.
 * @param addr    [I] - The address of the register being accessed.
 * @param data    [I] - The data to write to the register.
 *
 * @since 0.1
 */
void srm_reg_channel_write(
    uint32_t die, 
    uint32_t channel, 
    uint32_t addr, 
    uint32_t data);

/**
 * This method is called to perform a read/modify/write operation
 * on a register for a particular channel through the ASIC. This is used to
 * modify bitfields within a register.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel being accessed.
 * @param addr    [I] - The address of the register being accessed.
 * @param data    [I] - The data to write to the register.
 * @param mask    [I] - A mask to ignore unsed bits.
 * 
 * @return The modified register value.
 *
 * @since 0.1
 */
uint32_t srm_reg_channel_rmw(
    uint32_t die, 
    uint32_t channel, 
    uint32_t addr, 
    uint32_t data, 
    uint32_t mask);

/**
 * This method is used to re-map the address for particular register based
 * on the ASIC.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel being accessed.
 * @param addr    [I] - The address of the register being accessed.
 *
 * @since 0.1
 *
 * @return The corrected register channel for the target channel.
 */
uint32_t srm_reg_channel_addr(
    uint32_t die, 
    uint32_t channel,
    uint32_t addr);

typedef ip_status_t (*srm_callback_lock)(uint32_t die);
typedef ip_status_t (*srm_callback_unlock)(uint32_t die);

/**
 * @h2 Hardware Locking Methods
 * =======================================================
 * The following methods provide support for multi-threading.
 * Because this is optional they are implemented as callback
 * methods that the user may chose to register.
 *
 * @note
 * The locking methods must be implemented as recursive/counting locks
 * or reentrant mutex as the API will attempt to obtain the
 * same lock multiple times in child function calls:
 *   https://en.wikipedia.org/wiki/Reentrant_mutex
 *
 * @brief
 * Setup a callback method to support h/w locking. Setting up hardware
 * locking/multi-threading is optional. It will be disabled
 * by default.
 *
 * @param callback [I] - Pointer to the callback function to
 *                       call to lock access to the h/w.
 *
 * @return None
 *
 * @since 0.1
 */
void srm_set_callback_for_lock(
    srm_callback_lock callback);

/**
 * Setup a callback method to support h/w unlocking. Setting up
 * hardware locking is optional. It will be disabled by default.
 *
 * @param callback [I] - Pointer to the callback function to
 *                       call to lock access to the h/w.
 *
 * @return None
 *
 * @since 0.1
 */
void srm_set_callback_for_unlock(
    srm_callback_unlock callback);

    
#define SRM_LOCK(die) {if(srm_lock(die) != IP_OK) return IP_ERROR;}
#define SRM_UNLOCK(die) {if(srm_unlock(die) != IP_OK) return IP_ERROR;}

/**
 * Lock the hardware for exclusive access. If hardware locking
 * has not been enabled then these methods silently return.
 *
 * @{note, Failure to obtain lock (via timeout or some other method)
 * should return IP_ERROR, otherwise the API will proceed without
 * obtaining lock}
 *
 * @{note, The locking feature has not been tested}
 *
 * @param die [I] - The ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @see srm_set_callback_for_lock, srm_set_callback_for_unlock
 *
 * @since 0.1
 */
ip_status_t srm_lock(
    uint32_t die);

/**
 * Unlock the hardware for exclusive access. If hardware locking
 * has not been enabled then these methods silently return.
 *
 * @{note, The locking feature has not been tested}
* 
 * @param die [I] - The ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @see srm_set_callback_for_lock, srm_set_callback_for_unlock
 *
 * @since 0.1
 */
ip_status_t srm_unlock(
    uint32_t die);

/**
 * @h2 Firmware Management
 * =======================================================
 *
 * @h3 Firmware Mode Enumerations
 * =======================================================
 *
 * @brief
 * The following enumeration defines the modes of
 * operation of the firmware.
 */
typedef enum
{
    /** Unknown FW mode */
    SRM_FW_MODE_UNKNOWN           = 0,
    /**  FW in pplication mode */
    SRM_FW_MODE_APPLICATION       = 1,

} e_srm_fw_mode;


/**
 * @h3 Switching Firmware Modes
 * =======================================================
 * The following methods may be used to switch between different
 * firmware modes.
 *
 * @brief
 * This method is called to reset the firmware into application mode. It
 * resets the MCU and switches to the application bank (assuming it
 * has been previously programmed in the IRAM/DRAM). If the
 * @{b,wait_till_started} flag is set it waits for the MCU_FW_MODE register to report
 * 0xACC0 to indicate that the application image has started up.
 *
 * This method assumes that the * firmware has been previously downloaded to the IRAM/DRAM.
 *
 * @{note,
 * To avoid blocking forever in the case of a failure or where the
 * firmware image is not yet programmed this method will timeout after five
 * seconds and return IP_ERROR.}
 *
 * @param die               [I] - The ASIC die being accessed.
 * @param wait_till_started [I] - Wait until the application firmware is started.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_reset_into_application(
    uint32_t die, 
    bool     wait_till_started);


/**
 * Query the current firmware mode
 *
 * @param die     [I]   - The physical ASIC die being accessed.
 * @param fw_mode [I/O] - The firmware mode.
 *
 * @return IP_OK on success, IP_ERROR on failure
 *
 * @since 0.1
 */
ip_status_t srm_mcu_fw_mode_query(
    uint32_t       die, 
    e_srm_fw_mode* fw_mode);


/**
 * This method may be called to verify that the FW status
 * is ok. If not, a dump of the FW status is performed.
 *
 * To determine if the FW is ok, the following is checked:
 *
 * - Check that it's in application mode (ACC0)
 * - Check that there is no exception
 * - Check that the HL_STATE (FW high-level state) reg is not 0xffff (stuck in startup)
 * - Check that the loop counter is incrementing
 * - Read, wait 10ms, read loop counter again
 * 
 * @param die         [I] - The ASIC die being accessed.
 *
 * @return true when FW ok, false on FW not ok.
 *
 * @since 0.1
 */
bool srm_is_fw_running_ok(
    uint32_t die);


/**
 * This method is called to block waiting for the f/w to be
 * running in application mode. This is useful when switching
 * f/w modes or when programming the application firmware image.
 *
 * @param die           [I] - The ASIC die being accessed.
 * @param timeout_in_ms [I] - The maximum timeout in milli-seconds
 *                            to block waiting for the application image to
 *                            startup.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_block_application_mode(
    uint32_t die,
    int      timeout_in_ms);


/**
 * @h3 Firmware Programming APIs
 * =======================================================
 * There are two ways of programming the embedded application
 * firmware:
 *
 * @table
 * - Method           | Description | Methods
 * - Direct Download  | The firmware image is programmed directly
 *                      to the on-board IRAM/DRAM and the MCU is
 *                      brought out of reset. This download needs
 *                      to happen on every reset. | srm_mcu_download_firmware,
 *                      srm_mcu_download_firmware_from_external_memory,
 *                      srm_mcu_download_firmware_from_file
 *  
 * @brief
 * This method is called to download the firmware inlined
 * with the API directly to the MCUs RAM memory.
 *
 * It will program the microcode on all dies ,
 * jump to the new application image and verify it is
 * running properly.
 *
 * @param die    [I] - The ASIC die being accessed.
 * @param verify [I] - Optionally read back the programmed values
 *                     to verify the results. This is typically
 *                     not required and will slow down the programming
 *                     but is provided for users that want an
 *                     extra integrity check.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must have direct download support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 * - IP_HAS_INLINE_APP_FW
 *
 * @since 0.1
 */
ip_status_t srm_mcu_download_firmware(
    uint32_t die, 
    bool     verify);

/**
 * This method is called to fetch a pointer to the inlined f/w image.
 *
 * @param ptr    [O] - The pointer to the inlined firmware.
 * @param length [O] - The length of the firmware image in 32b words
 *
 * @requires
 * The API must have direct download support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 * - IP_HAS_INLINE_APP_FW
 *
 * @since 0.8
 */
ip_status_t srm_mcu_get_inline_firmware(const uint32_t** ptr, uint32_t* length);


/**
 * Get the inlined f/w version number.
 *
 * @return The inlined f/w version number (if present)
 *
 * @requires
 * The API must be compiled with
 * - IP_HAS_INLINE_APP_FW
 *
 * @since 0.1
 */
uint32_t srm_mcu_get_inline_firmware_version(void);


/**
 * This method may be called to broadcast the firmware download to
 * multiple ASICs.
 *
 * @param die          [I] - The physical ASIC die being accessed.
 * @param get_firmware [I] - A callback method used to fetch the
 *                           firmware to download.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must have direct download support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 * - IP_HAS_INLINE_APP_FW
 *
 * @since 0.8
 */
ip_status_t srm_mcu_direct_download_image_bcast(
    uint32_t die,
    ip_status_t (*get_firmware)(const uint32_t** ptr, uint32_t* length));


/**
 * This is a helper method used to broadcast the inlined firmware
 * to multiple ASICs.
 *
 * @param die  [I] - The physical ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must have direct download support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 * - IP_HAS_INLINE_APP_FW
 *
 * @since 0.8
 */
ip_status_t srm_mcu_direct_download_image_bcast_inline(uint32_t die);


/**
 * This is a helper method used to broadcast a particular image
 * to multiple IPs.
 *
 * @param die  [I] - The physical ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must have direct download support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 *
 * @since 0.10
 */
ip_status_t srm_mcu_direct_download_image_bcast_buffer(
    uint32_t        die,
    const uint32_t* image_ptr,
    uint32_t        length);


/**
 * This wrapper method may be called after programming the firmware to
 * verify the contents of the IRAM/DRAM firmware image. This is primarily
 * for testing via Python
 *
 * @{note, If the f/w is stalled then both the IRAM and DRAM images will
 *         be verified otherwise if the f/w is not stalled then only 
 *         the IRAM image will be verified.
 *
 * @param die          [I] - The ASIC die being accessed.
 *
 * @return IP_OK if the image is ok, IP_ERROR if the image
 *         is not ok.
 *
 * @requires
 * The API must have direct download support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 *
 * @since 0.9
 */
ip_status_t srm_mcu_verify_image_wrapper(
    uint32_t        die);


/**
 * This method may be called after programming the firmware to
 * verify the contents of the IRAM/DRAM firmware image.
 *
 * @{note, If the f/w is stalled then both the IRAM and DRAM images will
 *         be verified otherwise if the f/w is not stalled then only 
 *         the IRAM image will be verified.
 *
 * @param die          [I] - The ASIC die being accessed.
 * @param image        [I] - The pointer to the firmware image to verify
 *                           against.
 * @param image_length [I] - The length of the firmware image in 32b words.
 *
 * @return IP_OK if the image is ok, IP_ERROR if the image
 *         is not ok.
 *
 * @requires
 * The API must have direct download support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 *
 * @since 0.1
 */
ip_status_t srm_mcu_verify_image(
    uint32_t        die,
    const uint32_t* image,
    uint32_t        image_length);


/**
 * This method is called to download the firmware directly
 * to the MCUs RAM memory.
 * It will program the microcode on all dies,
 * jump to the new application image and verify it is
 * running properly.
 *
 * @param die    [I] - The ASIC die being accessed.
 * @param path   [I] - The path to the application firmware
 *                     to program.
 * @param verify [I] - Optionally performs a CRC-32 checksum calculation
 *                     on the programmed firmware and compares this calculated 
 *                     result with the value embedded in the file. This is 
 *                     provided for users that want an extra integrity check.
 *                     Note that for FW versions older than 0.8.468, this flag 
 *                     msut be set to false as this verify is not supported. 
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must have file system support. It must be
 * compiled with the following flags set to 1:
 * - IP_HAS_DIRECT_DOWNLOAD
 * - IP_HAS_FILESYSTEM
 *
 * @since 0.1
 */
ip_status_t srm_mcu_download_firmware_from_file(
    uint32_t    die, 
    const char* path, 
    bool        verify);

/**
 * This method is called to zero initialize the IRAM and DRAM memories
 * to ensure ECC bits are properly initialized
 *
 * @param die    [I] - The ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.14
 */
ip_status_t srm_mcu_ram_init(
    uint32_t die);

/**
 * @h2 Firmware Debug
 * =======================================================
 *
 * @brief
 * This structure is used to gather status information from the MCU
 * for debugging purposes.
 */
typedef struct
{
    /** The firmware mode of operation */
    e_srm_fw_mode fw_mode;
    /** The firmware mode (human readable string) */
    const char*    fw_mode_str;
    /** Is the firmware stalled? */
    bool           runstall;
    /** An array of program counter values */
    uint32_t       pc_trace[10];
    /** An array of main loop counter values */
    uint32_t       loop_count[2];
    /** The delta between loop counters read once per second */
    int            loop_delta;
    /** A rough estimate of the duration of the main loop in micro seconds */
    uint32_t       loop_duration;
    /** Any MDIO address errors that may have been flagged */
    uint32_t       mdio_addr_err;
    
    /** The application firmware version code */
    uint32_t       app_version;
    /** The application firmware major version */
    uint8_t        app_version_major;
    /** The application firmware minor version */
    uint8_t        app_version_minor;
    /** The application firmware patch revision number */
    uint8_t        app_version_revision;
    /** The application firmware build id */
    uint16_t       app_version_build;
    
    /** The API version code (if programmed) */
    uint32_t       api_version;
    /** The API major version (if programmed) */
    uint8_t        api_version_major;
    /** The API minor version (if programmed) */
    uint8_t        api_version_minor;
    /** The API patch revision number (if programmed) */
    uint8_t        api_version_revision;
    /** The API build ID (if programmed) */
    uint16_t       api_version_build;
}srm_mcu_status_t;


/**
 * This method is used to query status information from the on-board
 * MCU for debug purposes
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param mcu_status [I] - The MCU status queried from the hardware.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_status_query(
    uint32_t          die,
    srm_mcu_status_t* mcu_status,
    uint32_t loop_delay);


#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)
/**
 * This method is used to query and display status information from the on-board
 * MCU for debug purposes
 *
 * @param die        [I] - The ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 *
 * @requires
 * The API must be compiled with IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_mcu_status_query_dump(uint32_t die);
#endif //defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)


/**
 * This method fetches a trace of the program counter for debug
 * purposes.
 *
 * @param die         [I] - The physical ASIC being accessed.
 * @param entries     [O] - The allocated buffer to write PC entries to.
 * @param num_entries [I] - The number of entries to fetch.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_pc_log_query(uint32_t die, uint32_t* entries, int num_entries);


#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)    
/**
 * This method is used to dump a trace of the program counter from
 * the MCU for debug purposes.
 *
 * @param die         [I] - The physical ASIC being accessed.
 * @param num_entries [I] - The number of entries to dump.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_pc_log_query_dump(uint32_t die, int num_entries);

// The default MCU debug filter is 0xffffffff ie. all logs enabled.
// The following is a bit map that identifies the log types that can be enabled/disabled.
// Note that this bit map must be kept synchronized with the one in firmware/application/mcu_debug.h.
#define LOG_DEBUG   1 << 0
#define LOG_ERROR   1 << 1
#define LOG_WARN    1 << 2
#define LOG_RX_LOCK 1 << 3
#define LOG_INT     1 << 4
#define LOG_RX_DBG  1 << 5

/**
 * This method is used to print the firmware trace log
 * for debug purposes.
 *
 * @param die         [I] - The physical ASIC being accessed.
 * @param buff        [I] - A buffer containg the log to print
 * @param buff_size   [I] - The size of the buffer
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_debug_log_dump(uint32_t die, char* buff);

/**
 * This method is used to dump the firmware trace log
 * for debug purposes.
 *
 * @param die         [I] - The physical ASIC being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_debug_log_query_dump(uint32_t die);

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)    

/**
 * This method fetches a trace of the program counter for debug
 * purposes.
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param entries     [O] - The allocated buffer to write PC entries to.
 * @param num_entries [I] - The number of entries to fetc.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_pc_log_query(
    uint32_t  die, 
    uint32_t* entries, 
    int       num_entries);

/**
 * This method is called to fetch the current setting of the f/w debug log
 * filter. The filter is used to restrict which log messages get displayed
 * in the firmware log
 *
 * @param die [I] - The physical ASIC die being accessed.
 *
 * @return The filter log message or 0xffffffff if it couldn't be read.
 *
 * @since 0.1
 */
uint32_t srm_mcu_debug_log_filter_get(
    uint32_t die);


/**
 * This method is called to update the current setting of the f/w debug log
 * filter. The filter is used to restrict which log messages get displayed
 * in the firmware log
 *
 * @param die    [I] - The physical ASIC die being accessed.
 * @param filter [I] - The filter to use to filter log messages in the f/w log.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_debug_log_filter_set(
    uint32_t die, 
    uint32_t filter);



#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)    
/**
 * This method is used to dump a trace of the program counter from
 * the MCU for debug purposes.
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param num_entries [I] - The number of entries to dump.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_pc_log_query_dump(
    uint32_t die, 
    int      num_entries);


/**
 * This method is used to dump the firmware trace log
 * for debug purposes.
 *
 * @param die         [I] - The ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_debug_log_query_dump(
    uint32_t die);

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)    


/**
 * @h2 Version Information
 * =======================================================
 *
 * @brief
 * This method is used to retreive the API version string describing
 * the version of the API in use. The user must allocate
 * a buffer of at least 256 bytes to retrieve the version information.
 * 
 * @param buffer     [O] - The output buffer where the version string will
 *                         be stored.
 * @param buffer_len [I] - The length of the allocated buffer. Units are bytes.
 *
 * @return IP_OK on success, IP_ERROR on failure 
 *
 * @since 0.1
 */
ip_status_t srm_version(
    char*    buffer, 
    uint32_t buffer_len);

/**
 * @brief
 * This method is used to retreive the version string describing
 * the version of the firmware in use. The user must allocate
 * a buffer of at least 256 bytes to retrieve the version information.
 *
 * @param die        [I] - TThe ASIC die being accessed.
 * @param buffer     [O] - The output buffer where the version string will
 *                         be stored.
 * @param buffer_len [I] - The length of the allocated buffer. Units are bytes.
 *
 * @return IP_OK on success, IP_ERROR on failure 
 *
 * @since 0.1
 */
ip_status_t srm_version_firmware(
    uint32_t die,
    char*    buffer, 
    uint32_t buffer_len);

/**
 * @h2 Device Configuration
 * =======================================================
 *
 * @brief
 * This method sets up the default tx rules 
 * to simplify the implementation for the user. 
 *
 * @{note,This method initializes the tx rules data-structure, it does 
 * not write to any registers.}
 *
 * @param tx_rules   [O] - The default tx rules
 *
 * @return IP_OK on success, IP_ERROR otherwise
 *
 * @since 0.1
 */
ip_status_t srm_tx_rules_set_default(
    srm_tx_rules_t*  tx_rules);

/**
 * This method sets up the default rx rules 
 * to simplify the implementation for the user. 
 *
 * @{note,This method initializes the rx rules data-structure, it does 
 * not write to any registers.}
 *
 * @param rx_rules   [O] - The default rx rules
 *
 * @return IP_OK on success, IP_ERROR otherwise
 *
 * @since 0.1
 */
ip_status_t srm_rx_rules_set_default(
    srm_rx_rules_t*  rx_rules);


/**
 * This method sets up the default PLL rules 
 * to simplify the implementation for the user. 
 *
 * @{note,This method initializes the PLL rules data-structure, it does 
 * not write to any registers.}
 *
 * @param pll_rules   [O] - The default PLL rules
 *
 * @return IP_OK on success, IP_ERROR otherwise
 *
 * @since 0.1
 */
ip_status_t srm_pll_rules_set_default(
    srm_pll_rules_t*  pll_rules);

/**
 * This method sets up the default PLL, tx and rx rules
 * to simplify the implementation for the user. 
 *
 * @{note,This method initializes the PLL, tx and rx rules data-structures, 
 * it does not write to any registers.}
 *
 * @param pll_rules  [O] - The default pll rules
 * @param tx_rules   [O] - The default tx rules
 * @param rx_rules   [O] - The default rx rules
 *
 * @return IP_OK on success, IP_ERROR otherwise
 *
 * @since 0.1
 */
ip_status_t srm_rules_set_default(
    srm_pll_rules_t* pll_rules, 
    srm_tx_rules_t* tx_rules, 
    srm_rx_rules_t* rx_rules);

/**
 * A helper method used to copy the PLL rules to
 * hardware registers.
 *
 * @param die       [I] - The IP to access
 * @param pll_rules [I] - The PLL rules to copy to hardware registers
 *
 * @since 0.1
 */
ip_status_t srm_pll_cp_rules_to_overlays(
    uint32_t         die, 
    srm_pll_rules_t* pll_rules);

/**
 * A helper method used to copy the RX rules to
 * hardware registers.
 *
 * @param die      [I] - The IP to access
 * @param channel  [I] - The RX channel to access
 * @param rx_rules [I] - The RX rules to copy to hardware registers
 *
 * @since 0.1
 */
ip_status_t srm_rx_cp_rules_to_overlays(
    uint32_t        die,
    uint32_t        channel,
    srm_rx_rules_t* rx_rules);

/**
 * A helper method used to copy the TX rules to
 * hardware registers.
 *
 * @param die      [I] - The IP to access
 * @param channel  [I] - The TX channel to access
 * @param tx_rules [I] - The TX rules to copy to hardware registers
 *
 * @since 0.1
 */
ip_status_t srm_tx_cp_rules_to_overlays(
    uint32_t        die,
    uint32_t        channel,
    srm_tx_rules_t* tx_rules);


/**
 * Initializes the device with the universal ID
 *
 * @param die                   [I] - The ASIC die being accessed.
 * @param uid                   [I] - All devices with the same ERU should have the same
 *                                    upper 11-bits, i.e [15:5].
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.14
 */
ip_status_t srm_init_uid(
    uint32_t die,
    uint16_t uid
);


/**
 * Reset the device to have it ready for any user config, 
 * and then call srm_init_tx, srm_init_rx.
 *
 * @param die                   [I] - The ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_init(
    uint32_t  die);

/**
 * This method is called to configure the PLL.
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param pll_rules  [I] - The PLL rules structure
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_init_pll(
    uint32_t die,
    srm_pll_rules_t* pll_rules);

/**
 * This method is called to configure a Tx channel.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param tx_rules [I] - The Tx configuration rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_init_tx(
    uint32_t die,
    uint32_t channel,
    srm_tx_rules_t* tx_rules);

/**
 * This method is called to configure an Rx channel.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param rx_rules [I] - The Rx configuration rules.
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_init_rx(
    uint32_t die,
    uint32_t channel,
    srm_rx_rules_t* rx_rules);


/**
 * RX Parameters that are not configurable by
 * the RX rules.
 */
typedef enum
{
    /** Signal detect fall value (0-31) */
    SRM_RX_PARAM_SDT_CODE_FALL = 0,
    /** Signal detect rise value (0-31) */
    SRM_RX_PARAM_SDT_CODE_RISE = 1,
    /** Signal detect code threshold (0-31) */
    SRM_RX_PARAM_SDT_CODE_TH   = 2,
    /** Signal detect block count */
    SRM_RX_PARAM_SDT_BLOCK_CNT = 4
}e_srm_rx_param;


/**
 * This method is used to tune a parameter associated
 * with the RX that isn't available in the RX rules structure.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param param    [I] - The parameter to tweak.
 * @param value    [I] - The value to set the parameter t.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_rx_param_set(
    uint32_t       die,
    uint32_t       channel,
    e_srm_rx_param param,
    uint32_t       value);


/**
 * This method is called to see if the FW has asserted the acknowledge
 *
 * @{note, This method is non-blocking. It will read the hardware to
 *   see if the ACK is asserted and return immediately. Use the
 *   wait_for_ack methods to block waiting for a maximum period
 *   of time for the ACK to be asserted.}
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param ack_type [I] - The ACK type (see e_srm_ack_type enum)
 * 
 * @return True if acknowleged, False otherwise
 *
 * @since 0.1
 */
bool srm_is_ack_asserted(
    uint32_t die, 
    uint32_t channel, 
    e_srm_ack_type ack_type);

/**
 * This method is called to block wait for the FW to assert an ACK
 *
 * @{warning, This method is blocking. It will poll the
 *   hardware for up to max_wait_ms mill-seconds until
 *   the ACK is asserted or the operation times out.
 *   Use the is_ack_asserted methods to avoid blocking}
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * @param ack_type    [I] - The ACK type bit mask (see e_srm_ack_type enum)
 * @param max_wait_ms [I] - Maximum wait for an ACK (units are in micro-seconds)
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_wait_for_ack(
    uint32_t die, 
    uint32_t channel, 
    uint16_t ack_type, 
    uint32_t max_wait_us);


/**
 * This method is called to synchronize the PLL rules with the overlays
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param pll_rules [O] - The PLL rules structure
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_pll_rules_query(
    uint32_t         die,
    srm_pll_rules_t* pll_rules);

/**
 * This method is called to synchronize the Tx rules with the overlays
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param channel   [I] - The channel to access
 * @param tx_rules  [O] - The Tx rules structure
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_rules_query(
    uint32_t        die,
    uint32_t        channel,
    srm_tx_rules_t* tx_rules);

/**
 * This method is called to synchronize the Rx rules with the overlays
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param channel   [I] - The channel to access
 * @param rx_rules  [O] - The Rx rules structure
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_rx_rules_query(
    uint32_t        die,
    uint32_t        channel,
    srm_rx_rules_t* rx_rules);


/**
 * This is an option soft reset that asserts the MMD08_PMA_CONTROL.RESET
 * bit. The user should normally assert the reset pin instead of hitting
 * the soft reset.
 *
 * @param die [I] - The ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_soft_reset(
    uint32_t die);

#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)    


/**
 * This is a debug method used to dump the PLL configuration rules.
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param pll_rules  [I] - The PLL rules structure
 *
 * @since 0.1
 
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
void srm_pll_rules_dump(
    uint32_t         die,
    srm_pll_rules_t* pll_rules);

/**
 * This is a debug method used to query then dump the PLL configuration rules.
 *
 * @param die      [I] - The ASIC die being accessed.
 *
 * @since 0.1
 
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_pll_rules_query_dump(
    uint32_t die);

/**
 * This is a debug method used to dump the Tx configuration rules.
 *
 * @param die       [I] - The ASIC die being accessed.
 * @param channel   [I] - The channel being accessed.
 * @param tx_rules  [I] - The Tx rules structure
 *
 * @since 0.1
 * 
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
void srm_tx_rules_dump(
    uint32_t        die,
    uint32_t        channel,
    srm_tx_rules_t* tx_rules);

/**
 * This is a debug method used to query then dump the Tx configuration rules.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 *
 * @since 0.1
 * 
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_tx_rules_query_dump(
    uint32_t die,
    uint32_t channel);

/**
 * This is a debug method used to dump the Rx configuration rules.
 *
 * @param die       [I] - The ASIC die being accessed.
 * @param channel   [I] - The channel being accessed.
 * @param rx_rules  [I] - The Tx rules structure
 *
 * @since 0.1
 * 
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
void srm_rx_rules_dump(
    uint32_t        die,
    uint32_t        channel,
    srm_rx_rules_t* rx_rules);

/**
 * This is a debug method used to query then dump the Rx configuration rules.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 *
 * @since 0.1
 * 
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_rx_rules_query_dump(
    uint32_t die,
    uint32_t channel);

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)

/**
 * @h2 Device Power-up and Calibration
 * =======================================================
 *
 * @brief
 * This method configures the rules to their default values
 *
 * @param pwrup_rules  [I/O] - A pointer to a power up rules structure.
 *
 * @return IP_OK on success, IP_ERROR otherwise.
 *
 * @since 0.1
 */
ip_status_t srm_pwrup_rules_set_default(
    srm_pwrup_rules_t*  pwrup_rules);


/**
 * This method starts the regulator power-up process of the device
 *
 * @param pwrup_rules  [I] - A pointer to the regulator rules structure.
 *
 * @return IP_OK on success, IP_ERROR otherwise.
 *
 * @since 0.1
 */
ip_status_t srm_pwrup_start(
    srm_pwrup_rules_t* pwrup_rules);

/**
 * Check to see if the BIAS is in service
 *
 * @param die [I] - The die representing the IP to access
 *
 * @return true if the BIAS block is in service, false otherwise.
 */
bool srm_pwrup_is_bias_ready(uint32_t die);

/**
 * Check to see if the ERU is in service
 *
 * @param die [I] - The die representing the IP to access
 *
 * @return true if the ERU block is in service, false otherwise.
 */
bool srm_pwrup_is_eru_ready(uint32_t die);

/**
 * Check to see if the whole regulator chain is in service
 *
 * @param die [I] - The die representing the IP to access
 *
 * @return true if the regulators are in service, false otherwise.
 */
bool srm_pwrup_is_ready(srm_pwrup_rules_t* rules);

#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)
/**
 * This is a diagnostic method used to display the Powerup rules
 * configuration.
 *
 * @param pwrup_rules  [I] - A pointer to a power up rules structure.
 *
 */
void srm_pwrup_rules_dump(srm_pwrup_rules_t *p_pwrup_rules);
#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)

/**
 * This is an internal method used to manually power up the LDOs
 * in an alternate configuration. Normally this method is not
 * called direclty and srm_pwrup_start is used instead.
 *
 * @param die  [I] - The ASIC die being accessed.
 * @param mode [I] - The LDO powerup mode.
 * @param show [I] - A diagnostic flag to turn on or off debug messages.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_pwrup_bias_qpmp_ldo_pwrup(
    uint32_t         die,
    e_srm_pwrup_mode mode,
    bool             show);

/**
 * This method fetches the R-cal status from the IP chain when FW
 * stalls, after the regulator power-up process of the device.
 *
 * @param pwrup_rules  [I] - A pointer to the regulator rules structure.
 * @param rcal_status  [O] - The R-Cal status structure
 *
 * @return IP_OK on success, IP_ERROR otherwise.
 *
 * @since 0.30
 */
ip_status_t srm_cal_rcal_status_query(
    srm_pwrup_rules_t* pwrup_rules,
    srm_rcal_status_t* rcal_status);

/* Legacy method for backward compatibility */
ip_status_t srm_cal_rules_set_default(srm_cal_rules_t*  cal_rules);
ip_status_t srm_cal_start(srm_cal_rules_t* cal_rules);
bool srm_cal_is_bias_ready(uint32_t die);
bool srm_cal_is_eru_ready(uint32_t die);
bool srm_cal_is_ready(srm_cal_rules_t* rules);


/**
 * @h2 Loopback Management
 * =======================================================
 *
 * @brief
 * The following enumerations define the available loopbacks
 * that can be applied to the device.
 *
 * @since 0.1
 */
typedef enum
{
    /** Core Near Loopback */
    SRM_LOOPBACK_CORE_NEAR  = 1,
    /** Serial Far Loopback */
    SRM_LOOPBACK_SERIAL_FAR = 2,

}e_srm_loopback_mode;

/**
 * This method is called to enable/disable a loopback
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * @param type        [I] - The loopback type
 * @param enable      [I] - Enable/disable flag
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_loopback_set(
    uint32_t            die,
    uint32_t            channel,
    e_srm_loopback_mode type,
    bool                enable);


/**
 * @h2 Reading the Link Status
 * The following methods are used to determine the link status including the
 * PLL, RX and TX path status.
 *
 * @brief
 * This method is used to wait for all channel
 * to be in the receive ready state where they are ready to receive
 * traffic. This is state information is polled from the on-board
 * firmware.
 *
 * @{note,
 *   The timeout may be longer than the input specified as the
 *   overhead of accessing registers will increase the time}
 *
 * @param die              [I] - The physical ASIC die being accessed.
 * @param channel          [I] - The channel being accessed.
 * @param timeout_in_usecs [I] - The amount of time to wait for all
 *                               channels to be ready in micro-seconds.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_wait_for_link_ready(
    uint32_t die, 
    uint32_t channel,
    int      timeout_in_usecs);


/**
 * This method is called to determine whether a channel
 * is in the link up state.
 *
 * @param die       [I] - The ASIC die being accessed.
 * @param channel   [I] - The channel being accessed.
 * @param intf      [I] - The interface of the channel ie. SRM_INTF_DIR_RX or SRM_INTF_DIR_TX
 *
 * @return true if the link is up, false if the link is down.
 *
 * @since 0.1
 */
bool srm_is_link_ready(
    uint32_t         die,
    uint32_t         channel,
    e_srm_intf       intf);


/**
 * This method is called to determine whether the PLL is locked.
 *
 * @param die       [I] - The ASIC die being accessed.
 *
 * @return true if the PLL is locked, false if the PLL is not locked.
 *
 * @since 0.1
 */
bool srm_is_pll_locked(
    uint32_t   die);
 

/**
 * This method is used to wait for the PLL to complete initialization
 *
 * @{note,
 *   The timeout may be longer than the input specified as the
 *   overhead of accessing registers will increase the time}
 *
 * @param die              [I] - The physical ASIC die being accessed.
 * @param timeout_in_usecs [I] - The amount of time to wait for the
 *                               PLL to lock.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.2
 */
ip_status_t srm_wait_for_pll_locked(
    uint32_t die, 
    int      timeout_in_usecs);

/**
 * This method is called to get the Tx link ready status
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * 
 * @return True on Tx ready, False otherwise.
 *
 * @since 0.2
 */
bool srm_is_tx_ready(
    uint32_t die,
    uint32_t channel);

/**
 * This method is called to determine whether the
 * TX path is ready to transmit.
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * 
 * @return true if the TX is ready to transmit, False otherwise.
 *
 * @deprecated Use srm_is_tx_ready instead
 *
 * @since 0.1
 */
bool srm_tx_ready_get(
    uint32_t die,
    uint32_t channel);

/**
 * This method is called to determine whether the RX
 * path is ready to receive traffic.
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * 
 * @return true if the RX is ready to receive, False otherwise.
 *
 * @since 0.2
 */
bool srm_is_rx_ready(
    uint32_t die,
    uint32_t channel);

/**
 * This method is called to get the Rx link ready status
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * 
 * @return True on Tx ready, False otherwise.
 *
 * @deprecated Use srm_is_rx_ready instead.
 *
 * @since 0.1
 */
bool srm_rx_ready_get(
    uint32_t die,
    uint32_t channel);


/**
 * Link status
 */
typedef struct
{
    // TX
    /** Channel is locked and ready to pass traffic */
    bool tx_fw_lock;
    /** PLL lock */
    bool tx_pll_lock;

    // RX
    /** Signal detect */
    bool rx_sdt;
    /** DSP ready */
    bool rx_dsp_ready;
    /** Channel is locked and ready to pass traffic */
    bool rx_fw_lock;
    /** PLL lock */
    bool rx_pll_lock;

    // Interrupts
    /** RX PLL lock detect interrupt */
    bool rx_pll_lockdet_int;

    /** TX PLL lock detect interrupt */
    bool tx_pll_lockdet_int;

    /** TX FIFO A empty interrupt */
    bool tx_fifoa_empty_int;
    /** TX FIFO A full interrupt */
    bool tx_fifoa_full_int;

    /** TX FIFO B empty interrupt */
    bool tx_fifob_empty_int;
    /** TX FIFO B full interrupt */
    bool tx_fifob_full_int;

} srm_link_status_t;
 

/**
 * This method may be called to query the current link status 
 * of the interfaces of the device.
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * @param intf        [I] - The interface of the channel ie. SRM_INTF_DIR_RX or SRM_INTF_DIR_TX
 * @param link_status [O] - Pointer to the link status.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_link_status_query(
    uint32_t   die, 
    uint32_t   channel,
    e_srm_intf intf,
    srm_link_status_t* link_status);



#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && IP_HAS_DIAGNOSTIC_DUMPS == 1
/**
 * This method may be called to print the current link status 
 * of the interfaces of the device.
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * @param intf        [I] - The interface of the channel ie. SRM_INTF_DIR_RX or SRM_INTF_DIR_TX
 * @param link_status [I] - Pointer to the link status.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 *
 * @since 0.1
 */
ip_status_t srm_link_status_print(
    uint32_t           die, 
    uint32_t           channel,
    e_srm_intf         intf,
    srm_link_status_t* link_status);

/**
 * This method may be called to query then print the current link status 
 * of the interfaces of the device.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel being accessed.
 * @param intf    [I] - The interface of the channel ie. SRM_INTF_DIR_RX or SRM_INTF_DIR_TX
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 *
 * @since 0.1
 */
ip_status_t srm_link_status_query_dump(
    uint32_t    die,
    uint32_t    channel, 
    e_srm_intf  intf);
#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1) 


/** 
 * @h2 RX Management
 * =======================================================
 * @brief
 * This method is called to configure the Rx encoding.
 *
 * @{warning,
 * Configures the signalling, gray mapping. 
 * This is currently done in srm_init_rx.}
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param channel    [I] - The channel being accessed.
 * @param signalling [I] - The Rx signalling ie. NRZ or PAM4.
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_rx_encoding_set(
    uint32_t die,
    uint32_t channel, 
    e_srm_signal_mode signalling);


/**
 * This method is called to configure the Rx polarity.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param inv_pol  [I] - Flag to enable/disable Rx polarity inversion.
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_rx_polarity_set(
    uint32_t die,
    uint32_t channel,
    bool     inv_pol);


/**
 * This method is called to power-down the selected Rx channel.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * 
 * @note
 * This method powers-down the receiver.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_rx_power_down_set(
    uint32_t die,
    uint32_t channel);


/**
 * This method is called to configure the Rx equalization.
 *
 * @{warning,
 * Configure the Rx DSP mode. Currently this is done in srm_init_rx.}
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param dsp_mode [I] - The Rx DSP mode.
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_rx_equalization_set(
    uint32_t die,
    uint32_t channel,
    e_srm_dsp_mode dsp_mode);


/**
 * This is a diagnostic method that is called to toggle the current invert
 * status of the RX channel after it has been configured. This is sometimes
 * useful when trying to determine the hardware inversions to fix PCS alignment
 * issues.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The physical channel to toggle the invert for.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_rx_invert_toggle(
    uint32_t         die,
    uint32_t         channel);


/**
 * Force a DSP relock on the target interface. This can be used for debugging
 * or when there are significant changes to the link without a loss of data.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The physical RX channel to relock
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_dbg_force_dsp_relock(
    uint32_t          die,
    uint32_t          channel);


/**
 * @h2 TX Management
 * =======================================================
 *
 * @brief
 * This method sets up the default tx FIR settings 
 * to simplify the implementation for the user. 
 *
 * @{note,This method initializes the tx FIR data-structure, it does 
 * not write to any registers.}
 *
 * @param tx_fir   [O] - The default tx FIR settings
 *
 * @return IP_OK on success, IP_ERROR otherwise
 *
 * @since 0.1
 */
ip_status_t srm_tx_fir_set_default(
    srm_tx_fir_t*  tx_fir);


/**
 * Update the TX configuration for a particular channel (including the Tx FIR).
 *
 * @param die              [I] - The physical ASIC die being accessed.
 * @param channel          [I] - The channel through the device to change.
 * @param rules            [I] - The rules to apply to re-configure the channel.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_set(
    uint32_t        die, 
    uint32_t        channel, 
    srm_tx_rules_t* rules);

/**
 * This method is called to configure the Tx encoding.
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param channel    [I] - The channel being accessed.
 * @param signalling [I] - The signalling ie. NRZ or PAM4
 * 
 * @note
 * Configures the signalling, gray mapping. 
 * This is currently done in srm_init_tx.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_encoding_set(
    uint32_t die,
    uint32_t channel,  
    e_srm_signal_mode signalling);

/**
 * This method is called to configure the Tx polarity.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param inv_pol  [I] - Flag to enable/disable Tx polarity inversion.
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_polarity_set(
    uint32_t die,
    uint32_t channel,
    bool     inv_pol);

/**
 * This method is called to configure Tx equalization.
 *
 * @{warning,
 * Configure the Tx FIR setting. Currently this is also done on srm_init_tx}
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * @param fir_tap  [I] - An array of 7 tap values. Note that in 3-Tap mode
 *                       fir_tap[0] = pre-Tap, fir_tap[1] = main-Tap and fir_tap[2] = post-Tap.
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_equalization_set(
    uint32_t die,
    uint32_t channel, 
    int16_t fir_tap[7]);

/**
 * This method is called to power-down the selected Tx channel.
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param channel  [I] - The channel being accessed.
 * 
 * @note
 * This method powers-down the transmitter.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_power_down_set(
    uint32_t die,
    uint32_t channel);

/**
 * This method may be called to query the current configuration of the
 * transmitters from the ASIC.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The channel through the device to query.
 * @param rules   [O] - The configuration for the transmitter read back from the hardware.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.2
 */
ip_status_t srm_tx_fir_query(uint32_t die, uint32_t channel, srm_tx_fir_t* fir);

/**
 * Update the TX FIR configuration for a particular channel.
 *
 * @{warning, In this release the programming of the lookup table
 *            is not atomic so the transmit output may be non-deterministic
 *            when changing the FIR. It is recommended to squelch the
 *            transmit output when changing the TX FIR using the
 *            srm_tx_squelch method.}
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The channel through the device to change.
 * @param fir     [I] - The rules to apply to re-configure the channel.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.2
 */
ip_status_t srm_tx_fir_set(uint32_t die, uint32_t channel, srm_tx_fir_t* fir);



#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1) 
/**
 * This method is called to dump the contents TAP TX LUT table on the device
 * for debugging purposes.
 *
 * @param tx_rules [I] - The Tx rules to dump
 *
 * @since 0.1
 *
 * @requires
 * The API must be compiled with:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1 
 */
void srm_tx_fir_tap_dump(
    srm_tx_fir_t* tx_fir);


/**
 * This method is called to query then dump the contents 7-TAP TX linear table on the device
 * for debugging purposes.
 *
 * @param die              [I] - The physical ASIC die being accessed.
 *
 * @since 0.1
 *
 * @requires
 * The API must be compiled with:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1 
 */
void srm_tx_fir_7tap_lin_query_dump(
    uint32_t die);

/**
 * This method is called to query then dump the contents 3-TAP TX LUT table on the device
 * for debugging purposes.
 *
 * @param die              [I] - The physical ASIC die being accessed.
 * @param channel          [I] - The channel through the device to change.
 *
 * @since 0.1
 *
 * @requires
 * The API must be compiled with:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1 
 */
void srm_tx_fir_3tap_lut_query_dump(
    uint32_t die, 
    uint32_t channel);

// /**
//  * Query then dump the TX configuration.
//  *
//  * @param die     [I] - The physical ASIC die being accessed.
//  * @param channel [I] - The channel to access
//  *
//  * @return IP_OK on success, IP_ERROR on failure.
//  *
//  * @since 0.1
//  *
//  * @requires
//  * The API must be compiled with
//  * - IP_HAS_DIAGNOSTIC_DUMPS=1
//  */
// ip_status_t srm_tx_query_dump(
//     uint32_t          die, 
//     uint32_t          channel); 

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1) 

/**
 * This method is used to query whether or not a particular
 * channel is currently in the squelched state.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The channel through the device to query
 *
 * @return true if the TX is squelched, false if it is not.
 *
 * @since 0.1
 */
bool srm_tx_is_squelched(
    uint32_t   die,
    uint32_t   channel);


/**
 * This method squelches/un-squelches the Tx channel
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The channel through the device to query
 * @param enable  [I] - Squelch flag, true or false
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_squelch(
    uint32_t   die,
    uint32_t   channel,
    bool       squelch);


/**
 * This method squelches/un-squelches the Tx channel
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The channel through the device to query
 * @param enable  [I] - Squelch flag, true or false
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
 ip_status_t srm_tx_squelch_set(
    uint32_t   die,
    uint32_t   channel, 
    bool       enable);


/**
 * This is a diagnostic method that is called to toggle the current invert
 * status of the TX channel after it has been configured. This is sometimes
 * useful when trying to determine the hardware inversions to fix PCS alignment
 * issues.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The physical channel to toggle the invert for.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_tx_invert_toggle(
    uint32_t          die,
    uint32_t          channel);




/**
 * @h2 PRBS Generator/checker
 * =======================================================
 *
 * @brief
 * PRBS synthetic pattern types.
 *
 * @{note,
 * The value of these PRBS polynomial types are abstracted from the hardware because
 * the Serial side checker config is different from the other checkers and 
 * generators config. For this reason we use a common
 * enum decoupled from the hardware (ie synthetic) to enumerate the pattern types.}
 */
typedef enum
{

    /** PRBS x^7 + x^6 + 1 */
    SRM_PAT_PRBS7  = 0,
    /** PRBS x^9 + x^4 + 1 */
    SRM_PAT_PRBS9_4 = 1,
    /** PRBS x^9 + x^5 + 1 */
    SRM_PAT_PRBS9_5 = 2,
    /** PRBS x^11 + x^9 + 1 */
    SRM_PAT_PRBS11 = 3,
    /** PRBS x^13 + x^12 + x^2 + x + 1 */
    SRM_PAT_PRBS13 = 4,
    /** PRBS x^15 + x^4 + 1 */
    SRM_PAT_PRBS15 = 5,
    /** PRBS x^16 + x^4 + 1 */
    SRM_PAT_PRBS16 = 6,
    /** PRBS x^23 + x^18 + 1 */
    SRM_PAT_PRBS23 = 7,
    /** PRBS x^31 + x^28 + 1 */
    SRM_PAT_PRBS31 = 8,
    /** PRBS x^58 + x^39 + 1*/
    SRM_PAT_PRBS58 = 9,
    /** Invalid PRBS pattern */ 
    SRM_PAT_NONE = 10

} e_srm_prbs_pat;

/**
 * Tx PRBS pattern modes 
 */
typedef enum
{
    /** PRBS pattern modes */
    SRM_PRBS_PATTERN_PRBS   = 0,
    /** Programmable fixed pattern mode */
    SRM_PRBS_PATTERN_FIXED  = 1,
    /** JP03B test pattern. IEEE 802.3bs Clause 120.5.10.2.2*/
    SRM_PRBS_PATTERN_JP083B = 2,
    /** Transmitter linearity test pattern. IEEE 802.3bs Clause 120.5.10.2.4 */
    SRM_PRBS_PATTERN_LIN    = 3,
    /** CID jitter tolerance test pattern. OIF-CEI-3.1 Sections 2.1.1.1 and 2.5.1.1 */
    SRM_PRBS_PATTERN_CJT    = 4,
    /** SSPRQ pattern, IEEE 802.3bs Clause 120.5.11.2.3 */
    SRM_PRBS_PATTERN_SSPRQ  = 5

} e_srm_prbs_pat_mode;

/**
 * Rx PRBS checker modes
 */
typedef enum
{
    /** PRBS mode for individual MSB/LSB bit streams in a PAM-4 symbol */
    SRM_PRBS_MODE_MSB_LSB   = 0,
    /** PRBS mode for a combined PAM-4 symbol */
    SRM_PRBS_MODE_COMBINED  = 1

} e_srm_prbs_chk_mode;

/**
 * Tx error injection patterns
 */
typedef enum
{
    /** Bit 0 (one MSB). 0x0000_0000_0000_0001 */
    SRM_ERRINJ_PAT_BIT0  = 0,
    /** Bit 1 (one LSB). 0x0000_0000_0000_0002 */    
    SRM_ERRINJ_PAT_BIT1  = 1,
    /** Bits 0 and 1 (one PAM4 symbol). 0x0000_0000_0000_0003 */
    SRM_ERRINJ_PAT_BIT01 = 2,
    /** All MSBs. 0x5555_5555_5555_5555 */    
    SRM_ERRINJ_PAT_MSBS  = 3,
    /** All LSBs. 0xAAAA_AAAA_AAAA_AAAA */    
    SRM_ERRINJ_PAT_LSBS  = 4,
    /** All bits. 0xFFFF_FFFF_FFFF_FFFF */    
    SRM_ERRINJ_PAT_ALL   = 5, 
    /** One bit per word. The position shifts right each time an error is injected */    
    SRM_ERRINJ_PAT_WALK  = 6, 
    /** One 2-bit PAM4 symbol per word. The position shift right two bits each time an error is injected */
    SRM_ERRINJ_PAT_WALK3 = 7 

} e_srm_prbs_err_inj_pat;

/**
 * This structure is used to configure one
 * of the pattern generators on the device.
 */
typedef struct 
{
    /**
     * In combined mode this enables
     * the PRBS generator.
     *
     * In MSB/LSB mode this enables the LSB/MSB pattern
     * generation.
     */
    bool en;

    /**
     * If operating in MSB/LSB mode this enables
     * the MSB/LSB pattern. These will generally
     * be enabled at the same time but can be controlled
     * independently if required.
     */
    bool gen_en_lsb;

    /**
     * Setup the pattern generator to operate in
     * either MSB/LSB or Combined mode:
     */
    e_srm_prbs_chk_mode prbs_mode;

    /** The LSB PRBS pattern to transmit */
    e_srm_prbs_pat prbs_pattern_lsb;

    /** The PRBS pattern to transmit */
    e_srm_prbs_pat prbs_pattern;

    /** * Selects the type of test pattern that is generated. */
    e_srm_prbs_pat_mode pattern_mode;

    /** Specifies the fixed pattern word value that the fixed pattern checker attempts to lock to. 
     *  Bit 63 is expected to be received first. The default corresponds to the JP03A pattern described 
     *  in IEEE 802.3bs Clause 120.5.10.2.1. */

    /** PRBS Seed (Even) Configuration:
     *  This is the seed used when re-seeding (re-seeding is an optional feature).  The bit positions used for 
     *  each PRBS polynomial order are shown below.  Ensure at least one bit of the seed being used is High.
     *  The seed itself does not come out of the generator, instead the seed represents previously generated bits.  
     *  So the first bit of generator output is based off the seed bits, but does not equal the seed bits.  
     *  The seed is LSB first, meaning the LSB of the seed represents the oldest previously generated bit and 
     *  the MSB of the seed represents the nevest previously generated bit.
     *  This even seed is applied when GEN_PRBS_SEED_CFG__reseed_evn is High in two cases:
     *  
     *  1) Rising edge of GEN_PRBS_SEED_CFG__reseed.
     *  2) GEN_CFG__prbs_mode changes and GEN_PRBS_SEED_CFG__reseed is High.
     *  
     *  PRBS order 7  use bits 57:51
     *  PRBS order 9  use bits 57:49
     *  PRBS order 11 use bits 57:47
     *  PRBS order 13 use bits 57:45
     *  PRBS order 15 use bits 57:43
     *  PRBS order 16 use bits 57:42
     *  PRBS order 23 use bits 57:35
     *  PRBS order 31 use bits 57:27
     *  PRBS order 58 use bits 57:0
     *  
     *  Fixed Pattern Value 0 Configuration:
     *  One of the fixed pattern word values. Bit 63 of this pattern is transmitted first. The fixed pattern consists 
     *  of two 64-bit words, each repeated a configurable number of times. The default fixed pattern is the 
     *  JP03A pattern described in IEEE 802.3bs Clause 120.5.10.2.1. */
    uint16_t seed_evn_0;
    uint16_t seed_evn_1;
    uint16_t seed_evn_2;
    uint16_t seed_evn_3;

    /** PRBS Seed (Odd) Configuration:
     *  This is the seed used when re-seeding (re-seeding is an optional feature).  The bit positions used for 
     *  each PRBS polynomial order are shown below.  Ensure at least one bit of the seed being used is High.
     *  The seed itself does not come out of the generator, instead the seed represents previously generated bits.  
     *  So the first bit of generator output is based off the seed bits, but does not equal the seed bits.  
     *  The seed is LSB first, meaning the LSB of the seed represents the oldest previously generated bit and 
     *  the MSB of the seed represents the nevest previously generated bit.
     *  This odd seed is applied when GEN_PRBS_SEED_CFG__reseed_odd is High in two cases:
     *  1) Rising edge of GEN_PRBS_SEED_CFG__reseed.
     *  2) GEN_CFG__prbs_mode changes and GEN_PRBS_SEED_CFG__reseed is High.
     *  PRBS order 7  use bits 57:51
     *  PRBS order 9  use bits 57:49
     *  PRBS order 11 use bits 57:47
     *  PRBS order 13 use bits 57:45
     *  PRBS order 15 use bits 57:43
     *  PRBS order 16 use bits 57:42
     *  PRBS order 23 use bits 57:35
     *  PRBS order 31 use bits 57:27
     *  PRBS order 58 use bits 57:0
     *  
     *  Fixed Pattern Value 1 Configuration:
     *  One of the fixed pattern word values. Bit 63 of this pattern is transmitted first. The fixed pattern consists 
     *  of two 64-bit words, each repeated a configurable number of times. */
    uint16_t seed_odd_0;
    uint16_t seed_odd_1;
    uint16_t seed_odd_2;
    uint16_t seed_odd_3;

} srm_prbs_gen_rules_t;

/**
 * PRBS checker auto-polarity thresholds on the core 
 */
typedef enum
{
    /** More than 9 consecutive 64 bit words with one or more errors each */
    SRM_PRBS_AUTO_POLARITY_9   = 0,
    /** More than 17 consecutive 64 bit words with one or more errors each */
    SRM_PRBS_AUTO_POLARITY_17  = 1,
    /** More than 33  consecutive 64 bit words with one or more errors each */
    SRM_PRBS_AUTO_POLARITY_33  = 2,
    /** More than 65 consecutive 64 bit words with one or more errors each */
    SRM_PRBS_AUTO_POLARITY_65  = 3,

} e_srm_rx_prbs_auto_pol_thresh;

/** 
 * rules specific to the core rx checker
 */
typedef struct
{

    /** Enables the auto polarity detection feature of the PRBS checker. After a consecutive number of 
      * errors (programmable by auto_polarity_thresh) the polarity is inverted. */
    bool auto_polarity_en;

    /** When out of sync this controls the threshold for toggling the receive data polarity in auto 
     *  polarity mode. Every 64 bits (a "word") is checked for an error and if a certain number of 
     *  consecutive words contain errors then the polarity is toggled. In NRZ mode a word is 64 bits
     *  and in PAM4 mode a word is 32 symbols, i.e. 64 bits too. Caution: the alignment of serial bits
     *  to words is effectively random so, for example, two errors 10 bits apart may look like one
     *  word with two errors or two consecutive words with one error each.
     *      Value     Symbol                              Description
     *      2'd0  AUTO_POLARITY_9  More than 9 consecutive 64 bit words with one or more errors each
     *      2'd1  AUTO_POLARITY_17  More than 17 consecutive 64 bit words with one or more errors each
     *      2'd2  AUTO_POLARITY_33  More than 33 consecutive 64 bit words with one or more errors each
     *      2'd3  AUTO_POLARITY_65  More than 65 consecutive 64 bit words with one or more errors each */
    e_srm_rx_prbs_auto_pol_thresh auto_polarity_thresh;

    /** Selects the type of test pattern that is generated. */
    e_srm_prbs_pat_mode pattern_mode;

    /** Specifies the fixed pattern word value that the fixed pattern checker attempts to lock to. 
     *  Bit 63 is expected to be received first. The default corresponds to the JP03A pattern described 
     *  in IEEE 802.3bs Clause 120.5.10.2.1. */
    uint16_t fixed_pat0;
    uint16_t fixed_pat1;
    uint16_t fixed_pat2;
    uint16_t fixed_pat3;

    /** Controls the number of bit errors in one parallel data bus sample that cause a transition to the 
     * out of sync state. If more errors are found in one cycle than this value the transition occurs. 
     * Applies to the PRBS and fixed pattern checker state machines. Note that the alignment of the 
     * received data to the 64-bit word boundaries is not predictable. So, for example, two adjacent 
     * errors in the incoming serial stream may show up in one 64-bit word (which will declare two mismatches 
     * in that word) or may show up in two consecutive 64-bit words (each of which will declare just one mismatch). */
    uint8_t oos_thresh;                                          

} srm_prbs_chk_core_rules_t;


/** 
 * rules specific to the serial rx checker
 */
typedef struct
{

    /** Error threshold of PRBS interrupt */    
    uint8_t prbs_err_th_irq;

    /** enable PRBS auto lock mode */
    bool prbs_auto_lock;

    /** Threshold of number of errors for PRBS lock Note: Must be non-zero values */
    uint8_t prbs_err_th_lock;

    /** Threshold of number of cycles for PRBS lock */
    uint8_t prbs_cyc_th_lock;

} srm_prbs_chk_serial_rules_t;


/**
 * Rx PRBS checker rules
 */
typedef struct
{
    /** Enables the PRBS checker. */
    bool en;

    /** Enables separate PRBS generation on MSB and LSB bits (PAM4 MSB and LSB). When 0, a single 
      * PRBS stream is generated. */
    e_srm_prbs_chk_mode prbs_mode;

    /** Inverts the receive bit pattern ahead of the PRBS checker if auto polarity is not enabled. */
    bool prbs_inv;

    /** Selects the PRBS polynomial for LSB bits (PAM4 symbol LSB) when dual PRBS mode is enabled. */
    e_srm_prbs_pat prbs_pattern_lsb;

    /** Selects the PRBS polynomial when not in dual PRBS mode or for MSB bits when in dual PRBS mode 
      * (PAM4 symbol MSB) */
    e_srm_prbs_pat prbs_pattern;

    /** rules specific to the serial rx checker */
    srm_prbs_chk_serial_rules_t serial;

    /** rules specific to the core rx checker */
    srm_prbs_chk_core_rules_t core;

} srm_prbs_chk_rules_t;


/**
 * Host and Rx PRBS checker status
 */
typedef struct
{
    /** PRBS mode for individual MSB/LSB or combined bit streams */
    e_srm_prbs_chk_mode prbs_mode;

    /** PRBS lock status */
    bool prbs_lock;

    /** PRBS lock status (LSB) */
    bool prbs_lock_lsb;

    /** Fixed pattern sync */
    uint8_t prbs_fixed_pat_sync;

    /** Received PRBS pattern */
    e_srm_prbs_pat prbs_pattern;

    /** Received PRBS pattern (LSB) */
    e_srm_prbs_pat prbs_pattern_lsb;

    /** Flag to indicate if the prbs total bit counter has saturated */
    bool prbs_total_bit_count_saturated;

    /** PRBS bit error counter */
    uint32_t prbs_error_bit_count;

    /** PRBS errored bit counter (LSB) */
    uint32_t prbs_error_bit_count_lsb;

    /** PRBS total bit counter */
    uint64_t prbs_total_bit_count;

    /** Received PRBS invert status */
    uint8_t prbs_inv;

    /** Received PRBS invert status (LSB) */
    uint8_t prbs_inv_lsb;

} srm_prbs_chk_status_t;
 

/**
 * This method is used to set the PRBS generator rules to their default values.
 *
 * @param gen_rules [I/O] - The PRBS generator rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_prbs_gen_rules_set_default(
    srm_prbs_gen_rules_t* gen_rules);

/**
 * This method is used to set the PRBS checker rules to their default values.
 *
 * @param chk_rules [I/O] - The PRBS checker rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_prbs_chk_rules_set_default(
    srm_prbs_chk_rules_t* chk_rules);

/**
 * This method is used to configure the PRBS generator.
 *
 * @{note,
 * You may want to squelch the transmitter before disabling the PRBS generator.
 * This will prevent the transmitter from emitting garbage to a downstream device}
 *
 * @param die         [I] - The physical ASIC die being accessed.
 * @param channel     [I] - The channel number, range 0..1.
 * @param intf        [I] - The interface, see e_srm_intf enum.
 * @param gen_rules   [I] - The generator rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_prbs_gen_config(
    uint32_t    die, 
    uint32_t    channel, 
    e_srm_intf  intf,
    srm_prbs_gen_rules_t* gen_rules);

/**
 * This method is used to configure the PRBS checker.
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param channel   [I] - The channel number
 * @param intf      [I] - The interface, see e_srm_intf enum.
 * @param chk_rules [I] - The checker rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_prbs_chk_config(
    uint32_t    die, 
    uint32_t    channel, 
    e_srm_intf  intf,
    srm_prbs_chk_rules_t*  chk_rules);


/**
 * This method is used to determine whether the PRBS checker is already
 * enabled.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The physical channel number (0-1)
 * @param intf    [I] - The interface, see e_srm_intf enum.
 *
 * @return true if the checker is enabled, false if it's not
 *
 * @since 0.1
 */
bool srm_prbs_chk_is_enabled(
    uint32_t    die, 
    uint32_t    channel,
    e_srm_intf  intf);

/**
 * This method is used to get the PRBS checker status.
 *
 * @param die        [I] - The physical ASIC die being accessed.
 * @param channel    [I] - The channel number (0-1)
 * @param intf       [I] - The interface, see e_srm_intf enum.
 * @param chk_status [O] - The checker status.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_prbs_chk_status(
    uint32_t    die, 
    uint32_t    channel, 
    e_srm_intf  intf,
    srm_prbs_chk_status_t*  chk_status);


#if defined(IP_HAS_FLOATING_POINT) && (IP_HAS_FLOATING_POINT==1)
/**
 * This method figures out the BER based on the PRBS checker status.
 *
 * @param chk_status    [I] - The checker status.
 * @param ber           [O] - The BER (MSB or combined)
 * @param ber_lsb       [O] - The BER (LSB)
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 *
 * @requires
 * The API must be have floating point support. It must be
 * compiled with the following flag:
 * - IP_HAS_FLOATING_POINT=1
 */
ip_status_t srm_prbs_chk_ber(
    srm_prbs_chk_status_t *chk_status,
    double  *ber,
    double  *ber_lsb);
#endif //defined(IP_HAS_FLOATING_POINT) && (IP_HAS_FLOATING_POINT==1)

#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)

ip_status_t srm_prbs_chk_status_print(
    uint32_t               die, 
    uint32_t               channel,
    e_srm_intf             intf,
    srm_prbs_chk_status_t* chk_status);

/**
 * This method is used to dump the PRBS checker status.
 *
 * @param die           [I] - The physical ASIC die being accessed.
 * @param channel       [I] - The channel number, range 0..1.
 * @param intf          [I] - The interface, see e_srm_intf enum.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_prbs_chk_status_query_print(
    uint32_t   die, 
    uint32_t   channel,
    e_srm_intf intf);

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)

/**
 * This method is called to inject errors into the TX datapath.
 *
 * @param die      [I] - The die of the ASIC being accessed.
 * @param channel  [I] - The channel to inject errors on
 * @param enable   [I] - Turn the injector on/off
 * @param pattern  [I] - The pattern to inject
 * @param gap      [I] - Number of 64-bit words without errors to insert between words with errors
 * @param duration [I] - Number of 64-bit words to inject errors on
 *
 * @return IP_OK on success, IP_ERROR on failure
 *
 * @since 0.1
 */ 
ip_status_t srm_prbs_gen_error_inject(
    uint32_t               die,
    uint32_t               channel,
    bool                   enable,
    e_srm_prbs_err_inj_pat pattern,
    uint8_t                gap,
    uint8_t                duration);


/**
 * @h2 Rx DSP
 * =======================================================
 * The following APIs are used to query status information
 * from the Rx interface.
 *
 * @h3 Reading the SNR Monitor
 * The following methods are used to manage and query
 * the SNR monitor on the Line receiver.
 *
 * @brief
 * The block count using when monitoring SNR
 */
typedef enum
{
    /** 2^10 blocks */
    SRM_RX_SNR_SYMBOL_COUNT_2EXP10 = 0,
    /** 2^13 blocks */
    SRM_RX_SNR_SYMBOL_COUNT_2EXP13 = 1,
    /** 2^16 blocks */
    SRM_RX_SNR_SYMBOL_COUNT_2EXP16 = 2,
    /** 2^19 blocks */
    SRM_RX_SNR_SYMBOL_COUNT_2EXP19 = 3,
    
    /** Use the default block count if the user is not sure what to enter */
    SRM_RX_SNR_SYMBOL_COUNT_USE_DEFAULT = 4,

}e_srm_rx_snr_symbol_count;


/**
 * The point where the error signal is generated
 * from in the datapath.
 */
typedef enum
{
    /**
     * Pick up the error signal prior to the RC block (reflection cancellor)
     * in the event it is not enabled or checking is being done prior
     * to the RC.
     */
    SRM_RX_DSP_ERR_GEN1_NO_RC = 1,
    
    /**
     * Pick up the error signal after the RC block (reflection cancellor)
     */
    SRM_RX_DSP_ERR_GEN2_POST_RC = 2,
    
    /**
     * In this mode the default value of the error gen signal is
     * being used based on whatever it is currently configured for.
     */
    SRM_RX_DSP_ERR_GEN_USE_DEFAULT = 3,
}e_srm_rx_error_gen;

/**
 * DFE Coefficient Values. These are stored as fixed point values
 * to minimize the use of floating point numbers. To convert to floating
 * point:
 *
 *    dfe_f1    = (dfe_f1    * 100000)/64
 *    dfe_nlfb0 = (dfe_nlfb0 * 100000)/64
 *    dfe_nlfb1 = (dfe_nlfb0 * 100000)/64
 */
typedef struct
{
    /** The main DFE tap */
    int32_t dfe_f1;
    
    /** Non Linear Feedback */
    int32_t dfe_nlfb0;
    
    /** Non Linear Feedback */
    int32_t dfe_nlfb1;
}srm_rx_dsp_dfe_coefficients_t;

/**
 * This method extracts the DFE F1 tap coefficient
 * and non-linear feedback terms for each of 8 sub-channels of 
 * the selected channel.
 *
 * @param die         [I] - The die used to identify the IP instance
 * @param channel     [I] - The RX channel to extract the DFE tap from.
 * @param sub_channel [I] - The DFE sub-channel.
 * @param dfe_coeffs  [O] - The DFE coefficients
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 */
ip_status_t srm_rx_dsp_dfe_get_coefficients(
    uint32_t                       die,
    uint32_t                       channel,
    uint32_t                       sub_channel,
    srm_rx_dsp_dfe_coefficients_t* dfe_coeffs);

#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && IP_HAS_DIAGNOSTIC_DUMPS == 1

/**
 * This method extracts then prints the DFE F1 tap coefficient
 * and non-linear feedback terms for each of 8 sub-channels of 
 * the selected channel.
 *
 * @param die         [I] - The die used to identify the IP instance
 * @param channel     [I] - The RX channel to extract the DFE tap from.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must be compiled with the following compilation define:
 * - IP_HAS_DIAGNOSTIC_DUMPS == 1
 *
 * @since 0.10
 */
ip_status_t srm_rx_dsp_dfe_coefficients_print(
    uint32_t die,
    uint32_t channel);

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && IP_HAS_DIAGNOSTIC_DUMPS == 1

/**
 * This method is used to turn on the SNR monitor for a particular
 * channel.
 *
 * @{note,
 * After enabling the SNR monitor circuit make sure you wait
 * at least 2xBlock size 32UIs for SNR ready}
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel through the device to access.
 * @param enable  [I] - true to enable the monitor, false to disable it.
 *
 * @since 0.1
 */
void srm_rx_dsp_snr_mon_en(
    uint32_t   die, 
    uint32_t   channel, 
    bool       enable);


/**
 * This method is used to determine whether or not the SNR monitor
 * is enabled or not.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The channel through the device to query.
 *
 * @return true if the monitor is enabled, false otherwise.
 *
 * @since 0.2
 */
bool srm_rx_dsp_snr_mon_enabled(uint32_t die, uint32_t channel);

/**
 * This method is called to configure the SNR monitor prior
 * to it being used for the first time.
 *
 * @{note,
 * After enabling the SNR monitor circuit make sure you wait
 * at least 2xBlock size 32UIs for SNR ready}
 *
 * @param die       [I] - The ASIC die being accessed.
 * @param channel   [I] - The channel through the device to query.
 * @param errgen    [I] - The location where the error signal is being
 *                        routed from. If you're not sure what to put here
 *                        then enter SRM_RX_DSP_ERR_GEN_USE_DEFAULT and the
 *                        API will use the default value. If this DSP mode is setup so that
 *                        the RC (Reflection Cancellor) is enabled then
 *                        this should be SRM_RX_DSP_ERR_GEN2_POST_RC. If
 *                        the DSP mode is configured such that the RC 
 *                        is disabled this should be set to SRM_RX_DSP_ERR_GEN1_NO_RC.
 * @param block_cnt [I] - The number of blocks to sample for when
 *                        monitoring the SNR. If you're not sure what to put here
 *                        enter SRM_RX_SNR_SYMBOL_COUNT_USE_DEFAULT and the h/w
 *                        default will be used.
 *
 * @since 0.1
 */
void srm_rx_dsp_snr_mon_cfg(
        uint32_t                   die,
        uint32_t                   channel,
        e_srm_rx_error_gen         errgen,
        e_srm_rx_snr_symbol_count  block_cnt);


/**
 * This method is called to read the raw SNR monitor value from
 * the hardware for the input channel.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel through the device to query.
 *
 * @return The raw SNR value read from the hardware.
 *
 * @since 0.1
 */
uint16_t srm_rx_dsp_snr_read_value(
    uint32_t   die, 
    uint32_t   channel);



/**
 * This method is called to read the SNR monitor value from the hardware
 * and translate it to a decimal (fixed-point) dB value.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel through the device to query.
 *
 * @return The (fixed-point) SNR value in dB
 *
 * @see
 * srm_rx_dsp_snr_read_value() to return the raw SNR value reported
 * by the hardware that has not been converted to dB.
 *
 * @since 0.1
 */
uint32_t srm_rx_dsp_snr_read_db_fixp(
    uint32_t die, 
    uint32_t channel);



#if defined(IP_HAS_MATH_DOT_H) && (IP_HAS_MATH_DOT_H == 1)

/**
 * This method is called to take an existing raw SNR value from
 * the hardware and translate it into a dB value.
 *
 * @param snr_val  [I] - The SNR reading read from the hardware via
 *                       srm_rx_dsp_snr_read_value().
 * @param pam_mode [I] - The signalling mode that the channel is operating
 *                       in (NRZ or PAM).
 *
 * @return The SNR value in dB
 *
 * @requires
 * The API must be compiled with IP_HAS_MATH_DOT_H flag. This will
 * pull in the <math.h> library which will increase the size of
 * the generated image.
 *
 * @since 0.1
 */
double srm_rx_dsp_snr_format(
    uint16_t          snr_val, 
    e_srm_signal_mode pam_mode);


/**
 * This method is called to read the SNR monitor value from the hardware
 * and translate it to a decimal dB value.
 *
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel through the device to query.
 *
 * @return The SNR value in dB
 *
 * @see
 * srm_rx_dsp_get_snr_value() to return the raw SNR value reported
 * by the hardware that has not been converted to dB.
 *
 * @requires
 * The API must be compiled with IP_HAS_MATH_DOT_H flag. This will
 * pull in the <math.h> library which will increase the size of
 * the generated image.
 *
 * @since 0.1
 */

double srm_rx_dsp_snr_read_db(
    uint32_t   die, 
    uint32_t   channel);


#endif // defined(IP_HAS_MATH_DOT_H) && (IP_HAS_MATH_DOT_H == 1)


/**
 * This method is converts SNR in milli-dB value to mse value
 *
 * @param snr_mdb     [I] - SNR value
 * @param pam_mode    [I] - signalling mode
 *
 * @return mse_val
 *
 * @since 0.22
 */
uint16_t srm_snr_fixp_to_mse(uint32_t snr_mdb, e_srm_signal_mode pam_mode);



/**
 * @h3 Configuring the FFE Taps
 * =======================================================
 * This section contains routines used to query the FFE
 * tap values for each of the 32 FFE sub-channels
 *
 * @brief
 * FFE Tap indices
 */
typedef enum
{
    /** pre-cursor 4 Tap index */
    SRM_FFE_TAP_PRE_CURSOR_4  = 0,
    /** pre-cursor 3 Tap index */
    SRM_FFE_TAP_PRE_CURSOR_3  = 1,
    /** pre-cursor 2 Tap index */
    SRM_FFE_TAP_PRE_CURSOR_2  = 2,
    /** pre-cursor 1 Tap index */
    SRM_FFE_TAP_PRE_CURSOR_1  = 3,
    /** main cursor Tap index */
    SRM_FFE_TAP_MAIN_CURSOR   = 4,
    /** post-cursor 1 Tap index */
    SRM_FFE_TAP_POST_CURSOR_1 = 5,
    /** post-cursor 2 Tap index */
    SRM_FFE_TAP_POST_CURSOR_2 = 6,
    /** post-cursor 3 Tap index */
    SRM_FFE_TAP_POST_CURSOR_3 = 7,
    /** post-cursor 4 Tap index */
    SRM_FFE_TAP_POST_CURSOR_4 = 8,
    /** post-cursor 5 Tap index */
    SRM_FFE_TAP_POST_CURSOR_5 = 9,
}e_srm_rx_ffe_taps;


#define SRM_FFE_TAP_COUNT 10

/**
 * Query the FFE taps
 *
 * @param die             [I] - The ASIC die being accessed.
 * @param channel         [I] - The channel through the device to query.
 * @param ffe_sub_channel [I] - The FFE sub-channel to query the taps for.
 * @param ffe_tap         [O] - The array of taps to populate
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_rx_dsp_ffe_taps_query(
    uint32_t    die,
    uint32_t    channel,
    uint16_t    ffe_sub_channel, // range 0..31
    int16_t    ffe_tap[SRM_FFE_TAP_COUNT]);


#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && IP_HAS_DIAGNOSTIC_DUMPS == 1

/**
 * This is a debug method used to translate the FFE taps index into a human
 * readable string for diagnotic dumps
 *
 * @param tap_index [I] - The tap index to translate to a string
 *
 * @return The human readable version of the FFE tap.
 *
 * @requires
 * The API must be compiled with the following compilation define:
 * - IP_HAS_DIAGNOSTIC_DUMPS == 1
 *
 * @since 0.1
 */
const char* srm_rx_dsp_dbg_translate_ffe_tap_index(
    e_srm_rx_ffe_taps tap_index);


/**
 * Print the FFE taps for a particular Rx channel and FFE sub-channel
 *
 * @param die             [I] - The ASIC die being accessed.
 * @param channel         [I] - The channel through the device to query.
 * @param ffe_sub_channel [I] - The FFE sub-channel to print the
 *                              tap values for.
 * @param ffe_taps        [I] - The array of FFE taps queried via the
 *                              srm_rx_dsp_ffe_taps_query method.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @see srm_rx_dsp_ffe_taps_query
 *
 * @requires
 * The API must be compiled with the following compilation define:
 * - IP_HAS_DIAGNOSTIC_DUMPS == 1
 *
 * @since 0.1
 */
ip_status_t srm_rx_dsp_ffe_taps_print(
    uint32_t    die,
    uint32_t    channel,
    uint16_t    ffe_sub_channel, // range 0..31
    int16_t     ffe_taps[SRM_FFE_TAP_COUNT]);

/**
 * Queries then prints the FFE taps for a particular Rx channel and FFE sub-channel
 *
 * @param die             [I] - The ASIC die being accessed.
 * @param channel         [I] - The channel through the device to query.
 * @param ffe_sub_channel [I] - The FFE sub-channel to print the
 *                              tap values for.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @see srm_rx_dsp_ffe_taps_query and srm_rx_dsp_ffe_taps_print
 *
 * @requires
 * The API must be compiled with the following compilation define:
 * - IP_HAS_DIAGNOSTIC_DUMPS == 1
 *
 * @since 0.14
 */

ip_status_t srm_rx_dsp_ffe_taps_query_dump(
    uint32_t die,
    uint32_t channel,
    uint16_t ffe_sub_channel); // range 0..31

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && IP_HAS_DIAGNOSTIC_DUMPS == 1

/**
 * @h3 Histogram
 * =======================================================
 * The following methods are used to manage capturing and
 * displaying the RX histogram.
 *
 * @brief
 * Initialize then capture the DSP histogram.
 * Note that this method captures the histogram data from the HW.
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param channel    [I] - The channel through the device to query.
 * @param errgen_id  [I] - SNR Monitor Error Generator value.
 * @param hist_data  [O] - Pointer to the histogram data. This must be a single
 *                         dimensional array of exactly 160 uint32_t entries.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @example
 * uint32_t die = 0;              // The ASIC die to fetch the histogram for
 * uint32_t channel = 0;          // Fetch the histogram for channel 0
 * uint32_t hist_data[160] = {0}; // The buffer to fetch the histogram into
 * 
 * // Fetch the histogram
 * status |= srm_rx_dsp_get_histogram(die,
 *               channel,
 *               SRM_RX_DSP_ERR_GEN1_NO_RC, // The Reflection cancellor is not enabled
 *               hist_data);
 *
 * // If it was successful plot it as an ASCII diagram
 * if(status == IP_OK)
 * {
 *     srm_dsp_hist_ascii_plot(die, channel, hist_data); 
 * }
 *
 *
 * @since 0.1
 */
ip_status_t srm_rx_dsp_get_histogram(
    uint32_t            die,
    uint32_t            channel,
    e_srm_rx_error_gen  errgen_id,
    uint32_t*           hist_data);

/**
 * Equivalent to srm_rx_dsp_get_histogram but bypassing the f/w for the eye monitor
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param channel    [I] - The channel through the device to query.
 * @param errgen_id  [I] - SNR Monitor Error Generator value.
 * @param hist_data  [O] - Pointer to the histogram data. This must be a single
 *                         dimensional array of exactly 160 uint32_t entries.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @example
 * uint32_t die = 0;              // The ASIC die to fetch the histogram for
 * uint32_t channel = 0;          // Fetch the histogram for channel 0
 * uint32_t hist_data[160] = {0}; // The buffer to fetch the histogram into
 * 
 * // Fetch the histogram
 * status |= srm_rx_dsp_get_histogram_bypass(die,
 *               channel,
 *               SRM_RX_DSP_ERR_GEN1_NO_RC, // The Reflection cancellor is not enabled
 *               hist_data);
 *
 * // If it was successful plot it as an ASCII diagram
 * if(status == IP_OK)
 * {
 *     srm_dsp_hist_ascii_plot(die, channel, hist_data); 
 * }
 */
ip_status_t srm_rx_dsp_get_histogram_bypass(
    uint32_t            die,
    uint32_t            channel,
    e_srm_rx_error_gen  errgen_id,
    uint32_t*           hist_data);

/**
 * Send/receive the RX histogram messages with the FW
 * @private
 */
ip_status_t srm_mcu_msg_rx_hist_request(
    uint32_t die,
    uint32_t channel,
    e_srm_rx_error_gen errgen_id,
    uint32_t hist_data[160]);


#if defined(IP_HAS_MATH_DOT_H) && (IP_HAS_MATH_DOT_H == 1)

/**
 * ASCII plot the Tx DSP histogram data
 *
 * @param die        [I] - The ASIC die being accessed.
 * @param channel    [I] - The channel through the device to query.
 * @param hist_data  [I] - Pointer to the histogram data which is a single
 *                         dimensional array of 160 uint32_t entries.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must be compiled with math.h support:
 * - IP_HAS_MATH_DOT_H=1
 *
 * @since 0.1
 */
ip_status_t srm_rx_dsp_hist_ascii_plot(
    uint32_t    die,
    uint32_t    channel,
    uint32_t*   hist_data);

/**
 * Capture then plot the Rx DSP histogram data for a given die
 * 
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel through the device to query.
 * @param errgen  [I] - SNR Monitor Error Generator value.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must be compiled with math.h support:
 * - IP_HAS_MATH_DOT_H=1
 *
 * @since 0.1
 */
ip_status_t srm_rx_dsp_hist_query_dump(
    uint32_t            die, 
    uint32_t            channel,
    e_srm_rx_error_gen  errgen);

/**
 * Capture then plot the Rx DSP histogram data to a specified file for a given die
 * 
 * @param die     [I] - The ASIC die being accessed.
 * @param channel [I] - The channel through the device to query.
 * @param errgen  [I] - SNR Monitor Error Generator value.
 * @param path    [I] - Output file name.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * The API must be compiled with math.h support:
 * - IP_HAS_MATH_DOT_H=1
 * The API must also be compiled with file system support:
 * - IP_HAS_FILESYSTEM=1
 *
 * @since 0.1
 */
ip_status_t srm_rx_dsp_hist_query_dump_to_file(
    uint32_t            die, 
    uint32_t            channel,
    e_srm_rx_error_gen  errgen,  
    const char*         path);


#endif // defined(IP_HAS_MATH_DOT_H) && (IP_HAS_MATH_DOT_H == 1)


#if defined(IP_HAS_EYEMON) && (IP_HAS_EYEMON == 1)
/**
 * @h3 The Eye Monitor APIs
 * =======================================================
 * The following methods are used to fetch and display
 * the RX eye monitor.
 *
 * @{warning,
 * IP does not recommend the eye monitor and it is preferrable
 * to use the SNR monitor and histogram for monitoring the link.}
 *
 * @{warning,
 * The eye capture is destructive/traffic affecting which means
 * it will cause a data hit to the incoming stream and RX adapation
 * may be stopped. After capturing the eye monitor data the receiver
 * should be reset by:
 * - squelch/unsquelch of the link partner TX
 * - force the DSP to recover (see force_dbg_relock)
 * - re-configure the interface
 * }
 *
 * The following picture shows the output of the eye monitor
 * plotted via Python/matplotlib:
 *
 * @{image, src="docs/images/eye_capture.png"}
 *
 * @h4 A Note about NRZ Mode
 * In NRZ mode the eye monitor is not capable of sampling
 * between the inner slicer levels (-1 and +1). This is by design
 * and not a limitation in PAM mode. The information in this
 * range would be outside the operating range of NRZ mode and is not
 * deemed critical information and is a known limitation in NRZ mode.
 * It results in the eye being cut off on the outer outer
 * edges as shown in the picture below:
 *
 * @{image, src="docs/images/eye_capture_nrz.png"}
 *
 *
 * @brief
 * A support method used to freeze the DSP in order to
 * capture the eye. This should not normally be called and
 * is exposed for use in the IP Explorer GUI.
 * 
 * @param die     [I] - The physical ASIC die being accessed.
 * @param channel [I] - The RX channel to capture the eye for.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @requires
 * - IP_HAS_EYEMON=1
 *
 * @private
 *
 * @since 0.10
 */
ip_status_t srm_rx_dsp_freeze(uint32_t die, uint32_t channel);


/**
 * This method is used to sweep the eye and return the
 * captured data in the input array.
 *
 * @{warning,
 * The eye capture is destructive/traffic affecting which means
 * it will cause a data hit to the incoming stream and RX adapation
 * may be stopped. After capturing the eye monitor data the receiver
 * should be reset by:
 * - squelch/unsquelch of the link partner TX
 * - force the DSP to recover (see force_dbg_relock)
 * - re-configure the interface
 * }
 *
 * See the srm_dbg_force_dsp_relock method to force the receiver
 * to re-acquire lock.
 *
 * @param die        [I] - The physical ASIC die being accessed. This is used to
 *                         steer accesses between multiple dies in the same ASIC package
 *                         or between multiple ASICs on the same MDIO/I2C bus.
 * @param channel    [I] - The RX channel to capture the eye for.
 * @param eye_data [I/O] - The buffer to store the captured eye data.
 * @param min        [I] - The start or minimum point from the center (typically 1)
 * @param max        [I] - The end or maximum point from the center (typically 64)
 * @param step_size  [I] - The sweep step size (typically 1)
 *
 * @return IP_OK on success, IP_ERROR on failure.
 * 
 * @requires
 * - IP_HAS_EYEMON=1
 *
 * @since 0.10
 */
ip_status_t srm_rx_dsp_eyemon_query(
    uint32_t           die,
    uint32_t           channel,
    uint32_t           eye_data[128][160],
    int                min,
    int                max,
    int                step_size);


/**
 * This method is used to sweep the eye and dump the captured data to
 * file.
 *
 * @{warning,
 * The eye capture is destructive/traffic affecting which means
 * it will cause a data hit to the incoming stream and RX adapation
 * may be stopped. After capturing the eye monitor data the receiver
 * should be reset by:
 * - squelch/unsquelch of the link partner TX
 * - force the DSP to recover (see force_dbg_relock)
 * - re-configure the interface
 * }
 *
 * See the srm_dbg_force_dsp_relock method to force the receiver
 * to re-acquire lock.
 *
 * @{note,
 * The examples/diagnostics directory contains an eye_monitor_plot.py
 * script that may be used to plot the captured eye using matplotlib.
 * }
 *
 * @param die        [I] - The physical ASIC die being accessed. This is used to
 *                         steer accesses between multiple dies in the same ASIC package
 *                         or between multiple ASICs on the same MDIO/I2C bus.
 * @param channel    [I] - The RX channel to capture the eye for.
 * @param min        [I] - The start or minimum point from the center (typically 1)
 * @param max        [I] - The end or maximum point from the center (typically 64)
 * @param step_size  [I] - The sweep step size (typically 1)
 * @param path       [I] - The path to write the captured data to.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 *
 * @requires
 * The API must be compiled with file system support:
 * - IP_HAS_FILESYSTEM=1
 * - IP_HAS_EYEMON=1
 *
 * @example
 *   // Capture the LRX eye for channel 0 and save it to eyemon.txt
 *   const char* path = "eyemon.txt";
 *   status |= srm_rx_dsp_eyemon_query_dump(die,                        // The physical ASIC die being accessed
 *                                           0,                         // RX channel 0
 *                                           0,                         // start point
 *                                           64,                        // end point
 *                                           1,                         // step size
 *                                           path                       // output path
 *             );
 */
ip_status_t srm_rx_dsp_eyemon_query_dump(
    uint32_t die,
    uint32_t channel,
    int min,
    int max,
    int step_size,
    const char* path);
#endif // defined(IP_HAS_EYEMON) && (IP_HAS_EYEMON == 1)


/**
 *
 * @h3 Rx Quality Check (RX_QC) Statistics
 * This section describes methods used for fetching the RX_QC statistics
 * from the device when RX_QC is enabled.
 *
 * @brief
 * The RX_QC statistics structure used when fetching
 * statistics from the device.
 */
typedef struct srm_rx_qc_stats_s
{
    /** Status of RX_QC */
    uint16_t   rx_qc_status;

    /** Number of failing RX_QC while checking to build-up the interface */
    uint8_t    up_retry_fail_cnt;

    /** Number of successful RX_QC while checking to build-up the interface */
    uint8_t    up_retry_pass_cnt;

    /** Number of failing RX_QC while checking the need to tear-down the interface */
    uint8_t    dn_retry_fail_cnt;

    /** MSE of last successful RX_QC while checking to build-up the interface */
    uint16_t up_mse_pass;

    /** MSE of last failing RX_QC while checking to build-up the interface */
    uint16_t up_mse_fail;

    /** MSE of last successful RX_QC while checking to tear-down the interface*/
    uint16_t dn_mse_pass;

    /** MSE of last failing RX_QC while checking to tear-down the interface */
    uint16_t dn_mse_fail;

    /** Accumulated number of successful RX_QC while checking to build-up the interface */
    uint8_t  up_retry_pass_cnt_accum;

    /** Accumulated number of failing RX_QC while checking the need to tear-down the interface */
    uint8_t  dn_retry_fail_cnt_accum;

    /** Maximum MSE of failing RX_QC while checking to build-up the interface */
    uint16_t up_mse_fail_max;

    /** Maximum MSE of failing RX_QC while checking to tear-down the interface */
    uint16_t dn_mse_fail_max;

}   srm_rx_qc_stats_t;


/**
 * This method is used to update RX Quality-Check rules
 * for the specified interface rules already running.
 *
 * @param die          [I] - The physical ASIC die being accessed.
 * @param ch_mask      [I] - Channel mask with bit 0 and 1 for channels 0 and 1 respectively
 * @param rx_qc        [I] - rx_qc rule
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.22
 *
 */
ip_status_t srm_channel_mask_rx_qc_update(
    uint32_t die,
    uint32_t ch_mask,
    srm_rx_qc_rules_t *rx_qc
);


/**
 * This method is used to query RX Quality-Check rules
 * for the specified channel already running.
 *
 * @param die          [I] - The physical ASIC die being accessed.
 * @param channel      [I] - The receive channel being accessed.
 * @param rx_qc        [I] - rx_qc rule
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.22
 *
 */
ip_status_t srm_channel_rx_qc_query(
    uint32_t           die,
    uint32_t           channel,
    srm_rx_qc_rules_t *rx_qc
);


/**
 * This method prints RX Quality-Check rules
 *
 * @param die          [I] - The physical ASIC die being accessed.
 * @param channel      [I] - The receive channel being accessed.
 * @param rx_qc        [I] - rx_qc rule
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.22
 *
 */
ip_status_t srm_channel_rx_qc_print(
    uint32_t           die,
    uint32_t           channel,
    srm_rx_qc_rules_t *rx_qc
);


/**
 * Query the RX_QC statistics from the hardware.
 * The statistics will be cleared only when the bundle or interface
 * is re-initialized.
 *
 * @param die     [I]   - The physical ASIC die being accessed.
 * @param channel [I]   - The channel to query the FEC stats for. 
 * @param stats   [I/O] - The RX_QC statistics read from the hardware.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.22
 *
 * @example
 * srm_rx_qc_stats_t qc_stats;
 *
 * char *rx_str;
 *
 * for (int ch = 0; ch < 2; ch++) {
 *     status |= srm_rx_qc_stats_query(mbd | die, ch, &qc_stats);
 *     status |= srm_rx_qc_stats_print(mbd | die, ch, &qc_stats);
 * }
 *
 */
ip_status_t srm_rx_qc_stats_query(
    uint32_t           die,
    uint32_t           channel,
    srm_rx_qc_stats_t *stats
);


/**
 * Print the RX_QC statistics from the hardware.
 *
 * @param die     [I]   - The physical ASIC die being accessed.
 * @param channel [I]   - The channel to query the FEC stats for. 
 * @param stats   [I/O] - The RX_QC statistics read from the hardware.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.22
 *
 */
ip_status_t srm_rx_qc_stats_print(
    uint32_t           die,
    uint32_t           channel,
    srm_rx_qc_stats_t *stats
);


/**
 * @h2 Debug/diagnostic methods
 * =======================================================
 *
 * @brief
 * This is a diagnostic method to print all of the accessible registers within the device.
 *
 * @param die  [I] - The physical ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_diags_register_dump(
    uint32_t die);

#if defined(IP_HAS_FILESYSTEM) && IP_HAS_FILESYSTEM == 1
/**
 * This is a diagnostic method used to dump all accessible registers to
 * a file for logging purposes.
 *
 * @param die  [I] - The physical ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flags:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 * - IP_HAS_FILESYSTEM=1
 */
ip_status_t srm_diags_register_dump_file(uint32_t die, FILE* handle);


/**
 * This is a diagnostic method used to dump all accessible registers to
 * a given path for logging purposes.
 *
 * @param die  [I] - The physical ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flags:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 * - IP_HAS_FILESYSTEM=1
 */
ip_status_t srm_diags_register_dump_path(uint32_t die, const char* handle);
#endif // defined(IP_HAS_FILESYSTEM) && IP_HAS_FILESYSTEM == 1


/**
 * This method is used to query the temperature from the device. The
 * temperature is reported in degrees Celsius.
 * the device
 *
 * @param die         [I] - The physical ASIC die being accessed.
 * @param temperature [O] - The output temperature read from the device in
 *                          degress Celsius.
 *
 * @since 0.10
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_diags_temperature_query(uint32_t die, int32_t* temperature);


/**
 * This method write to internal data structure of the device.
 *
 * @since 0.15
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @example
 * uint32_t long_buf[5];
 * uint32_t byte_count = 0;
 *
 * long_buf[0]  = 0x03020100;
 * long_buf[1]  = 0x07060504;
 * long_buf[2]  = 0x0b0a0908;
 * long_buf[3]  = 0x0f0e0d0c;
 * long_buf[4]  = 0x13121110;
 *
 * srm_diags_internal_data_write(mbd, 6, 0, 5, long_buf, &byte_count);
 *
 */
ip_status_t srm_diags_internal_data_write(
    uint32_t  die, 
    int       index,
    uint32_t  long_offset,
    uint32_t  long_max,
    uint32_t* long_buf,
    uint32_t* byte_count
);




/**
 * This method query internal data from the device.
 *
 * @since 0.14
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @example
 * #define BUF_SIZE (64)
 * uint32_t die = 0;
 * uint32_t long_buf[BUF_SIZE];
 * uint32_t byte_count = 0;
 *
 * for (int i = 0; i < 128; i += BUF_SIZE) {
 *     srm_variable_data_query(mbd, 7, i, BUF_SIZE, long_buf, &byte_count);
 *
 *     for (int i = 0; i < 64; i++) {
 *        IP_PRINTF("%3d: %08x (%d)\n", i, long_buf[i], long_buf[i]);
 *     }
 *
 *     IP_PRINTF("byte_count=%d\n", byte_count);
 * }
 *
 */
ip_status_t srm_diags_internal_data_query(
    uint32_t  die, 
    int       index,
    uint32_t  long_offset,
    uint32_t  long_max,
    uint32_t* long_buf,
    uint32_t* byte_count
);




typedef enum _e_srm_tx_pmd_states {
    STATE_TX_PMD_ERROR          = -1,
    STATE_TX_PMD_RESET_PD       =  0,
    STATE_TX_PMD_IDLE,           //1

    STATE_TX_PMD_BASE_PU,        //2
    STATE_TX_PMD_PLL_SETUP,      //3
    STATE_TX_PMD_PLL_FCAL,       //4

    STATE_TX_PMD_LANE_PU,        //5
    STATE_TX_PMD_SOFT_RESET,     //6
    STATE_TX_PMD_CONFIGURE,      //7
    
    STATE_TX_PMD_READY,          //8
    STATE_TX_PMD_RUN,            //9
    STATE_TX_PMD_DATA_MODE,      //10
    STATE_TX_PMD_DME_MODE,       //11 
    STATE_TX_PMD_TRAIN_MODE,     //12
    STATE_TX_PMD_READY_TO_TRAIN, //13

} e_srm_tx_pmd_states;

typedef enum _e_srm_rx_pmd_states {
    STATE_RX_PMD_ERROR          = -1,
    STATE_RX_PMD_RESET_PD       =  0,
    STATE_RX_PMD_IDLE,           //1

    STATE_RX_PMD_BASE_PU,        //2
    STATE_RX_PMD_PLL_SETUP,      //3
    STATE_RX_PMD_PLL_FCAL,       //4

    STATE_RX_PMD_LANE_PU,        //5
    STATE_RX_PMD_SOFT_RESET,     //6
    STATE_RX_PMD_CONFIGURE,      //7
    STATE_RX_PMD_WAIT_DSP_READY, //8
    STATE_RX_PMD_DATA_MODE,      //9
    STATE_RX_PMD_DME_MODE,       //10
    STATE_RX_PMD_TRAIN_MODE      //11 

} e_srm_rx_pmd_states;


/**
 * This structure contains the FSM state info.
 */
typedef struct
{
    /** Chip Initialized, True or False */
    bool chip_init;
    /** PLL Initialized, True or False */
    bool pll_init;
    /** Tx Initialized (per channel), True or False */
    bool tx_init[2];
    /** Tx FSM state (per channel) */
    e_srm_tx_pmd_states tx_pmd_state[2];
    /** Rx Initialized (per channel), True or False */
    bool rx_init[2];
    /** Rx FSM state (per channel) */
    e_srm_rx_pmd_states rx_pmd_state[2];

} srm_fsm_state_t;


/**
 * This is a diagnostic method used to query the FW FSM state info.
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param fsm_state [O] - Pointer to the FSM info structure.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 *
 */
ip_status_t srm_dbg_fsm_query(
    uint32_t die,
    srm_fsm_state_t * fsm_state);

#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)
/**
 * This is a diagnostic method used to dump the FW FSM state info.
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param fsm_state [O] - Pointer to the FSM info structure.
 *
 * The following table describes the possible Tx FSM states:
 *
 *   Tx State        Enum  Description
 *   ========        ====  ===========
 *   ERROR            -1   Fatal Error
 *   RESET_PD          0   Initial, mode change, pll lol, Tx channel power-down
 *   IDLE              1   Reserved for future use
 *   BASE_PU           2   Tx channel power-up
 *   PLL_SETUP         3   Reserved for future use
 *   PLL_FCAL          4   Reserved for future use
 *   LANE_PU           5   Lane power-up
 *   SOFT_RESET        6   Squelch the Tx, toggle reset the digital Tx channel
 *   CONFIGURE         7   Configure the Tx channel based on the rules
 *   READY             8   Reserved for future use
 *   RUN               9   Reserved for future use
 *   DATA_MODE        10   Monitor the status of the Tx FIFO
 *   DME_MODE         11   Reserved for future use
 *   TRAIN_MODE       12   Reserved for future use
 *   READY_TO_TRAIN   13   Reserved for future use
 *
 * The following table describes the possible Rx FSM states:
 *
 *   Rx State        Enum  Description
 *   ========        ====  ===========
 *   ERROR            -1   Fatal Error
 *   RESET_PD          0   Initial, mode change, Rx channel power-down
 *   IDLE              1   Reserved for future use
 *   BASE_PU           2   Rx channel power-up
 *   PLL_SETUP         3   Configure the PLL
 *   PLL_FCAL          4   Reserved for future use
 *   LANE_PU           5   Lane Power-up
 *   SOFT_RESET        6   Toggle reset the digital Rx channel
 *   CONFIGURE         7   Configure the Rx channel based on the rules
 *   WAIT_DSP_READY    8   Wait for the DSP to become ready, debounced
 *   DATA_MODE         9   Monitor the SNR, SDT
 *   DME_MODE         10   Monitor DSP interrupts
 *   TRAIN_MODE       11   Processing the Link Training FSM
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_dbg_fsm_dump(
    uint32_t die,
    srm_fsm_state_t * fsm_state);

/**
 * This is a diagnostic method used to query/dump the FW FSM state info.
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param fsm_state [O] - Pointer to the FSM info structure.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_dbg_fsm_query_dump(
    uint32_t die);

/**
 * This is a diagnostic method used to query/dump the PLL status
 *
 * @param die       [I] - The physical ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.10
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_pll_status_query_dump(
    uint32_t die);

/**
 * This is a diagnostic method used to query/dump the high level 
 * status of a die
 *
 * @param die       [I] - The physical ASIC die being accessed.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.11
 *
 * @requires
 * The API must be have diagnostic dump support. It must be
 * compiled with the following flag:
 * - IP_HAS_DIAGNOSTIC_DUMPS=1
 */
ip_status_t srm_dbg_status_dump(
    uint32_t die);

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)

/**
 * @h2 MCU Diagnostics
 * =======================================================
 * @note
 *
 * Use srm_mcu_fw_mode_query to determine the current FW mode.
 *
 * @brief
 * Struct mimicing the one from the FW, which contains important
 * addresses for PIF accesses.
 *
 * @since 0.1
 *
 * @private
 */
typedef struct
{
    /** The address of the firmwares debug log */
    uint32_t debug_buffer_address;

    /** Address of the info buf */
    uint32_t info_buf_address;
}srm_fw_info_t;

/**
 * Reads the fw_info struct from the FW.
 *
 * @param die     [I] - The physical ASIC die being accessed.
 * @param fw_info [O] - FW info struct read from the FW.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 *
 * @private
 */
ip_status_t srm_mcu_fw_info_query(
    uint32_t       die,
    srm_fw_info_t *fw_info);




/**
 * Get access to a block of data reserved for downloading from
 * the host processor. A download buffer is used to collect
 * data in the processor and ensure it is valid before doing
 * anything with it. This ensures that we can transfer data
 * safely to the processor before we do anything else with it.
 *
 * @param die            [I] - The ASIC die to target
 * @param buffer_type    [I] - The type of buffer whose address
 *                             is being fetched:
 *                                 0 = transfer buffer
 *                                 1 = debug header
 *                                 2 = current debug ptr
 * @param buffer_address [O] - The address of the buffer
 * @param buff_32b_size  [O] - The size of the buffer in 32b words.
 * 
 * @return IP_OK on success, IP_ERROR on failure
 *
 * @since 0.1
 *
 * @private
 */
ip_status_t srm_mcu_get_buffer_address(
    uint32_t  die,
    uint32_t  buffer_type,
    uint32_t* buffer_address,
    uint16_t* buff_32b_size);


/**
 * Top bits of the MCU DRAM address space
 * @private
 */
#define SRM_MCU_DRAM_ADDR_MSW 0x5ff8


/**
 * Write to MCU memory via the inbound PIF interface
 *
 * @param die       [I] - The ASIC die to target
 * @param addr      [I] - The address to write
 * @param buffer    [O] - The buffer to write from
 * @param num_words [I] - The number of 32 bit words to write from 'buffer'
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_pif_write(
    uint32_t        die,
    uint32_t        addr,
    const uint32_t* buffer,
    uint32_t        num_words);


/**
 * Read from MCU memory through the inbound PIF interface
 *
 * @param die       [I] - The ASIC die to target
 * @param addr      [I] - The address to read
 * @param buffer    [O] - The buffer to read into
 * @param num_words [I] - The number of 32 bit words to read into 'buffer'
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 */
ip_status_t srm_mcu_pif_read(
    uint32_t  die,
    uint32_t  addr,
    uint32_t* buffer,
    uint32_t  num_words);



const char* srm_dbg_translate_fw_mode(e_srm_fw_mode mode);
#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1) 

const char* srm_dbg_translate_tx_pmd_state(e_srm_tx_pmd_states tx_pmd_state);
const char* srm_dbg_translate_rx_pmd_state(e_srm_rx_pmd_states rx_pmd_state);
const char* srm_dbg_translate_dsp_mode(e_srm_dsp_mode dsp_mode);
const char* srm_dbg_translate_intf(e_srm_intf intf);
const char* srm_dbg_translate_signalling(e_srm_signal_mode signalling);
const char* srm_dbg_translate_lut_mode(e_srm_lut_mode lut_mode);
const char* srm_dbg_translate_tx_swing(e_srm_tx_swing tx_swing);
const char* srm_dbg_translate_an_mode(e_srm_anlt_mode an_mode);
const char* srm_dbg_translate_lt_clk_src(e_srm_anlt_lt_clk_src lt_clk_src);

const char* srm_anlt_dbg_an_status_translate(e_srm_anlt_an_status an_status);
const char* srm_anlt_dbg_an_hcd_translate(uint32_t an_hcd_rate);

#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1) 



/**
 * This method writes the timestamps for AN/LT of a channel for debug purpose
 *
 * @param die        [I] - The IP to access
 * @param channel    [I] - The RX channel to access
 * @param tstamp_val [O] - array of 132 entries for reading out timestamp values
 * @param byte_count [O] - number of bytes read
 *
 * @since 0.15
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 */
ip_status_t srm_anlt_timestamp_write(
    uint32_t die,
    uint32_t channel,
    uint16_t *tstamp_val,
    uint32_t *p_byte_count
);


/**
 * This method reads out the timestamps for AN/LT of a channel.
 *
 * @param die        [I] - The IP to access
 * @param channel    [I] - The RX channel to access
 * @param tstamp_val [O] - array of 176 uint16_t entries for reading out timestamp values
 * @param byte_count [O] - number of bytes read
 *
 * @since 0.14
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @example
 * #define BUF_SIZE (176)
 * uint32_t die = 0;
 * uint32_t rx_channel = 0;
 * uint16_t long_buf[BUF_SIZE];
 * uint32_t byte_count = 0;
 *
 * srm_anlt_timestamp_query(die, rx_channel, long_buf, &byte_count);
 * srm_anlt_timestamp_print(long_buf);
 *
 */
ip_status_t srm_anlt_timestamp_query(
    uint32_t die,
    uint32_t channel,
    uint16_t *tstamp_val,
    uint32_t *p_byte_count
);

/**
 * This method prints out the timestamps for AN/LT of a channel.
 *
 * @param tstamp_val [O] - array of 176 uint16_t entries for reading out timestamp values
 *
 * @since 0.14
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 */
ip_status_t srm_anlt_timestamp_print(
    uint16_t *tstamp_val
);


/**
 * This is a debug method that allows the user to turn on or off
 * progress messages in the API like logs when waiting for
 * the link to be ready.
 *
 * @param enable [I] - Set to true to enable progress messages
 *                     or false to disable them.
 *
 * @since 0.1
 */
void srm_show_progress_enable(
    bool enable);

/**
 * Determine whether progress messages should be displayed
 * during long events like waiting for the link to be ready
 *
 * @param die  [I] - The physical ASIC die being accessed. 
 *
 * @return true if messages should be displayed or false
 *         otherwise.
 *
 * @since 0.1
 */
bool srm_show_progress();


/**
 * Download the FW to the MCU
 *
 * @param die                   [I] - The ASIC die being accessed.
 * @param fw_dwld_timeout       [I] - The amount of time to wait for the MCU
 *                                    to be running in application mode. Units are milli-seconds.
 * @param fw_warn_if_mismatched [I] - Flag to warn the user if the API and FW are 
 *                                    mismatched.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 *
 * @require
 * IP_HAS_INLINE_APP_FW = 1
 */
ip_status_t srm_dwld_fw(
    uint32_t  die,
    uint32_t  fw_dwld_timeout,
    bool      fw_warn_if_mismatched);




/**
 * This method is called to wait for the PLL to assert lock
 *
 * @param die      [I] - The ASIC die being accessed.
 * @param max_wait [I] - Maximum wait for the PLL to sync (units are seconds)
 * 
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.1
 *
 * @deprecated
 * This method is deprecated. Please use srm_wait_for_pll_locked
 * instead.
 */
ip_status_t srm_wait_for_pll_lock(
    uint32_t die,   
    uint32_t max_wait);



/**
 * @h2 AN/LT Configuration
 * =======================================================
 * The following methods are used to configure SRM for
 * AN/LT.
 *
 * @brief
 * This sets up the default AN/LT rules */
ip_status_t srm_anlt_rules_set_default(
    srm_anlt_rules_t* rules);

/**
 * Wait for ACK to clear
 *
 * @param die [I] - DIE number
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_wait_for_ack_clear(
    uint32_t           die);

/**
 * Copy AN rules to overlays
 *
 * @param die    [I] - DIE number
 * @param rules  [I] - The AN/LT rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_cp_an_to_overlays(
    uint32_t          die,
    srm_anlt_rules_t* p_anlt_rules);

/**
 * Copy LT rules to overlays
 *
 * @param die    [I] - DIE number
 * @param rules  [I] - The AN/LT rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_cp_lt_to_overlays(
    uint32_t          die,
    srm_anlt_rules_t* p_anlt_rules);

/**
 * Send ANLT REQ command.
 *
 * @param die    [I] - DIE number
 * @param cmd    [I] - Command
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_req_cmd(
    uint32_t           die,
    uint16_t           cmd);

/**
 * Copy RX rules bundle to channel
 *
 * @param bundle [I] - The rx bundle definition.
 * @param rules  [I] - The rx rules.
 * @param index  [I] - Index to follower. -1 for common values. 
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_cp_rx_rules_bundle_to_channel(
    srm_rx_bundle_rules_t *bundle,
    srm_rx_rules_t *channel,
    int index);

/**
 * Copy TX rules bundle to channel
 *
 * @param bundle [I] - The tx bundle definition.
 * @param rules  [I] - The tx rules.
 * @param index  [I] - Index to follower. -1 for common values. 
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_cp_tx_rules_bundle_to_channel(
    srm_tx_bundle_rules_t *p_bundle,
    srm_tx_rules_t *p_channel,
    int index);

/**
 * Wait for ACK to clear
 *
 * @param die [I] - DIE number
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_wait_for_ack_clear(
    uint32_t           die);

/**
 * Copy AN rules to overlays
 *
 * @param die    [I] - DIE number
 * @param rules  [I] - The AN/LT rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_cp_an_to_overlays(
    uint32_t          die,
    srm_anlt_rules_t* p_anlt_rules);

/**
 * Copy LT rules to overlays
 *
 * @param die    [I] - DIE number
 * @param rules  [I] - The AN/LT rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_cp_lt_to_overlays(
    uint32_t          die,
    srm_anlt_rules_t* p_anlt_rules);

/**
 * Send ANLT REQ command.
 *
 * @param die    [I] - DIE number
 * @param cmd    [I] - Command
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_req_cmd(
    uint32_t           die,
    uint16_t           cmd);

/**
 * Copy RX rules bundle to channel
 *
 * @param bundle [I] - The rx bundle definition.
 * @param rules  [I] - The rx rules.
 * @param index  [I] - Index to follower. -1 for common values. 
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_cp_rx_rules_bundle_to_channel(
    srm_rx_bundle_rules_t *bundle,
    srm_rx_rules_t *channel,
    int index);

/**
 * Copy TX rules bundle to channel
 *
 * @param bundle [I] - The tx bundle definition.
 * @param rules  [I] - The tx rules.
 * @param index  [I] - Index to follower. -1 for common values. 
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_cp_tx_rules_bundle_to_channel(
    srm_tx_bundle_rules_t *p_bundle,
    srm_tx_rules_t *p_channel,
    int index);

/**
 * Initialize the AN Leader and LT followers
 * in the bundle.
 *
 * @param bundle [I] - The AN/LT bundle definition.
 * @param rules  [I] - The AN/LT rules.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_init(
    srm_anlt_bundle_t* bundle,
    srm_anlt_rules_t*  rules);
 

/**
 * Trigger the AN/LT process.
 *
 * @param bundle [I] - The AN/LT bundle definition.
 * @param rules  [I] - The AN/LT rules. 
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_go(
    srm_anlt_bundle_t* bundle,
    srm_anlt_rules_t*  rules);


/**
 * This method is used to get Auto-Negotiation status
 *
 * @param bundle [I] - The AN/LT bundle definition.
 *
 * @return The AN/LT status.
 */
e_srm_anlt_an_status srm_anlt_get_an_status(srm_anlt_bundle_t* bundle);


/**
 * Fetch the results of the negotiation phase between
 * the local and remote link partners.
 *
 * @param bundle [I] - The AN/LT bundle definition.
 * @param result [O] - The result structure containing the
 *                     result of the negotiation.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_get_an_results(srm_anlt_bundle_t* bundle, srm_anlt_results_t* result);


/**
 * Recenter TX_FIFO.
 *
 * @param bundle [I] - The AN/LT bundle definition.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.23
 */
ip_status_t srm_anlt_recenter_tx_fifo(srm_anlt_bundle_t* bundle);


/**
 * Open TX and disable serial PRBS generator
 *
 * @param bundle [I] - The AN/LT bundle definition.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 * @since 0.23
 */
ip_status_t srm_anlt_open_tx(srm_anlt_bundle_t* bundle);


/**
 * This method is called to get the number of received AN pages from link partner
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * @param num_pages   [O] - pointer to number of received AN pages from link partner
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 */
ip_status_t srm_an_query_rx_lp_num_pages(
    uint32_t            die,
    uint32_t            channel,
    uint32_t            *num_pages);

/**
 * This method is called to get the number of received AN pages from link partner
 *
 * @param die         [I] - The ASIC die being accessed.
 * @param channel     [I] - The channel being accessed.
 * @param index       [I] - Index of the page
 * @param upper_page  [O] - pointer to Upper page received from link partner
 * @param upper_page  [O] - pointer to Lower page received from link partner
 *
 * @return IP_OK on success, IP_ERROR on failure.
 *
 */
ip_status_t srm_an_query_rx_lp_page(
    uint32_t          die,
    uint32_t          channel,
    uint32_t          index,
    uint32_t          *upper_page,
    uint32_t          *lower_page);



ip_status_t srm_bcst_emu_stat_query(
    uint32_t die,
    uint8_t  *xmt_occp,
    uint8_t  *xmt_vccy,
    uint8_t  *rcv_occp,
    uint8_t  *rcv_vccy);


ip_status_t srm_bcst_emu_deq_request(
    uint32_t   die,
    bool       master,
    uint32_t   ch_mask,
    uint32_t   *long_buf,
    uint16_t   cnt_requested,
    uint16_t   *cnt_actual);


ip_status_t srm_bcst_emu_enq_request(
    uint32_t   die,
    bool       master,
    uint32_t   ch_mask,
    uint32_t   *long_buf,
    uint16_t   cnt_requested,
    uint16_t   *cnt_actual);


ip_status_t srm_bcst_emu_stat_rd_bypass(
    uint32_t   die,
    bool       master,
    uint32_t   *stat_long_buf);


ip_status_t srm_bcst_emu_stat_wr_bypass(
    uint32_t   die,
    bool       master,
    uint32_t   *stat_long_buf);


ip_status_t srm_bcst_emu_rd_bypass(
    uint32_t   die,
    uint32_t   *stat_long_buf, 
    uint32_t   *fifo_long_buf);


ip_status_t srm_bcst_emu_wr_bypass(
    uint32_t   die,
    uint32_t   *stat_long_buf, 
    uint32_t   *fifo_long_buf);


void srm_bcst_emu_print(
    uint32_t   ch,
    uint32_t   *stat_long_buf,
    uint32_t   *fifo_long_buf);


void srm_bcst_emu_stat_query_bypass(
    uint32_t   *stat_long_buf,
    uint8_t    *occp,
    uint8_t    *vccy);


void srm_bcst_emu_enq_bypass(
    uint32_t   ch_mask,
    uint32_t   *stat_long_buf,
    uint32_t   *fifo_long_buf,
    uint32_t   *long_buf,
    uint16_t   cnt_requested,
    uint16_t   *cnt_actual);


void srm_bcst_emu_deq_bypass(
    uint32_t   ch_mask,
    uint32_t   *stat_long_buf,
    uint32_t   *fifo_long_buf,
    uint32_t   *long_buf,
    uint16_t   cnt_requested,
    uint16_t   *cnt_actual);

ip_status_t srm_lt_custom_preset_tap_set(
    uint32_t            die,
    uint32_t            channel,
    uint16_t            preset,
    int16_t             c1,
    int16_t             c0,
    int16_t             cm1,
    int16_t             cm2);








#if defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)
/**
 * This is a diagnostic method used to display the AN bundle configuration
 * including the location of the AN leader and any LT followers.
 *
 * @param rules  [I] - The AN/LT rules.
 */
void srm_anlt_rules_dump(
    srm_anlt_rules_t*  p_anlt_rules);


/**
 * This is a diagnostic method used to display the ANLT Rx bundle configuration.
 *
 * @param rx_rules  [I] - The AN/LT Rx bundle rules.
 *
 * @since 0.16
 * 
 */
void srm_rx_bundle_rules_print(
    srm_rx_bundle_rules_t* rx_rules);


/**
 * This is a diagnostic method used to display the ANLT Tx bundle configuration.
 *
 * @param tx_rules  [I] - The AN/LT Tx bundle rules.
 *
 * @since 0.16
 * 
 */
void srm_tx_bundle_rules_print(
    srm_tx_bundle_rules_t* tx_rules);


/**
 * This is a diagnostic method used to display the AN bundle configuration
 * including the location of the AN leader and any LT followers.
 *
 * @param bundle [I] - The AN/LT bundle to display.
 * @param rules  [I] - The AN/LT rules.
 */
void srm_anlt_bundle_dump(
    srm_anlt_bundle_t* bundle,
    srm_anlt_rules_t*  rules);

/**
 * This is a diagnostic method used to fetch then display the AN bundle configuration
 * including the location of the AN leader and any LT followers.
 *
 * @param die      [I] - The physical ASIC die being accessed. 
 * @param channel  [I] - The channel being accessed. 
 *
 * @since 0.11
 * 
 */
ip_status_t srm_anlt_rules_query_dump(
    uint32_t   die,
    uint32_t   channel);


/**
 * This is a diagnostic method used to query the AN/LT status
 *
 * @param bundle [I] - The AN/LT bundle definition.
 *
 * @return IP_OK on success, IP_ERROR on failure.
 */
ip_status_t srm_anlt_status_summary_query_dump(
    srm_anlt_bundle_t* bundle);


/**
 * This method is called to translate the AN status into a human
 * readable string
 *
 * @param an_status [I] - The AN status to translate
 *
 * @return The translated string
 */
const char* srm_anlt_dbg_an_status_translate(e_srm_anlt_an_status);


/**
 * This is a debug method used to translate the AN HCD into
 * a human readable string.
 *
 * @param an_hcd_rate [I] - The AN HCD rate.
 *
 * @return The translated HCD
 */
const char* srm_anlt_dbg_an_hcd_translate(uint32_t an_hcd_rate);


/**
 * This is a debug method used to query specific an_lt_rules
 *
 * @param die          [I] - The physical ASIC die being accessed.
 * @param channel      [I] - The channel being accessed.
 * @param intf         [I] - The interface of the channel ie. SRM_INTF_DIR_RX or SRM_INTF_DIR_TX
 * @param p_bundle     [O] - AN/LT bundle info associated with die, channel and intf
 * @param p_anlt_rules [O] - AN/LT rules info associated with die, channel and intf
 *
 */
ip_status_t srm_anlt_query(
    uint32_t           die,
    uint32_t           channel,
    e_srm_intf         intf,
    srm_anlt_bundle_t* p_bundle, 
    srm_anlt_rules_t*  p_anlt_rules
);


/**
 * This is a debug method used to query specific an_lt_rules
 *
 * @param die          [I] - The physical ASIC die being accessed.
 * @param channel      [I] - The channel being accessed.
 * @param intf         [I] - The interface of the channel ie. SRM_INTF_DIR_RX or SRM_INTF_DIR_TX
 * @param p_bundle     [O] - If die, channel and intf are that of an_leader, than the complete bundle info.
                             Otherwise, only an_leader.rx_die, an_leader.rx_channel, num_followers
 * @param p_anlt_rules [O] - AN/LT rules info associated with die, channel and intf
 *
 */
ip_status_t srm_channel_anlt_query(
    uint32_t           die,
    uint32_t           channel,
    e_srm_intf         intf,
    srm_anlt_bundle_t* p_bundle, 
    srm_anlt_rules_t*  p_anlt_rules
);


/**
 * This is a debug method used to query specific an_lt_rules
 *
 * @param die       [I] - The physical ASIC die being accessed.
 * @param channel   [I] - The channel being accessed.
 * @param intf      [I] - The interface of the channel ie. SRM_INTF_DIR_RX or SRM_INTF_DIR_TX
 * @param cmd       [I] - command to execute
 *
 */
ip_status_t srm_channel_req_cmd(
    uint32_t           die,
    uint32_t           channel,
    e_srm_intf         intf,
    uint16_t           cmd
);


#endif // defined(IP_HAS_DIAGNOSTIC_DUMPS) && (IP_HAS_DIAGNOSTIC_DUMPS==1)

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif /* __SRM_H__ */


