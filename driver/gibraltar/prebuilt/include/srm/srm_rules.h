/** @file srm_rules.h
 ****************************************************************************
 *
 * @brief
 *     This module describes the high level configuration rules for the API.
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
#ifndef __SRM_RULES_H__
#define __SRM_RULES_H__
#include "ip_rtos.h"

/**
 * @h2 ASIC Channel Management
 *
 * @brief
 * The maximum number of dies inside the ASIC. 
 */
#ifndef SYRMA_ASYNC
#define SRM_NUM_OF_RX_CHANNELS 2
#define SRM_NUM_OF_TX_CHANNELS 2
#define SRM_NUM_CHANNELS        2
#else   //SYRMA_ASYNC
#define SRM_NUM_OF_RX_CHANNELS 1
#define SRM_NUM_OF_TX_CHANNELS 1
#define SRM_NUM_CHANNELS        1
#endif  //SYRMA_ASYNC

/** The maximum number of line receivers in the ASIC */
#define SRM_MAX_RX_CHANNELS SRM_NUM_OF_RX_CHANNELS
/** The maximum number of line transmitters in the ASIC */
#define SRM_MAX_TX_CHANNELS SRM_NUM_OF_TX_CHANNELS
/** The maximum number of channels in the ASIC */
#ifndef SYRMA_ASYNC
#define SRM_MAX_CHANNELS 2
#else   //SYRMA_ASYNC
#define SRM_MAX_CHANNELS 1
#endif  //SYRMA_ASYNC

// The maximum number of SRM IPs that can be in an ERU block
#define SRM_MAX_SRM_PER_ERU          (32)
#define SRM_MAX_SRM_PER_ERU_BIT_MASK (0x1f)
#define SRM_CAL_MAX_SRM_PER_ERU SRM_MAX_SRM_PER_ERU

// 8 followers, 2 PMD (tx/rx)
#define SRM_MAX_DIE_PER_BUNDLE  (16)
// 256 max different dies
#define SRM_MAX_DIE_BIT_MASK    (0xff)

/**
 * @h2 Configuration Rules
 *
 * @brief
 * The signal/encoding mode (NRZ vs. PAM)
 */
typedef enum
{
    /** PAM signalling mode */
    SRM_SIGNAL_MODE_PAM = 0,
    /** NRZ signalling mode */
    SRM_SIGNAL_MODE_NRZ = 1,

} e_srm_signal_mode;


/**
 * This rule is used to define the source of the TX
 * data.
 */
typedef enum
{
    /**
     * The TX data to transmit comes from the
     * comes from the core/parallel bus
     */
    SRM_TX_SRC_CORE = 0,

    /**
     * The TX data comes from the serial RX via loopback.
     * Note that this is only valid if the RX and TX are in
     * the same RX/TX block of a single IP instance. This is 
     * referred to as a SERIAL FAR loopback*/
    SRM_TX_SRC_RX_LOOPBACK = 1,

    /**
     * The TX data comes from the Core TX traffic generator.
     * The TX clock comes from the local analog clock which is
     * always present even if there is no data on the core/parallel
     * bus.
     */
    SRM_TX_SRC_PAT_GEN = 2,
    
    /**
     * The TX data comes from the Serial TX traffic generator.
     * The TX clock comes from the local analog clock which is
     * always present even if there is no data on the core/parallel
     * bus.
     */
    SRM_TX_SRC_PAT_GEN_SERIAL = 3,
    
    /**
     * The TX data comes from the serial RX via deep loopback
     * throught the core. Note that this is only valid if the RX and TX are in
     * the same RX/TX block of a single IP instance. */
    SRM_TX_SRC_RX_DEEP_LOOPBACK = 4

} e_srm_tx_src;


/**
 * This rule is used to define the source of the RX
 * data to send across the core/parallel bus.
 */
typedef enum
{
    /** The RX data comes from the serial side receiver */
    SRM_RX_SRC_SERIAL = 0,

    /**
     * The RX data comes TX via the near end loopback. Note
     * that this is only valid if the RX and TX are in the
     * same RX/TX block of a single IP instance. This is 
     * referred to as a CORE NEAR loopback */
    SRM_RX_SRC_TX_LOOPBACK = 1,

    /**
     * The RX data comes from the local traffic generator.
     * The generated data is clocked from the recovered clock
     * which is always be present even if no data is received
     * on the serial interface.
     */
    SRM_RX_SRC_PAT_GEN = 2,
} e_srm_rx_src;


/**
 * The DSP mode 
 *
 * Each of the suggestions below are only guidelines, your selection of DSP mode is very
 * system dependant. Contact your customer support rep and start a discussion on which DSP
 * mode is best for your platform.
 *
 * Nomenclature:
 *
 * - FFE is the feed forward equalizer, and is enabled for all modes
 * - Slicer is what slices the PAM4 signal at different voltages, and is enabled for all modes
 * - RC is the reflection canceler, which extends the FFE and smooths out the tail in the pulse response.
 *   Used for links with strong reflections or too much energy in the pulse response tail.
 * - LDEQ is the level-dependant equalizer, which will equalize the eyes differently for each
 *   voltage level. Used for optics which may have non-uniform eye openings at each voltage.
 * - DFE is the decision feedback equalizer, used for strenuous links.
 *
 */
typedef enum
{
    /** PAM4 slicer, used for short non-strenuous links */
    SRM_DSP_MODE_SLC1                = 0,
    /** PAM4 slicer with reflection canceller */
    SRM_DSP_MODE_SLC1_RC_SLC2        = 2,
    /** Decision Feedback Equalizer (DFE) */
    SRM_DSP_MODE_DFE1                = 4,
    /** DFE with reflection canceller */
    SRM_DSP_MODE_DFE1_RC_DFE2        = 7,

} e_srm_dsp_mode;

/**
 * Selected data-rate, all units are kilo Baud per second (kBd/s). 
 * Note that when the channel is configured for NRZ signalling, the data-rate equals the baud-rate.
 * When configured for PAM signalling, the data-rate is 2x the baud-rate.
 */
typedef enum
{
    /** 19.90656 Gbaud */
    SRM_BAUD_RATE_19p90656G   = 19906560,
    /** 20 Gbaud */
    SRM_BAUD_RATE_20p0G       = 20000000,
    /** 20.625 Gbaud */
    SRM_BAUD_RATE_20p625G     = 20625000,
    /** 21.0562 Gbaud */
    SRM_BAUD_RATE_21p0562G    = 21056200,
    /** 21.418 Gbaud */
    SRM_BAUD_RATE_21p418G     = 21418000,
    /** 21.51 Gbaud */
    SRM_BAUD_RATE_21p51G      = 21510000,
    /** 21.875 Gbaud */
    SRM_BAUD_RATE_21p875G     = 21875000,
    /** 22.098 Gbaud */
    SRM_BAUD_RATE_22p098G     = 22098000,
    /** 22.1914 Gbaud */
    SRM_BAUD_RATE_22p1914G    = 22191400,
    /** 22.362 Gbaud */
    SRM_BAUD_RATE_22p362G     = 22362000,
    /** 22.5 Gbaud */
    SRM_BAUD_RATE_22p5G       = 22500000,
#ifdef SYRMA_ASYNC
    /** 23.90625 Gbaud */
    SRM_BAUD_RATE_23p90625G   = 23906250,
#endif //SYRMA_ASYNC
    /** 23.125 Gbaud */
    SRM_BAUD_RATE_23p125G     = 23125000,
    /** 23.75 Gbaud */
    SRM_BAUD_RATE_23p75G      = 23750000,
    /** 25 Gbaud */
    SRM_BAUD_RATE_25p0G       = 25000000,
    /** 25.234375 Gbaud */
    SRM_BAUD_RATE_25p234375G  = 25234375,
    /** 25.5 Gbaud */
    SRM_BAUD_RATE_25p5G       = 25500000,
    /** 25.78125 Gbaud */
    SRM_BAUD_RATE_25p78125G   = 25781250,
    /** 26.5625 Gbaud */
    SRM_BAUD_RATE_26p5625G    = 26562500,
    /** 27.34375 Gbaud */
    SRM_BAUD_RATE_27p34375G   = 27343750,
    /** 27.78125 Gbaud */
    SRM_BAUD_RATE_27p78125G   = 27781250,
    /** 27.95 Gbaud */
    SRM_BAUD_RATE_27p95G      = 27950000,
    /** 28.05 Gbaud */
    SRM_BAUD_RATE_28p05G      = 28050000,
    /** 28.125 Gbaud */
    SRM_BAUD_RATE_28p125G     = 28125000

} e_srm_baud_rates;


/**
 * The ADC subrate divide ratio
 */
typedef enum
{
    /** Bypass */
    SRM_SUBRATE_BYPASS = 0,
    /** Divide by 2 */
    SRM_SUBRATE_DIV_2  = 1,
    /** Divide by 4 */
    SRM_SUBRATE_DIV_4  = 2,
    /** Divide by 5 */
    SRM_SUBRATE_DIV_5  = 3,
    /** Divide by 8 */
    SRM_SUBRATE_DIV_8  = 4,
    /** Divide by 16 */
    SRM_SUBRATE_DIV_16 = 5,

} e_srm_subrate_ratio;


/**
 * The Transmitter Look-Up-Table (LUT) configuration
 */
typedef enum
{

    /** 3-tap non-linear mode. 3-tap convolution and non-linear LUT combined into one step via a 64-to-1 LUT */
    SRM_TX_LUT_3TAP     = 0,
    /** Not supported. Bypass mode. Directly maps one PAM4 symbol to one 7-bit FIR sample via a 4-to-1 LUT */
    SRM_TX_LUT_BYPASS   = 1,
    /** 7-tap linear mode. The block bypasses non-linear LUT, and outputs the 7-tap convolution directly */
    SRM_TX_LUT_7TAP_LIN = 2,
    /** Not supported. 7-tap non-linear mode. The computation is divided into two steps: 7-tap convolution and non-linear 128-to-1 LUT */
    SRM_TX_LUT_7TAP_LUT = 3

} e_srm_lut_mode;

/**
 * Tx VDDR voltage supply 
 */
typedef enum
{
    /** Tx VDDR supply, 1.125 V */
    SRM_VDDR_TX_1p125 = 0,
    /** Tx VDDR supply, 1.6 V */
    SRM_VDDR_TX_1p6 = 2,
    /** Tx VDDR supply, 1.95 V */
    SRM_VDDR_TX_1p95 = 3

} e_srm_vddr_tx;



/**
 * Control the AFE input termination block
 */
typedef enum
{
    /** Input shorting switch enable */
    SRM_AFE_TRIM_ISSE = 1,
    /** 0 dB */
    SRM_AFE_TRIM_0dB = 2,  
    /** -4 dB */
    SRM_AFE_TRIM_NEG_4dB = 4,
    /** -10 dB */
    SRM_AFE_TRIM_NEG_10dB = 16,

}e_srm_afe_trim;

/**
 * The TX swing is not currently supported by
 * the SRM hardware and will be ignored during
 * configuration.
 */
typedef enum 
{
    /** 60 percent Tx swing */
    SRM_TX_SWING_60p  = 0,
    /** 70 percent Tx swing */
    SRM_TX_SWING_70p  = 1,
    /** 80 percent Tx swing */
    SRM_TX_SWING_80p  = 2,
    /** 90 percent Tx swing */
    SRM_TX_SWING_90p  = 3,
    /** 100 percent Tx swing */
    SRM_TX_SWING_100p = 4,
    /** 110 percent Tx swing */
    SRM_TX_SWING_110p = 5,
    /** 120 percent Tx swing */
    SRM_TX_SWING_120p = 6 

} e_srm_tx_swing;

/**
 * LDO power-up calibration modes
 */
typedef enum
{
    /** Power up all the LDOs - this mode is not really used */
    SRM_PWRUP_BYPASS_NONE = 0,
    /** Bypass all the LDOs - this is the lowest power but not recommended */
    SRM_PWRUP_BYPASS_ALL  = 1,
    /** Bypass the RX and TX only */
    SRM_PWRUP_BYPASS_TXRX = 2,

    /** For backwards compatiblity */
    SRM_CAL_BYPASS_NONE  = 0,
    /** For backwards compatiblity */
    SRM_CAL_BYPASS_ALL   = 1,
    /** For backwards compatiblity */
    SRM_CAL_BYPASS_TXRX  = 2,
    /** For backwards compatibility - by default point the API to the .mode rule instead of the legacy .cal_mode */
    SRM_PWRUP_USE_MODE_RULE = 3,

} e_srm_pwrup_mode;

/** For backwards compability */
typedef e_srm_pwrup_mode e_srm_cal_mode;


/**
 * This structure contains the rules used to control
 * the Calibration of the device.
 */
typedef struct
{
    /** Used to idenifiy the IP block containing the ERU */
    uint32_t eru_die;

    /** Used to identify the individual IP blocks in the chain */
    uint32_t srm_dies[SRM_MAX_SRM_PER_ERU];

    /** The number of SRM dies in this ERU block (max 32), see SRM_MAX_SRM_PER_ERU */
    uint8_t num_srm_in_chain;

    /** Regulator power-up modes */
    e_srm_pwrup_mode mode;

    /** Old powerup mode for backwards compatibility - use .mode instead */
    e_srm_pwrup_mode cal_mode;

    /** Maximum LDOs to powerup */
    uint8_t max_ldo_count;

    /** Flag to enable debug prints */
    bool show_debug_info;

    /** Enable calibration */
    bool enable_calibration;

    /** Enable rcal */
    bool enable_rcal;

    /** The number of retry attempts if calibration fails */
    int retry_attempts;

    /** Is the ERU present */
    bool has_eru;

} srm_pwrup_rules_t;

// For backwards compatibility
typedef srm_pwrup_rules_t srm_cal_rules_t;

/**
 * This structure defines the R-Cal status for a particular Bias block
 */
typedef struct
{
    /** R-Cal Done */
    bool    done;
    /** R-Cal Code */
    uint8_t code;
    /** R-Cal successful */
    bool    success;
}srm_rcal_bias_status_t;

/**
 * This structure defines the R-Cal status for the IP chain
 */
typedef struct
{
    /** R-Cal operation successful */
    bool success;
    /** ERU status */
    srm_rcal_bias_status_t eru_status;
    /** Bias Statuses */
    srm_rcal_bias_status_t bias_status[32];
}srm_rcal_status_t;

/**
 * This structure contains the rules used to control
 * the PLL of the device.
 */
typedef struct
{
    /**
     * Selected data-rates, all units are kilo Baud per second (kBd/s). 
     * Note that when the channel is configured for NRZ signalling, the data-rate equals the baud-rate.
     * When configured for PAM signalling, the data-rate is 2x the baud-rate.
     * See the e_srm_baud_rates enum for a list of supported data-rates.
     */
    uint32_t baud_rate;

    /** Bypass or disable the temperature monitor based calibration */
    bool tmon_cal_disable;

    /** Force a particular temperature when calibrating the PLL based on temperature */
    uint8_t tmon_cal_force;

    /** Disable PLL analog tuning */
    bool pll_settings_disable;

    /** Disable re-programming the PLL when LOL detected */
    bool pll_ignore_lol;

} srm_pll_rules_t;

/**
 * This structure contains the RX quality check rules which are used
 * to ensure a minimum level of signal quality from the receiver.
 */
typedef struct
{
    /** Flag to disable the RX quality-check feature completely */
    bool dis;

    /** Flag to disable the RX quality-check using histogram */
    bool hist_dis;

    /** If the SNR monitor detects a MSE value below this threshold then check failed */ 
    uint8_t mse_min_threshold;

    /** Number of consecutive SNR monitor check pass before it enters into stead state */ 
    uint8_t retry_pass_max;

    /** Flag to disable the RX quality-check during steady state (aka mission mode, data mode, etc.) */
    bool data_mode_dis;

    /** Flag to disable the RX quality-check using histogram during steady state (aka mission mode, data mode, etc.) */
    bool data_mode_hist_dis;

    /** If the SNR monitor detects a MSE value below this threshold during steady state, then check failed */ 
    uint8_t data_mode_mse_min_threshold;

    /** Number of consecutive SNR monitor check failure during steady state before triggering a Rx restart */ 
    uint8_t data_mode_retry_fail_max;

} srm_rx_qc_rules_t;


/**
 * Configuration bitmask allowing additional control
 * over the RXA powerup sequence.
 */
typedef enum
{
    /** Default behavior - power up/down each channel on demand */
    SRM_RXA_PWRUP_ON_DEMAND = 0,
    /** Ripple power up/down the RXA (Analog blocks) */
    SRM_RXA_PWRUP_RIPPLE    = 1,
    /** Keep the RXA always powered up when srm_init_rx is called */
    SRM_RXA_PWRUP_ALWAYS_ON = 2,
    /** Power up the entire dual (two channels) when the RX is powered up (first call to srm_init_rx) */
    SRM_RXA_PWRUP_DUAL      = 4 
}e_srm_rxa_sequence_ctrl;


/**
 * This structure contains the rules used to control
 * the receivers of the device.
 */
typedef struct
{
    /**
     * Enable/disable the RX channel. If this is set to
     * disable the channel will be powered down
     */
    bool enable;

    /**
     * The source of the RX data to forward
     * across the core/parallel bus (serial data, loopback, local PRBS)
     */
    e_srm_rx_src src;

    /** Subrate ratio */
    e_srm_subrate_ratio subrate_ratio;

    /** Signalling type, NRZ or PAM */
    e_srm_signal_mode signalling;

    /** DSP mode */
    e_srm_dsp_mode dsp_mode;

    /** Gray mapping */
    bool gray_mapping;

    /**
     * IEEE Demap, sometimes called bit order. True to use the IEEE standard bit order of LSB-first,
     * false to use legacy bit order of MSB-first.
     *
     * This should always be left to true unless the other device is connected
     * to (on either host or line) is a legacy device (ie 28nm PAM B0). Even in those cases, the
     * latest APIs for legacy devices support IEEE mode, and should be enabled on those devices.
     */
    bool ieee_demap;

    /**
     * DFE precoder enable. The DFE precoder helps to transform
     * burst errors from the DFE to error events with smaller number of bit
     * flips in order to improve BER. The precoder should not be turned on in
     * non-DFE modes since it can actually increase the BER.
     *
     * @{note,
     * - the link partner's transmit precoder must be enabled if
     *   this rule is set to true.
     * - the precoder should only be enabled in PAM mode (it should
     *   be turned off in NRZ)
     * }
     */
    bool dfe_precoder_en;

    /** CTLE code */
    uint16_t ctle_code;

    /** Rx channel inversion */
    bool invert_chan;

    /** Control the AFE input termination block */
    e_srm_afe_trim afe_trim;

    /** Enable VGA tracking */
    bool vga_tracking;

    /** Enable 8b/10b Idle Pattern Protection */
    bool ipp_en;

    /** When there is an external AC cap, bypass the internal RX AC coupling logic */
    bool ac_coupling_bypass;

    /** RX quality-check rules */
    srm_rx_qc_rules_t rx_qc;

    /** Bypass the sub-ADC reference trimming algorithm in the f/w */
    bool bypass_reftrim_fw;

    /** set to 1 to bypass the sub-AD trim fine-tune step */
    bool bypass_reftrim_finetune;

    /** Preamp bias current control */
    uint8_t preamp_bias_ctrl;

    /** Turn on the serial side PRBS checker in auto mode */
    bool prbs_chk_en;
    
    /** Enable hardware based PGA attenuation control */
    bool pga_att_en;

    /**
     * Finer control over the RXA powerup sequence. This
     * should normally be left at the default setting but may be
     * changed if required
     *
     * - SRM_RXA_PWRUP_ON_DEMAND (0 = current behavior, power up/down channels on demand)
     * - SRM_RXA_PWRUP_RIPPLE    (1 = Ripple power up/down the analog control bits)
     * - SRM_RXA_PWRUP_ALWAYS_ON (2 = Leave the RX analog always on once powered up)
     * - SRM_RXA_PWRUP_DUAL + SRM_RXA_PWRUP_ALWAYS_ON ( Turn the RX analog supplies for the dual on and leave it on on the first call to srm_init_rx)
     * - SRM_RXA_PWRUP_DUAL + SRM_RXA_PWRUP_ALWAYS_ON + SRM_RXA_PWRUP_RIPPLE (Ripple power up the dual and leave it on)
     */
    uint8_t rxa_sequence;

} srm_rx_rules_t;

/**
 * This structure contains the rules used 
 * for querying/managing the TX FIR. This is used to change
 * the TX coefficients without restarting the TX.
 */
typedef struct
{
    /** LUT mode */
    e_srm_lut_mode lut_mode;

    /**
     * @{warning,
     * The Tx swing is not currently supported by the SRM hardware
     * and is ignored during configuration.
     * }
     */
    e_srm_tx_swing swing;

    /** FIR Taps 1 through 7 supporting each of the TX FIR modes (3-tap, 7-tap).
     *
     * Each tap ranges from -1000 to 1000 where:
     * - @{b,-1000} = -1.0
     * - @{b,+1000} = +1.0
     *
     * The taps are scaled by 1000 to avoid floating point numbers.
     *
     * In 3-Tap mode:
     * - fir_tap[0] = Pre Tap  
     * - fir_tap[1] = Main Tap 
     * - fir_tap[2] = Post Tap
     * 
     * @{note,
     * Each tap will be scaled proportionally by the embedded firmware to ensure that
     * absolute sum of the taps does not exceed 1000. 
     * 
     * If the absolute sum of the taps is less than 1000 the firmware will not
     * do any scaling.
     * }
     */  
    int16_t fir_tap[7];

    /** Scale PAM lower inner eye, range 500 to 1500 where 500 = 0.5, 1500 = 1.5 */
    uint16_t inner_eye1;

    /** Scale PAM upper inner eye, range 1500 to 2500 where 1500 = 1.5, 2500 = 2.5 */
    uint16_t inner_eye2;

}srm_tx_fir_t;
 
/**
 * This structure contains the rules used to control
 * the transmitters of the device.
 */
typedef struct
{
    /**
     * Enable/disable the TX channel. If this is set to
     * disable the channel will be powered down
     */
    bool enable;

    /**
     * Lock the TX open/un-squelch for manual control by host supervisor. The firmware
     * may still squelch the TX but it cannont un-squelch when this flag
     * is asserted
     */
    bool squelch_lock;
    
    /**
     * The source of the TX data to transmit out the
     * serial bus
     * (core/parallel data, loopback, local PRBS)
     */
    e_srm_tx_src src;

    /** Subrate ratio */
    e_srm_subrate_ratio subrate_ratio;

    /** Signalling type, NRZ or PAM */
    e_srm_signal_mode signalling;

    /** LUT mode */
    e_srm_lut_mode lut_mode;

    /** Gray mapping */
    bool gray_mapping;  

     /**
      * IEEE Demap, sometimes called bit order. True to use the IEEE standard bit order of LSB-first,
      * false to use legacy bit order of MSB-first.
      *
      * This should always be left to true unless the other device is connected
      * to (on either host or line) is a legacy device (ie 28nm PAM B0). Even in those cases, the
      * latest APIs for legacy devices support IEEE mode, and should be enabled on those devices.
      */
    bool ieee_demap;

    /**
     * DFE precoder enable. The DFE precoder helps to transform
     * burst errors from the DFE to error events with smaller number of bit
     * flips in order to improve BER. The precoder should not be turned on in
     * non-DFE modes since it can actually increase the BER.
     *
     * @{note,
     * - the link partner's receive precoder must be enabled if
     *   this rule is set to true.
     * - the precoder should only be enabled in PAM mode (it should
     *   be turned off in NRZ)
     * }
     */
    bool precoder_en;  

    /** channel inversion */
    bool invert_chan;
    
    /**
     * @{warning,
     * The Tx swing is not currently supported by the SRM hardware
     * and is ignored during configuration.
     * }
     */
    e_srm_tx_swing swing;

    /** FIR Taps 1 through 7 supporting each of the TX FIR modes (3-tap, 7-tap).
     *
     * Each tap ranges from -1000 to 1000 where:
     * - @{b,-1000} = -1.0
     * - @{b,+1000} = +1.0
     *
     * The taps are scaled by 1000 to avoid floating point numbers.
     *
     * In 3-Tap mode:
     * - fir_tap[0] = Pre Tap  
     * - fir_tap[1] = Main Tap 
     * - fir_tap[2] = Post Tap
     * 
     * @{note,
     * Each tap will be scaled proportionally by the embedded firmware to ensure that
     * absolute sum of the taps does not exceed 1000. 
     * 
     * If the absolute sum of the taps is less than 1000 the firmware will not
     * do any scaling.
     * }
     */  
    int16_t fir_tap[7];

    /** Scale PAM lower inner eye, range 500 to 1500 where 500 = 0.5, 1500 = 1.5 */
    uint16_t inner_eye1;

    /** Scale PAM upper inner eye, range 1500 to 2500 where 1500 = 1.5, 2500 = 2.5 */
    uint16_t inner_eye2;

} srm_tx_rules_t;



/**
 * This structure contains the rules used to control
 * the receivers of a bundle for ANLT purpose.
 */
typedef struct
{
    /**
     * Enable/disable the RX channel. If this is set to
     * disable the channel will be powered down
     */
    bool enable;

    /**
     * The source of the RX data to forward
     * across the core/parallel bus (serial data, loopback, local PRBS)
     */
    e_srm_rx_src src;

    /** Subrate ratio */
    e_srm_subrate_ratio subrate_ratio;

    /** Signalling type, NRZ or PAM */
    e_srm_signal_mode signalling;

    /** DSP mode */
    e_srm_dsp_mode dsp_mode;

    /** Gray mapping */
    bool gray_mapping;

    /**
     * IEEE Demap, sometimes called bit order. True to use the IEEE standard bit order of LSB-first,
     * false to use legacy bit order of MSB-first.
     *
     * This should always be left to true unless the other device is connected
     * to (on either host or line) is a legacy device (ie 28nm PAM B0). Even in those cases, the
     * latest APIs for legacy devices support IEEE mode, and should be enabled on those devices.
     */
    bool ieee_demap;

    /**
     * DFE precoder enable. The DFE precoder helps to transform
     * burst errors from the DFE to error events with smaller number of bit
     * flips in order to improve BER. The precoder should not be turned on in
     * non-DFE modes since it can actually increase the BER.
     *
     * @{note,
     * - the link partner's transmit precoder must be enabled if
     *   this rule is set to true.
     * - the precoder should only be enabled in PAM mode (it should
     *   be turned off in NRZ)
     * }
     */
    bool dfe_precoder_en;

    /** CTLE code */
    uint8_t ctle_code[8];

    /** channel inversion */
    bool invert_chan[8];

    /** Control the AFE input termination block */
    e_srm_afe_trim afe_trim[8];

    /** Enable VGA tracking */
    bool vga_tracking;

    /** Enable 8b/10b Idle Pattern Protection */
    bool ipp_en;

    /** When there is an external AC cap, bypass the internal RX AC coupling logic */
    bool ac_coupling_bypass;

    /** RX quality-check rules */
    srm_rx_qc_rules_t rx_qc;

    /** Bypass the sub-ADC reference trimming algorithm in the f/w */
    bool bypass_reftrim_fw;

    /** set to 1 to bypass the sub-AD trim fine-tune step */
    bool bypass_reftrim_finetune;

    /** Preamp bias current control */
    uint8_t preamp_bias_ctrl;

    /** Turn on the serial side PRBS checker in auto mode */
    bool prbs_chk_en;

    /** Enable hardware based PGA attenuation control */
    bool pga_att_en;

    /**
     * Finer control over the RXA powerup sequence. This
     * should normally be left at the default setting but may be
     * changed if required
     *
     * - SRM_RXA_PWRUP_ON_DEMAND (0 = current behavior, power up/down channels on demand)
     * - SRM_RXA_PWRUP_RIPPLE    (1 = Ripple power up/down the analog control bits)
     * - SRM_RXA_PWRUP_ALWAYS_ON (2 = Leave the RX analog always on once powered up)
     * - SRM_RXA_PWRUP_DUAL + SRM_RXA_PWRUP_ALWAYS_ON ( Turn the RX analog supplies for the dual on and leave it on on the first call to srm_init_rx)
     * - SRM_RXA_PWRUP_DUAL + SRM_RXA_PWRUP_ALWAYS_ON + SRM_RXA_PWRUP_RIPPLE (Ripple power up the dual and leave it on)
     */
    uint8_t rxa_sequence;

} srm_rx_bundle_rules_t;


/**
 * This structure contains the rules used to control
 * the transmitters of the device.
 */
typedef struct
{
    /**
     * Enable/disable the TX channel. If this is set to
     * disable the channel will be powered down
     */
    bool enable;

    /**
     * Lock the TX open/un-squelch for manual control by host supervisor. The firmware
     * may still squelch the TX but it cannont un-squelch when this flag
     * is asserted
     */
    bool squelch_lock;
    
    /**
     * The source of the TX data to transmit out the
     * serial bus
     * (core/parallel data, loopback, local PRBS)
     */
    e_srm_tx_src src;

    /** Subrate ratio */
    e_srm_subrate_ratio subrate_ratio;

    /** Signalling type, NRZ or PAM */
    e_srm_signal_mode signalling;

    /** LUT mode */
    e_srm_lut_mode lut_mode;

    /** Gray mapping */
    bool gray_mapping;  

     /**
      * IEEE Demap, sometimes called bit order. True to use the IEEE standard bit order of LSB-first,
      * false to use legacy bit order of MSB-first.
      *
      * This should always be left to true unless the other device is connected
      * to (on either host or line) is a legacy device (ie 28nm PAM B0). Even in those cases, the
      * latest APIs for legacy devices support IEEE mode, and should be enabled on those devices.
      */
    bool ieee_demap;

    /**
     * DFE precoder enable. The DFE precoder helps to transform
     * burst errors from the DFE to error events with smaller number of bit
     * flips in order to improve BER. The precoder should not be turned on in
     * non-DFE modes since it can actually increase the BER.
     *
     * @{note,
     * - the link partner's receive precoder must be enabled if
     *   this rule is set to true.
     * - the precoder should only be enabled in PAM mode (it should
     *   be turned off in NRZ)
     * }
     */
    bool precoder_en;  

    /** channel inversion */
    bool invert_chan[8];
    
    /**
     * @{warning,
     * The Tx swing is not currently supported by the SRM hardware
     * and is ignored during configuration.
     * }
     */
    e_srm_tx_swing swing[8];

    /** FIR Taps 1 through 7 supporting each of the TX FIR modes (3-tap, 7-tap).
     *
     * Each tap ranges from -1000 to 1000 where:
     * - @{b,-1000} = -1.0
     * - @{b,+1000} = +1.0
     *
     * The taps are scaled by 1000 to avoid floating point numbers.
     *
     * In 3-Tap mode:
     * - fir_tap[0] = Pre Tap  
     * - fir_tap[1] = Main Tap 
     * - fir_tap[2] = Post Tap
     * 
     * @{note,
     * Each tap will be scaled proportionally by the embedded firmware to ensure that
     * absolute sum of the taps does not exceed 1000. 
     * 
     * If the absolute sum of the taps is less than 1000 the firmware will not
     * do any scaling.
     * }
     */  
    int16_t fir_tap[8][7];

    /** Scale PAM lower inner eye, range 500 to 1500 where 500 = 0.5, 1500 = 1.5 */
    uint16_t inner_eye1[8];

    /** Scale PAM upper inner eye, range 1500 to 2500 where 1500 = 1.5, 2500 = 2.5 */
    uint16_t inner_eye2[8];

} srm_tx_bundle_rules_t;



/**
 * @h2 AN/LT Configuration Types
 *
 * @brief
 * AN/LT negotiation status
 */
#define SRM_AN_CAPABILITY_COUNT      (15)
#define SRM_AN_CAPABILITY_COUNT_EVEN (16)

typedef enum 
{
    /** Local device AN Ongoing */
    SRM_AN_STATUS_BUSY,

    /** Highest common denominator resolved */
    SRM_AN_STATUS_RESOLVED,

    /** Link training complete */
    SRM_AN_STATUS_LT_COMPLETE,

    /** Local device AN complete */
    SRM_AN_STATUS_COMPLETE,

    /** Local device no rate match */
    SRM_AN_STATUS_FAIL,

} e_srm_anlt_an_status; 


/**
 * AN modes
 */
typedef enum
{
    /** IEEE mode */
    SRM_AN_MODE_IEEE = 0,

    /** 50G Consortium Mode */
    SRM_AN_MODE_50G_CONSORTIUM_NP = 1,

    /** Broadcom Next Page Mode */
    SRM_AN_MODE_BROADCOM_NP = 2,

    /** Proprietary AN NEXT PAGE (PAN) Mode */
    SRM_AN_MODE_PAN_NP = 4,
}
e_srm_anlt_mode;


/** Configure the source clock for training */
typedef enum
{
    /** Perform training from the local reference clock */
    SRM_ANLT_LT_LOCAL_REFERENCE = 0,

    /** Perform training from the recovered clock */
    SRM_ANLT_LT_RECOVERED_CLOCK = 1
}e_srm_anlt_lt_clk_src;


/** Clause 136 PRESET type*/
typedef enum
{
    SRM_ANLT_LT_CL136_PRESET1 = 1,
    SRM_ANLT_LT_CL136_PRESET2 = 2,
    SRM_ANLT_LT_CL136_PRESET3 = 3,
} e_srm_anlt_lt_cl136_preset_type;


/** Configure the training algorithm  bit mask */
typedef enum
{
    SRM_ALGO_TYPE_INIT_MASK      = 0x0004,          // 0 : SRM_ALGO_IEEE_INIT          Set FIR taps based on IEEE Std
                                                    // 1 : SRM_ALGO_USER_INIT          Set FIR taps specified by user
    SRM_ALGO_TYPE_TUNE_STEP_MASK = 0x0008,          // 0 : SRM_ALGO_SMALL_TUNE_STEP    Send the command once
                                                    // 1 : SRM_ALGO_LARGE_TUNE_STEP    Send the command twice
    SRM_ALGO_SKIP_PRESET_MASK    = 0x0010,          // 0 : SRM_ALGO_SKIP_PRESET        Do not send PRESET command
                                                    // 1 : SRM_ALGO_SEND_PRESET        Send PRESET command
    SRM_ALGO_FIR_STEP_SIZE_MASK  = 0x0020,          // 0 : SRM_ALGO_SMALL_FIR_STEP     LT step size of 2^1 = 2. Each tap inc/dec by 2
                                                    // 1 : SRM_ALGO_LARGE_FIR_STEP     LT setp size  = 2^2 = 4. Each tap inc/dec by 4

} e_srm_kran_training_algo_mask;


/** AN Ability */
typedef enum
{
    SRM_AN_NOT_SUPPORTED,
    SRM_AN_10GBASE_KR,
    SRM_AN_25GBASE_KR,
    SRM_AN_25GBASE_KR_S,
    SRM_AN_40GBASE_CR4,
    SRM_AN_40GBASE_KR4,
    SRM_AN_50GBASE_KR,
    SRM_AN_100GBASE_KR2,
    SRM_AN_100GBASE_KR4,
    SRM_AN_100GBASE_CR4,
    SRM_AN_200GBASE_KR4,
    SRM_AN_25GBASE_KR1_CONS,
    SRM_AN_25GBASE_CR1_CONS,
    SRM_AN_50GBASE_KR2_CONS,
    SRM_AN_50GBASE_CR2_CONS,
    SRM_AN_400GBASE_KR8_CONS,
    SRM_AN_400GBASE_KR8_BRCM,
    SRM_AN_1_25GBASE_KX,
    SRM_AN_2_5GBASE_KX,
    SRM_AN_5GBASE_KR,
} e_srm_kran_ability;


/** FEC Protocol */
typedef enum
{
   SRM_FEC_TYPE_NONE     = 0,     // No FEC
   SRM_FEC_TYPE_FIRECODE = 1,     // Firecode FEC Clause 74 (NRZ Only)
   SRM_FEC_TYPE_RS528    = 2,     // RS528/514 FEC
   SRM_FEC_TYPE_RS544    = 3,     // RS544 FEC
   SRM_FEC_TYPE_RS272    = 4,     // RS272 FEC
}e_srm_fec_type;


/**
 * The configuration information for training
 *
 * @since 0.1
 */
typedef struct
{
    /** Turn on training */
    bool enable;

    /** Terminate training prematurely. This rule is for
     * future use and can be ignored. */
    bool tune_term;

    /** The training clock source */
    e_srm_anlt_lt_clk_src clk_src;

    /** The retry threshold if training fails */
    uint16_t  retry_threshold;
    
    /** The target SNR for the link in units of milli-dB. For
     * example:
     * - 19.5dB = 19500
     * - 24.5dB = 24500*/
    uint16_t target_snr;

    /** Walk the CTLE until SNR improves. The link_time_budget
     * may need to be extended to support CTLE tuning. This may
     * not be supported by all link partners. For example, in NRZ
     * mode (Link Training clause 72) it may not be possible to do CTLE
     * tuning and it may need to be programmed manually.
     */
    bool ctle_tune;

    /** Extend the link training time (deprecated) */
    /** Deprecated */
    bool extend_link_time;

    /** Extend the link training time with specified amount */
    uint16_t extended_link_time;

    /** Unique LT algorithm based on observations in the field
        used to select FIR step, preset, tune step and initial
        FIR settings */
    uint8_t algorithm;

    /** Each nibble represents the frequency of corresponding
        LT algorithm specified by algo[4] array in FW */
    uint16_t algo_cycle;

    bool    ctle_cache;

    /** Send receiver ready request after max wait time expires */
    bool     honor_ieee_link_time;

    /** feature: auto precode threshold */
    uint8_t auto_rx_precode_threshold;

    /** Auto invert */
    bool    auto_invert;

    /** Bypass FIR walk */
    bool    bypass_fir_walk;

    /** Clause 136 PRESET type */
    e_srm_anlt_lt_cl136_preset_type cl136_preset;

}srm_anlt_lt_t;


/**
 * This structure is used to manage the auto-negotiation
 * of FEC associated with a particular data rate.
 */
typedef struct
{
    /** Device is FEC capable */
    bool capable;

    /** FEC is requested by the user */
    bool request;

}srm_anlt_fec_capability_t;


typedef struct
{
    /** Advertize the rate */
    bool advertise;
    
    /** predict the rate */
    bool predict;

    /** The array of supported FEC types 
        [0]: Firecode
        [1]: RS528
        [2]: RS544 */
    srm_anlt_fec_capability_t fec[3];
} srm_an_capability_t;

/**
 * This structure is used to support Consortium LL-FEC RS272 FEC fields
 */
typedef struct
{
   uint8_t lf1_capable:1;               // Ability for  50GBASE-CR1/KR1
   uint8_t lf2_capable:1;               // Ability for 100GBASE-CR2/KR2
   uint8_t lf3_capable:1;               // Ability for 200GBASE-CR4/KR4
   uint8_t ll_rs272_request:1;          // LL-RS-FEC Request
}srm_kran_llfec_cap_t;


/**
 * This structure is used to manage PAN (Proprietary AN Next Page) Mode
 *
 * @since 0.15
 */
typedef struct
{
   /** 48 bit raw oui page */
   uint64_t oui_page; 

   /** 48 bit oui mask     */
   uint64_t oui_mask; 

   /** 48 bit ext page     */
   uint64_t ext_page; 

   /** 48 bit ext mask     */
   uint64_t ext_mask; 

   /** 48 bit expectation page */
   uint64_t exp_page; 

   /** Baud Rate -- for NRZ it is same as Bit rate & for PAM4 it is half the bit rate */
   uint32_t baud_rate;

   /** Channels in bundle - user pre-configure data path */
   uint8_t  bundling;

   /** PAM4 / NRZ */
   uint8_t  modulation_mode;

}srm_anlt_pan_aware_t;




/**
 * The configuration information for auto-negotiation
 *
 * @since 0.1
 */
typedef struct
{
    /** Turn auto-negotiation on or off */
    bool enable;
    
    /** Probe only, do not proceed to link training / link up */
    bool probe;

    /** The autonegotiation mode */
    e_srm_anlt_mode mode;

    /** Retry threshold if AN fails */
    uint16_t retry_threshold;

    /** 1.25GBASE KX Capability */
    srm_an_capability_t an_1_25gbase_kx;

    /** 2.5GBASE KX Capability */
    srm_an_capability_t an_2_5gbase_kx;

    /** 5GBASE KR Capability */
    srm_an_capability_t an_5gbase_kr;

    /** 10GBASE KR Capability */
    srm_an_capability_t an_10gbase_kr;
    
    /** 25GBASE KR/CR Capability */
    srm_an_capability_t an_25gbase_kr;

    /** 25GBASE KR_S/CR_S Capability */
    srm_an_capability_t an_25gbase_kr_s;

    /** 25GBASE KR_CON Capability */
    srm_an_capability_t an_25gbase_kr_con;

    /** 25GBASE CR_CON Capability */
    srm_an_capability_t an_25gbase_cr_con;

    /** 40GBASE KR4 Capability */
    srm_an_capability_t an_40gbase_kr4;

    /** 40GBASE CR4 Capability */
    srm_an_capability_t an_40gbase_cr4;
    
    /** 50GBASE KR Capability */
    srm_an_capability_t an_50gbase_kr;

    /** 50GBASE KR2 Capability */
    srm_an_capability_t an_50gbase_kr2;

    /** 50GBASE CR2 Capability */
    srm_an_capability_t an_50gbase_cr2;

    /** 100GBASE KR2 Capability */
    srm_an_capability_t an_100gbase_kr2;

    /** 100GBASE KR4 Capability */
    srm_an_capability_t an_100gbase_kr4;
    
    /** 100GBASE CR4 Capability */
    srm_an_capability_t an_100gbase_cr4;

    /** 200GBASE KR4 Capability */
    srm_an_capability_t an_200gbase_kr4;

    /** 400GBASE KR8 Capability */
    srm_an_capability_t an_400gbase_kr8;

    /** FEC Capability */
    /** Deprecated */
    srm_anlt_fec_capability_t an_fec;

    /** Override link_time_budget of 500ms +/- 1% (clause 72), or 1.5s +/- 2% (clause 136) */
    uint16_t link_time_budget;

    /** Pause ability */
    uint8_t an_pause_ability;

    /** Remote fault */
    uint8_t an_remote_fault;

    /** (D13) Shut the port by keeping line squelched */
    bool port_shut;

    /** Advanced rules */
    uint16_t advanced[1];

    /** PAN capabilities */
    srm_anlt_pan_aware_t pan;

    /** AN Nonce check disable */
    bool nonce_chk_disable;

    /** LT Timer disable */
    bool lt_timer_disable;

    /** Consortium LLFEC Capability/Request */
    srm_kran_llfec_cap_t llfec_con;

}srm_anlt_an_t;


/**
 * The negotiated results from the AN sequence.
 *
 * @since 0.1
 */
typedef struct 
{
  /** HCD Rate */
  e_srm_kran_ability hcd_rate;

  /** FEC Type */
  e_srm_fec_type fec_type;
}
srm_anlt_results_t;


/**
 * Definitition for a single channel for AN/LT
 * which may be split across multiple SRM instances
 */
typedef struct
{
    /** The die of the receiver for the AN leader or LT follower */
    uint32_t rx_die;
    /** The channel of the receiver for the AN leader or LT follower */
    uint8_t  rx_channel;
    /** The die of the transmitter for the AN leader or LT follower */
    uint32_t tx_die;
    /** The channel of the transmitter for the AN leader or LT follower */
    uint8_t  tx_channel;
}srm_channel_t;


/**
 * This structure creates the team for the AN/LT session
 * including the AN leader, the LT followers and the configuration
 * rules for training, AN + PLL, RX and TX.
 */
typedef struct
{
    /** The AN leader */
    srm_channel_t       an_leader;
    /** The number of LT followers */
    uint8_t             num_followers;
    /** The list of LT followers */
    srm_channel_t       lt_followers[8]; 
}srm_anlt_bundle_t;


/**
 * This structure defines the rules for the AN/LT
 * session.
 */
typedef struct
{
    /** Auto-negotation rules for the AN leader */
    srm_anlt_an_t   an;  
    /** Link training rules for the LT followers */
    srm_anlt_lt_t   lt;  
    /** The initial RX configuration rules */
    srm_rx_bundle_rules_t  rx;
    /** The initial TX configuration rules */
    srm_tx_bundle_rules_t  tx;
    /** The initial PLL configuration rules */
    srm_pll_rules_t pll;
}srm_anlt_rules_t;


#endif // __SRM_RULES_H__
