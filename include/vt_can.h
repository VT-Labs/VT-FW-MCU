/*
 *  VT-Firewall library.
 *
 *  Copyright (C) 2018 Visual Threat Inc
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *   
 */

#ifndef VT_CAN_H_
#define VT_CAN_H_

#ifdef __cplusplus
extern "C" {
#endif
 
/*------------------------------------------------------------------*
 *                           Includes                               *
 *------------------------------------------------------------------*/
#include "Cpu.h"
#include "flexcan_driver.h"
#include "vt_fw_if.h"

/*------------------------------------------------------------------*
 *                          Define Macro                            *
 *------------------------------------------------------------------*/
//#define USING_BRIDGE     1

#if USING_CAN_FD
	#define VT_CAN_MTU 64
#else
	#define VT_CAN_MTU 8
#endif

#define VT_CAN_EXTENDED_MASK_CS 0x00680000
#define VT_CAN_STANDARD_MASK_CS 0x00080000

/*! @brief Device instance number */
#define VT_INST_CAN0 (0U)
#define VT_INST_CAN1 (2U)

/*------------------------------------------------------------------*
 *                Define Enumeration and Structure                  *
 *------------------------------------------------------------------*/

typedef enum {
	VT_BITRATE_125 = 0,
	VT_BITRATE_250,
	VT_BITRATE_500,
	VT_BITRATE_800,
	VT_BITRATE_1M,
	VT_BITRATE_UNKNOWN
} vt_can_bitrate_type_t;

/*------------------------------------------------------------------*
 *                     Define Callback Functions                    *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                        Global Data Types                         *
 *------------------------------------------------------------------*/
/*! @brief Driver state structure which holds driver runtime data */
extern flexcan_state_t vt_can_State;

/*------------------------------------------------------------------*
 *                   Callback Function Prototypes                   *
 *------------------------------------------------------------------*/
/*!
 * @brief  This function will be called when the CAN interrupt occurs. You can overwrite this function in your file.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      eventType - is type of the event which occurred when the callback was invoked
 *                  (e.g: FLEXCAN_EVENT_RX_COMPLETE, FLEXCAN_EVENT_RXFIFO_COMPLETE, FLEXCAN_EVENT_TX_COMPLETE).
 * @param [in]      *flexcanState - is a pointer to flexcan driver state structure.
 * @return          none.
 */
#ifdef S32R274RRUEVB
void vt_rcv_callback(uint8_t instance, flexcan_event_type_t eventType, uint32_t buffIdx, flexcan_state_t *flexcanState);
#else  /* MPC5748G Devkit */
void vt_rcv_callback(uint8_t instance, flexcan_event_type_t eventType, flexcan_state_t *flexcanState);
#endif

/*------------------------------------------------------------------*
 *                       Function Prototypes                        *
 *------------------------------------------------------------------*/
/*!
 * @brief  This API will initialize a CAN port.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      bitrate - is a CAN bit rate in vt_can_bitrate_type_t (e.g: VT_BITRATE_125, VT_BITRATE_500).
 * @param [in]      callback - callback function.
 * @param [in]      *callbackParam - pointer to parameter.
 * @return          STATUS_SUCCESS, STATUS_FLEXCAN_MB_OUT_OF_RANGE,
 *                  or STATUS_ERROR.
 */
status_t vt_init_can(uint8_t inst_can, vt_can_bitrate_type_t bitrate, flexcan_callback_t callback, void *callbackParam);

/*!
 * @brief  This API will set a bit-rate to CAN.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      bitrate - is a CAN bit rate in vt_can_bitrate_type_t (e.g: VT_BITRATE_125, VT_BITRATE_500).
 * @return          STATUS_SUCCESS
 *                  or STATUS_ERROR.
 */
status_t vt_set_bitrate_can(uint8_t inst_can, vt_can_bitrate_type_t bitrate);

/*!
 * @brief  This API will detect current bit rate of CAN bus.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      listen_only - enable or disable listen only foe auto detect mode.
 * @return          vt_can_bitrate_type_t (e.g: VT_BITRATE_125, VT_BITRATE_500 or VT_BITRATE_UNKNOWN).
 */
vt_can_bitrate_type_t vt_autodetect_bitrate(uint8_t inst_can, uint8_t listen_only);

/*!
 * @brief  This API will get a CAN message that it received successful.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @return          a pointer to a local message buffer if success.
 *                  NULL if don't have data coming.
 */
flexcan_msgbuff_t *vt_get_msg(uint8_t inst_can);

/*!
 * @brief  This API will send a CAN message.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      *msgbuff - is a pointer to flexcan message buffer structure.
 * @param [in]      id-type - is ID type of CAN (e.g: FLEXCAN_MSG_ID_STD, FLEXCAN_MSG_ID_EXT).
 * @return          STATUS_SUCCESS
 *                  or STATUS_ERROR.
 */
status_t vt_send_can_msg(uint8_t inst_can, flexcan_msgbuff_t *msgbuff, flexcan_msgbuff_id_type_t id_type);


/*!
 * @brief  This API will set buffer to Rxfifo to start receive CAN message.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @return          none.
 */
void vt_start_rcv(uint8_t inst_can);

/*------------------------------------------------------------------*
 *                Test Function and Examples                        *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *   Put example here
 *------------------------------------------------------------------*/
/*------------------------------------------------------------------*
 * Example 1: This example only receives all CAN messages with CAN ID from 1 to 128 and echo them.
 *          #include "vt_can.h"
 *
 *          flexcan_msgbuff_t *msg = NULL;
 *          vt_can_bitrate_type_t bitrate = VT_BITRATE_500; *
 *
 *
 *          while(1) {
 *          	if(bitrate >= VT_BITRATE_UNKNOWN )
 *				{
 *					bitrate = vt_autodetect_bitrate(0U);
 *					if(bitrate < VT_BITRATE_UNKNOWN)
 *					{
 *						vt_start_rcv(0U);
 *					}
 *				}
 *				else
 *				{
 *          		if((msg = vt_get_msg(0U)) != NULL)
 *          		{
 *          			if((msg->frame.cs & VT_CAN_EXTENDED_MASK_CS) == VT_CAN_EXTENDED_MASK_CS)
 *          			{
 *          				vt_send_can_msg(0U, msg, FLEXCAN_MSG_ID_EXT);
 *          			}
 *          			else
 *          			{
 *          				vt_send_can_msg(0U, msg, FLEXCAN_MSG_ID_STD);
 *          			}
 *          		}
 *          	}
 *          }
 *
 *------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* VT_CAN_H_ */
