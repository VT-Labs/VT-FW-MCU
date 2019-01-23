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

#ifndef VT_FW_IF_H_
#define VT_FW_IF_H_

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*
 *                           Includes                               *
 *------------------------------------------------------------------*/
#include <stdint.h>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

/*------------------------------------------------------------------*
 *                          Define macro                            *
 *------------------------------------------------------------------*/
#define VT_MAX_DATA_BYTE_LENGTH 8  
#define MAX_ROLL_INVALID_ID 10
/*------------------------------------------------------------------*
 *                Define Enumeration and Structure                  *
 *------------------------------------------------------------------*/
typedef enum _vt_detail_bit_t{
	VT_UNMATCHED_BIT          = 0,
	VT_FRAME_BIT              = (1 << 0),
	VT_RANGE_BIT              = (1 << 1),
    VT_PATTERN_BIT            = (1 << 2)
} vt_detail_bit_t;

typedef enum _vt_status_t
{
    /* Generic status codes */
	VT_STATUS_UNMATCHED     =  1,
    VT_STATUS_SUCCESS       =  0,
    VT_STATUS_ERROR         = -1,
    VT_STATUS_BUSY          = -2,
    VT_STATUS_TIMEOUT       = -3,
	VT_STATUS_NO_MEM        = -4,
	VT_STATUS_NULL          = -5,
	VT_STATUS_EMPTY         = -6,
	VT_STATUS_FULL          = -7,
	VT_STATUS_IO            = -8,
	VT_STATUS_INVALID       = -9,
	VT_STATUS_SEND_ERROR    = -10,
	VT_STATUS_RCV_ERROR     = -11,
	VT_STATUS_SMALL_BUFF    = -12,
	VT_STATUS_EXIST         = -13,
	VT_STATUS_UNREADY       = -14,
	VT_STATUS_INVALID_DATA	= -15,
	VT_STATUS_UNSUPPORTED   = -16
}vt_status_t;

typedef enum _vt_car_status_t
{
	VT_CAR_UNKOWN_STAT          = 0,
	VT_CAR_NORMAL_STAT          = (1 << 0),
	VT_CAR_IDLE_STAT            = (1 << 1),
	VT_CAR_ABNORMAL_STAT        = (1 << 2),
	VT_CAR_ABNORMAL_DS_TP_STAT  = (1 << 3),
	VT_CAR_ABNORMAL_OVER_STAT   = (1 << 4),
	VT_CAR_ABNORMAL_MALICIOUS	= (1 << 5),
	VT_CAR_ABNORMAL_INVALID_ID	= (1 << 6),
}vt_car_status_t;

typedef enum _vt_pattern_type_t
{
	VT_PATTERN_RANDOM = 0,    /*!< No sequence, no interval time. The element of pattern appear random */
	VT_PATTERN_NO_SEQ_ITV,    /*!< No sequence but the interval time must be less than the maximum interval time */
	VT_PATTERN_SEQ_NO_ITV,    /*!< No interval time but the CAN frame must appear in sequence */
	VT_PATTERN_SEQ_ITV,       /*!< have interval time and sequence */
	VT_PATTERN_UNKNOWN        /*!< Unknown this pattern */
} vt_pattern_type_t;

typedef enum _vt_frame_type_t
{
	VT_FRAME_NORMAL = 0,
	VT_FRAME_CAN_ID_INC,
	VT_FRAME_CAN_ID_DEC,
	VT_FRAME_BYTE_0_INC,
	VT_FRAME_BYTE_1_INC,
	VT_FRAME_BYTE_2_INC,
	VT_FRAME_BYTE_3_INC,
	VT_FRAME_BYTE_4_INC,
	VT_FRAME_BYTE_5_INC,
	VT_FRAME_BYTE_6_INC,
	VT_FRAME_BYTE_7_INC,
	VT_FRAME_BYTE_0_DEC,
	VT_FRAME_BYTE_1_DEC,
	VT_FRAME_BYTE_2_DEC,
	VT_FRAME_BYTE_3_DEC,
	VT_FRAME_BYTE_4_DEC,
	VT_FRAME_BYTE_5_DEC,
	VT_FRAME_BYTE_6_DEC,
	VT_FRAME_BYTE_7_DEC,
	VT_FRAME_UNKNOWN
} vt_frame_type_t;

typedef struct _vt_vector_result_t
{
	uint32_t count_vector_in_rl;   /*!< Count matched of unique vector in rule*/
	uint32_t count_vector_in_rt;   /*!< Count the occurrence of the unique vector in run time */
	float matched_rate;            /*!< matched rate */
	uint8_t matched_flag;          /*!< 1 is matched , 0 is unmatched */
	uint32_t count_all_vector;     /*!< Counts all occurrences of a vector in a time window */
	uint32_t count_invalid_vector_id;
	uint32_t invalid_id[MAX_ROLL_INVALID_ID]; /*!< save latest invalid id */
	uint32_t count_invalid_id_items;
} vt_vector_result_t;

typedef struct _vt_can_frame_t
{
	uint32_t msgId;                          
	uint8_t data[VT_MAX_DATA_BYTE_LENGTH];   
	uint8_t dataLen;                        
} vt_can_frame_t;

typedef struct _vt_message_buff_t{
	vt_can_frame_t frame;                    
	uint32_t time_stamp;                     
} vt_msgbuff_t;


typedef struct _vt_fw_detail_result_t
{
	char detail[256];        
	uint8_t matched_type;
}vt_fw_detail_result_t;

/*------------------------------------------------------------------*
 *                     Define Callback Functions                    *
 *------------------------------------------------------------------*/

typedef vt_status_t (* vt_fw_vector_callback)(vt_vector_result_t *vector_t);

typedef void (* vt_fw_traffic_status_callback)(vt_car_status_t car_status, float slot_rate, float pattern_rate, uint32_t count_id);

typedef vt_status_t (*vt_fw_blacklist_callback)(vt_fw_detail_result_t *detail_result);

typedef vt_status_t (*vt_fw_monitor_callback)(vt_fw_detail_result_t *detail_result);

/*------------------------------------------------------------------*
 *                        Global Data Types                         *
 *------------------------------------------------------------------*/
extern const uint8_t car_policy[];          
extern const uint8_t car_vector[];     
/*------------------------------------------------------------------*
 *                   Callback Function Prototypes                   *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                       Function Prototypes                        *
 *------------------------------------------------------------------*/
/*!
 * @brief  This API will add CAN message to Firewall queue.
 * @param [in]   *databuff - a pointer to data array.
 * @param [in]   len - length of data buffer.
 * @param [in]   id - is CAN ID.
 * @return       none.
 */
void vt_fw_rcv_msg(uint32_t id, uint8_t len, uint8_t *databuff);

/*!
 * @brief  This API will install vector call back function to report to server or print out.
 * @param [in]   callback - is vector call-back function.
 * @return       none.
 */
void vt_fw_install_vector_callback(vt_fw_vector_callback callback);

/*!
 * @brief  This API will install traffic status call back function to report to server or print out when the traffic status is changed.
 * @param [in]   callback - is traffic status call-back function.
 * @return       none.
 */
void vt_fw_install_traffic_status_callback(vt_fw_traffic_status_callback callback);

/*!
 * @brief  This API will install black list  call back function to report to server or print out.
 * @param [in]   callback - is black list call-back function.
 * @return       none.
 */
void vt_fw_install_blacklist_callback(vt_fw_blacklist_callback callback);

/*!
 * @brief  This API will install monitor  call back function to report to server or print out.
 * @param [in]   callback - is monitor call-back function.
 * @return       none.
 */
void vt_fw_install_monitor_callback(vt_fw_monitor_callback callback);

/*!
 * @brief  This API will get current status of CAN bus traffic.
 * @param [in]   none.
 * @return       status
 */
vt_car_status_t vt_fw_get_traffic_status(void);

/*!
 * @brief  This API will initialize Firewall with a pattern data and a vector data of a vehicle.
 * @param [in]   *pattern_content - pointer to policy pattern data file.
 * @param [in]   *vector_content - pointer to vector data file.
 * @return       none.
 */
void vt_fw_init(const uint8_t *pattern_content, const uint8_t *vector_content);

/*!
 * @brief  This API will close Firewall core.
 * @param [in]   none.
 * @return       none.
 */
void vt_fw_close(void);

/*!
 * @brief  This API will increase system tick count for Firewall when the timer trigger. The unit of system tick is one second
 * @param [in]   none.
 * @return       none.
 */
void vt_fw_increase_system_time(void);

/*!
 * @brief  This API will increase tick count when the timer trigger. This tick count used to compute interval time of CAN message
 *         in Firewall core. Default of a tick count is 200us
 * @param [in]   none.
 * @return       none.
 */
void vt_fw_increase_slot_tick_count(void);

/*!
 * @brief  This API will set time unit for a tick in microsecond.
 * @param [in]   itv - is time unit.
 * @return       none.
 */
void vt_fw_set_slot_time_unit(uint16_t itv);

/*!
 * @brief  This API will process Firewall. This function will put in main loop or in a task of the RTOS.
 * @param [in]   none.
 * @return       none.
 */
void vt_fw_process(void);

/*!
 * @brief  This API will create tx queue with number of CAN port.
 * @param [in]   instance - is number of CAN port.
 * @param [in]   size - is size of tx queue.
 * @return       status.
 */
vt_status_t  vt_fw_create_tx_queue(uint8_t instance, uint32_t size);

/*!
 * @brief  This API will add CAN message to tx queue with number of CAN port.
 * @param [in]   instance - is number of CAN port.
 * @param [in]   msgId - is CAN Id.
 * @param [in]   dataLen - length of data.
 * @param [in]	 *databuff - is data buffer.
 * @return       status.
 */
vt_status_t  vt_fw_add_msg_to_tx_queue(uint8_t instance, uint32_t msgId, uint8_t dataLen, uint8_t *databuff);

/*!
 * @brief  This API will get a CAN message from tx queue with number of CAN port.
 * @param [in]       instance - is number of CAN port.
 * @param [in]       *msgId - pointer to CAN Id.
 * @param [in, out]  *dataLen - pointer to length of data.
 * @param [in]	     *databuff - is data buffer.
 * @return           status.
 */
vt_status_t  vt_fw_get_msg_from_tx_queue(uint8_t instance, uint32_t *msgId, uint8_t *dataLen, uint8_t *databuff);

/*!
 * @brief  This API will check a CAN frame is malicious or no.
 * @param [in]   msgId - is CAN Id.
 * @param [in]   dataLen - length of data.
 * @param [in]	 *databuff - is data buffer.
 * @return       0: not malicious
 *               1: malicious.
 */
uint8_t vt_fw_can_msg_is_malicious(uint32_t msgId, uint8_t dataLen, uint8_t *databuff);

/*!
 * @brief  This API will add a malicious CAN frame to black list.
 * @param [in]   msgId - is CAN Id.
 * @param [in]   dataLen - length of data.
 * @param [in]	 *databuff - is data buffer.
 * @return       status
 */
vt_status_t vt_fw_add_malicious_can_frame(uint32_t msgId, uint8_t dataLen, uint8_t *databuff);

/*!
 * @brief  This API will add a range from CAN ID to CAN ID to black list.
 * @param [in]   fromId - is CAN Id.
 * @param [in]   toId - is CAN Id.
 * @param [in]	 operator - 0: in range ids, 1: not in range ids.
 * @return       status
 */
vt_status_t vt_fw_blacklist_add_range_can_id(uint32_t fromId, uint32_t toId, uint8_t operator);

/*!
 * @brief  This API will add a CAN frame to monitor frame list.
 * @param [in]   msgId - is CAN Id.
 * @param [in]   dataLen - length of data.
 * @param [in]	 *databuff - is data buffer.
 * @param [in]	 operator - 0: in range of minimum and maximum, 1: not in range of minimum and maximum.
 * @param [in]   min_val - is minimum of occurrence CAN frame.
 * @param [in]   max_val - is maximum of occurrence CAN frame.
 * @param [in]   type - is vt_frame_type_t.
 * @param [in]   step - is value of increase or decrease step.
 * @return        status
 */
vt_status_t vt_fw_monitor_add_can_frame(uint32_t msgId, uint8_t dataLen, uint8_t *databuff, uint8_t operator, uint16_t min_val,  uint16_t max_val, vt_frame_type_t type, uint8_t step);

/*!
 * @brief  This API will add a pattern of CAN frame to monitor pattern list.
 * @param [in]   *frames - pointer to CAN frame array .
 * @param [in]	 ele_size - is size of element array in a pattern.
 * @param [in]	 operator - 0: in range of minimum and maximum, 1: not in range of minimum and maximum.
 * @param [in]   min_val - is minimum of occurrence pattern.
 * @param [in]   max_val - is maximum of occurrence pattern.
 * @param [in]   type - is pattern type.
 * @param [in]   max_itv - is maximum interval time.
 * @return       status
 */
vt_status_t vt_fw_monitor_add_pattern(vt_can_frame_t *frames, uint8_t ele_size, uint8_t operator, uint16_t min_val,  uint16_t max_val, vt_pattern_type_t type, uint32_t max_itv);

/*!
 * @brief  This API will add a range from CAN ID to CAN ID to monitor range list.
 * @param [in]	 id_operator - 0: in range id, 1: not in range id.
 * @param [in]   fromId - is CAN Id.
 * @param [in]   toId - is CAN Id.
 * @param [in]	 operator - 0: in range of minimum and maximum, 1: not in range of minimum and maximum.
 * @param [in]   min_val - is minimum of occurrence range ID.
 * @param [in]   max_val - is maximum of occurrence range ID.
 * @return       status
 */
vt_status_t vt_fw_monitor_add_ids_to_range_list(uint8_t id_operator, uint32_t fromId, uint32_t toId, uint8_t operator, uint16_t min_val,  uint16_t max_val);


#ifdef __cplusplus
}
#endif


#endif /* VT_FW_IF_H_ */
