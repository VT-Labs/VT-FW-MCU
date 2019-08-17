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

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*
 *                           Includes                               *
 *------------------------------------------------------------------*/
#include "vt_fw_oem.h"
#include "vt_can.h"
#include "uart_pal1.h"
/*------------------------------------------------------------------*
 *                          Define Macro                            *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                Define Enumeration and Structure                  *
 *------------------------------------------------------------------*/


/*------------------------------------------------------------------*
 *                     Define callback functions                    *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                        Private Data Types                        *
 *------------------------------------------------------------------*/

static vt_can_frame_t malicious_frame = {
		.msgId = 0xCD,
		.dataLen = 8,
		.data = {0xCD,0xA0,0xFF,0xFA,0x04,0x26,0x19,0x79}
};

/*------------------------------------------------------------------*
 *                        Global Data Types                         *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                 Private Function Prototypes                      *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                        Private Functions                         *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                         Public Functions                         *
 *------------------------------------------------------------------*/

/*!
 * @brief  This API will send traffic status to report to server or print out.
 * @param [in]   car_status - is traffic status.
 * @param [in]   slot_rate - is slot rate of CAN traffic bus.
 * @param [in]   pattern_rate - is pattern rate of CAN traffic bus.
 * @param [in]   count_frames - is CAN frames of a time window.
 * @return       none.
 */
void vt_fw_traffic_status_event(vt_car_status_t car_status, float slot_rate, float pattern_rate, uint32_t count_frames)
{
	char st[256];
	int size = 0;

	memset(st,'\0', 256);

	/* Don't have CAN message for more minute or don't connect to car */
	if(car_status == VT_CAR_IDLE_STAT)
	{
		snprintf(st, 256, "[Idle]\r\n");
	}
	else
	{
		snprintf(st, 256, "- Slot rate: %.3f%%\r\n- Pattern rate: %.3f%% all frame: %lu\r\n", slot_rate * 100.0f, pattern_rate * 100.0f, count_frames);
		size = strlen(st);
		/* Matched with vector, slot and pattern */
		if((car_status & VT_CAR_NORMAL_STAT) == VT_CAR_NORMAL_STAT)
		{
			snprintf(&st[size], (256 - size),"[Normal] \r\n");
		}
		else
		{
			snprintf(&st[size], (256 - size),"[Abnormal] \r\n");
			if((car_status & VT_CAR_ABNORMAL_OVER_STAT) == VT_CAR_ABNORMAL_OVER_STAT)
			{
				size = strlen(st);
				snprintf(&st[size - 2], (256 - size)," - overload frames\r\n");
			}
			if((car_status & VT_CAR_ABNORMAL_INVALID_ID) == VT_CAR_ABNORMAL_INVALID_ID)
			{
				size = strlen(st);
				snprintf(&st[size - 2], (256 - size)," - invalid id\r\n");
			}
			if((car_status & VT_CAR_ABNORMAL_PAYLOAD) == VT_CAR_ABNORMAL_PAYLOAD)
			{
				size = strlen(st);
				snprintf(&st[size - 2], (256 - size)," - payload\r\n");
			}
			if((car_status & VT_CAR_ABNORMAL_OVER_CAN_ID) == VT_CAR_ABNORMAL_OVER_CAN_ID)
			{
				size = strlen(st);
				snprintf(&st[size - 2], (256 - size)," - over can id\r\n");
			}
			/* Matched with another condition */
			if((car_status & VT_CAR_ABNORMAL_DS_TP_STAT) == VT_CAR_ABNORMAL_DS_TP_STAT)
			{
				size = strlen(st);
				snprintf(&st[size - 2], (256 - size), " - diagnostic\r\n");
			}

			if((car_status & VT_CAR_ABNORMAL_MALICIOUS) == VT_CAR_ABNORMAL_MALICIOUS)
			{
				size = strlen(st);
				snprintf(&st[size - 2], (256 - size), " - malicious\r\n");
			}
		}
		/* Don't have CAN message for more 3 seconds */
		if((car_status & VT_CAR_IDLE_STAT) == VT_CAR_IDLE_STAT)
		{
			size = strlen(st);
			snprintf(&st[size -2 ], (256 - size), " - idle\r\n");
		}
	}
#ifdef S32R274RRUEVB
	UART_SendDataBlocking(&uart_pal1_instance, (const uint8_t*)st, strlen(st),30);
#else
	UART_SendDataBlocking(INST_UART_PAL1, (const uint8_t*)st, strlen(st),30);
#endif
}

/*!
 * @brief  This API will send matched of vector data to report to server or print out.
 * @param [in]   *vector_t - pointer to vt_vector_result_t structure.
 * @return       status.
 */
vt_status_t vt_fw_vector_report_matched(vt_vector_result_t *vector_t)
{
	char st[256];
	int i = 0, size = 0;;

	if(vector_t == NULL)
		return VT_STATUS_NULL;

	memset(st,'\0', 256);
	snprintf(st, 256, "- Vector rate: %lu/%lu = %.3f%% - all vectors: %lu\r\n", vector_t->count_vector_in_rl, vector_t->count_vector_in_rt, vector_t->matched_rate * 100.0f, vector_t->count_all_vector);
	if(vector_t->count_payload_unmatched > 0)
	{
		size = strlen(st);
		snprintf(&st[size - 2], 256 - size, " - count unmatched payload: %lu\r\n", vector_t->count_payload_unmatched);
	}
	if(vector_t->count_invalid_id_items > 0)
	{
		size = strlen(st);
		snprintf(&st[size - 2], 256 - size, " - count invalid id: %lu IDs: \r\n", vector_t->count_invalid_vector_id);
		for(i = 0; i < vector_t->count_invalid_id_items; i++)
		{
			size = strlen(st);
			snprintf(&st[size - 2], 256 - size, " 0x%lx  ", vector_t->invalid_id[i]);
		}
	}
	/* Over CAN Id */
	if(vector_t->count_over_id_items > 0)
	{
		size = strlen(st);
		snprintf(&st[size - 2], 256 - size, " - count over id: %u IDs: \r\n", vector_t->count_over_id);
		for(i = 0; i < vector_t->count_over_id_items; i++)
		{
			size = strlen(st);
			snprintf(&st[size - 2], 256 - size, " 0x%lx  ", vector_t->over_id[i]);
		}
	}
	size = strlen(st);
	st[size - 2] = '\r';
	st[size - 1] = '\n';
#ifdef S32R274RRUEVB
	UART_SendDataBlocking(&uart_pal1_instance, (const uint8_t*)st, strlen(st),30);
#else
	UART_SendDataBlocking(INST_UART_PAL1, (const uint8_t*)st, strlen(st),30);
#endif
	return VT_STATUS_SUCCESS;
}

/*!
 * @brief  This API will send matched of blacklist data to report to server or print out.
 * @param [in]   *detail_result - pointer to vt_fw_detail_result_t structure.
 * @return       status.
 */
vt_status_t vt_fw_blacklist_report_matched(vt_fw_detail_result_t *detail_result)
{
	if(detail_result == NULL)
		return VT_STATUS_NULL;

	if(detail_result->level > 0)
	#ifdef S32R274RRUEVB
		UART_SendDataBlocking(&uart_pal1_instance, (const uint8_t*)detail_result->detail, strlen(detail_result->detail),30);
	#else
		UART_SendDataBlocking(INST_UART_PAL1, (const uint8_t*)detail_result->detail, strlen(detail_result->detail),30);
	#endif
	return VT_STATUS_SUCCESS;
}

/*!
 * @brief  This API will send matched of monitor data to report to server or print out.
 * @param [in]   *detail_result - pointer to vt_fw_detail_result_t structure.
 * @return       status.
 */
vt_status_t vt_fw_monitor_report_matched(vt_fw_detail_result_t *detail_result)
{
	if(detail_result == NULL)
			return VT_STATUS_NULL;

	if(detail_result->level > 0)
	#ifdef S32R274RRUEVB
		UART_SendDataBlocking(&uart_pal1_instance, (const uint8_t*)detail_result->detail, strlen(detail_result->detail),30);
	#else
		UART_SendDataBlocking(INST_UART_PAL1, (const uint8_t*)detail_result->detail, strlen(detail_result->detail),30);
	#endif

	return VT_STATUS_SUCCESS;
}

/*!
 * @brief  This API will send a DoS attack report to server or print out.
 * @param [in]   *detail_result - pointer to vt_fw_detail_result_t structure.
 * @return       status.
 */
vt_status_t vt_fw_dos_report(vt_fw_detail_result_t *detail_result)
{
	if(detail_result == NULL)
			return VT_STATUS_NULL;

	#ifdef S32R274RRUEVB
		UART_SendDataBlocking(&uart_pal1_instance, (const uint8_t*)detail_result->detail, strlen(detail_result->detail),30);
	#else
		UART_SendDataBlocking(INST_UART_PAL1, (const uint8_t*)detail_result->detail, strlen(detail_result->detail),30);
	#endif

	return VT_STATUS_SUCCESS;
}

/*!
 * @brief  This API will initialize firewall.
 * @param [in]   none.
 * @return       none.
 */
void vt_fw_oem_init(void)
{
	//vt_fw_set_vector_payload_rate(1.0);
	/* Initialize firewall */
#ifdef USING_ONLY_ATTACK_RULES
	vt_fw_init(NULL, NULL, obd_attack_rules);
#else
	vt_fw_init(policy_rules, vector_rules, obd_attack_rules);
#endif

#ifdef USING_BRIDGE
	/* Create 2 tx queue for CAN0 and CAN1 */
	vt_fw_create_tx_queue(VT_INST_CAN0, 256);
	vt_fw_create_tx_queue(VT_INST_CAN1, 256);
#endif
	/* Set slot to rule */
	vt_fw_set_slot_time_unit(VT_PIT_PERIOD);
	/* Install call-back functions. These call-back functions is implemented by OEM */
#ifndef USING_ONLY_ATTACK_RULES
	/* Add a malicious CAN frame */
	vt_fw_black_list_create_frames(2);
	/* Level 1 */
	vt_fw_add_malicious_can_frame(malicious_frame.msgId, malicious_frame.dataLen, malicious_frame.data, 1);
	vt_fw_install_vector_callback(vt_fw_vector_report_matched);
	vt_fw_install_traffic_status_callback(vt_fw_traffic_status_event);
	vt_fw_install_blacklist_callback(vt_fw_blacklist_report_matched);
#endif
	vt_fw_install_monitor_callback(vt_fw_monitor_report_matched);
	vt_fw_install_dos_callback(vt_fw_dos_report);
}

/*------------------------------------------------------------------*
 *                       Test Function                              *
 *------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif
