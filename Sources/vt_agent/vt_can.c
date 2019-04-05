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

/*!
 *  @addtogroup can_module can module documentation
 *  @{
 */
/*------------------------------------------------------------------*
 *                           Includes                               *
 *------------------------------------------------------------------*/
#include "vt_can.h"
#include "vt_timer.h"
#include "vt_fw_oem.h"
/*------------------------------------------------------------------*
 *                          Define Macro                            *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                Define Enumeration and Structure                  *
 *------------------------------------------------------------------*/
#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*
 *                     Define callback functions                    *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                        Private Data Types                        *
 *------------------------------------------------------------------*/
flexcan_msgbuff_t msg_buff[2];
static volatile uint8_t active_buff = 0;

/* PE clock 40MHz bitRate for can 2.0b */
static const flexcan_time_segment_t bitRateTable[] = {
    { 7, 4, 1, 19, 1},  /* 125 kHz */
    { 7, 4, 1,  9, 1},  /* 250 kHz */
    { 7, 4, 1,  4, 1 }, /* 500 kHz */
    { 4, 1, 1,  4, 1},  /* 800 kHz */
    { 7, 6, 3,  1, 1},  /* 1   MHz */
};
/* PE clock 40MHz bitRate for can fd */
static const flexcan_time_segment_t bitRateCbtTable[] = {
	{ 7, 4, 1, 19, 1},  /* 125 kHz */
	{ 7, 4, 1,  9, 1},  /* 250 kHz */
	{ 7, 4, 1,  4, 1 }, /* 500 kHz */
	{ 4, 1, 1,  4, 1},  /* 800 kHz */
	{ 7, 6, 3,  1, 1},  /* 1   MHz */
};

static flexcan_user_config_t vt_can_InitConfig = {
    .fd_enable = false,
#ifdef S32R274RRUEVB
    .pe_clock = FLEXCAN_CLK_SOURCE_OSC,
#else    /* MPC5748G Devkit */
	.pe_clock = FLEXCAN_CLK_SOURCE_FXOSC,
#endif
    .max_num_mb = 48,
    .num_id_filters = FLEXCAN_RX_FIFO_ID_FILTERS_48,
    .is_rx_fifo_needed = true,
    .flexcanMode = FLEXCAN_NORMAL_MODE,
    .payload = FLEXCAN_PAYLOAD_SIZE_8,
    .bitrate = {
        .propSeg = 7,
        .phaseSeg1 = 4,
        .phaseSeg2 = 1,
        .preDivider = 4,
        .rJumpwidth = 1
    },
    .bitrate_cbt = {
        .propSeg = 7,
        .phaseSeg1 = 4,
        .phaseSeg2 = 1,
        .preDivider = 4,
        .rJumpwidth = 1
    },
    .transfer_type = FLEXCAN_RXFIFO_USING_INTERRUPTS,
};
#ifdef USING_BRIDGE
static uint8_t forward_id[VT_MAX_CAN_NUMBER] = {VT_INST_CAN1, VT_INST_CAN0};
static volatile uint8_t tx_flags[VT_MAX_CAN_NUMBER] = {0, 0};
#endif

/*------------------------------------------------------------------*
 *                        Global Data Types                         *
 *------------------------------------------------------------------*/
flexcan_state_t vt_can_State;
/*------------------------------------------------------------------*
 *                 Private Function Prototypes                      *
 *------------------------------------------------------------------*/
static inline flexcan_msgbuff_t * _vt_get_msg(uint8_t inst_can);
static inline int _vt_can_bsearch(uint32_t *id_table, int size, uint32_t can_id);
#ifdef USING_BRIDGE
static inline void _vt_can_get_and_send_message(uint8_t instant);
static inline void _vt_can_add_message_to_forward_queue(uint8_t instant, flexcan_msgbuff_t *msg);
#endif
/*------------------------------------------------------------------*
 *                    Callback Functions                            *
 *------------------------------------------------------------------*/
#ifdef S32R274RRUEVB
void vt_rcv_callback(uint8_t instance, flexcan_event_type_t eventType, uint32_t buffIdx, flexcan_state_t *flexcanState)
#else  /* MPC5748G Devkit */
void vt_rcv_callback(uint8_t instance, flexcan_event_type_t eventType, flexcan_state_t *flexcanState)
#endif
{
	flexcan_msgbuff_t * msg = NULL;
	(void)flexcanState;
	uint8_t malicious_flag = 0;

	switch(eventType)
	{
	case FLEXCAN_EVENT_RXFIFO_COMPLETE:
		msg = _vt_get_msg(instance);
		malicious_flag = vt_fw_can_msg_is_malicious(msg->msgId, msg->dataLen, msg->data);
#ifdef USING_BRIDGE
		if(malicious_flag == 0)
			_vt_can_add_message_to_forward_queue(instance, msg);
#endif
		/* Add message to firewall */
		vt_fw_rcv_msg(msg->msgId, msg->dataLen, msg->data);
		break;
	case FLEXCAN_EVENT_TX_COMPLETE:
#ifdef USING_BRIDGE
		_vt_can_get_and_send_message(instance);
#endif
		break;
	default:
		break;
	}
}
/*------------------------------------------------------------------*
 *                        Private Functions                         *
 *------------------------------------------------------------------*/
/*static int vt_can_id_compare(const void * a, const void * b)
{
	return (int)(*(uint32_t *)a - *(uint32_t *)b);
}*/

/*!
 * @brief  This API will search can_id in can id array.
 * @param [in]      *id_table - pointer to can id table.
 * @param [in]      size - size of can id table
 * @param [in]      can_id - is a CAN ID to search in can id table (e.g: 0x123, 0x750 ).
 * @return          position in can id table
 *                  -1.
 */
static inline int _vt_can_bsearch(uint32_t *id_table, int size, uint32_t can_id)
{
   int front = 0, rear = 0, mid = 0;

   if((size <= 0) || (id_table == NULL))
	   return -1;
   rear = size - 1;

   while(front <= rear) {
	  mid = (front + rear)/2;
	  if(id_table[mid] == can_id)
         break;
      else if(id_table[mid] < can_id)
         front = mid + 1;
      else
         rear = mid - 1;
   }

   if (front > rear)
     return -1;
   return mid;
}


/*!
 * @brief  This API will get a CAN message that it received successful.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @return          a pointer to a local message buffer if success.
 *                  NULL if don't have data coming.
 */
static inline flexcan_msgbuff_t * _vt_get_msg(uint8_t inst_can)
{
	flexcan_msgbuff_t * msg = NULL;

	msg = &msg_buff[active_buff];
	active_buff = !active_buff;
	FLEXCAN_DRV_RxFifo(inst_can, &msg_buff[active_buff]);
	return msg;
}

#ifdef USING_BRIDGE
/*!
 * @brief  This API will add CAN message to forward queue.
 * @param [in]      instant - CAN number (e.g: 0, 1, 2).
 * @param [in]      *msg - is pointer to flexcan message.
 * @return       none.
 */
static inline void _vt_can_add_message_to_forward_queue(uint8_t instant, flexcan_msgbuff_t *msg)
{
	status_t result = STATUS_ERROR;
	int mb_idx;
	static flexcan_data_info_t dataInfo =
	{
		.data_length = 1U,
		.msg_id_type = FLEXCAN_MSG_ID_STD,
		.enable_brs  = false,
		.fd_enable   = false,
		.is_remote = false,
		.fd_padding  = 0U
	};

	if(instant >= VT_MAX_CAN_NUMBER)
		return;
	if(tx_flags[forward_id[instant]] == 0)
	{
		/* Send direct */
		dataInfo.data_length = (uint32_t)msg->dataLen;
		/* Try to send message with mbx idx */
		for(mb_idx = 0; mb_idx < 16; mb_idx++)
		{
			result = FLEXCAN_DRV_ConfigTxMb(forward_id[instant], mb_idx, (const flexcan_data_info_t *)&dataInfo, msg->msgId);
			if(result == STATUS_SUCCESS)
			{
				result = FLEXCAN_DRV_Send(forward_id[instant], mb_idx, (const flexcan_data_info_t *)&dataInfo, msg->msgId,(const uint8_t *) &msg->data[0]);
				break;
			}
		}
		if((result != STATUS_SUCCESS) || (mb_idx == 16))
		{
			vt_fw_add_msg_to_tx_queue(forward_id[instant], msg->msgId, msg->dataLen, msg->data);
			tx_flags[forward_id[instant]] = 1;
		}
	}
	else
	{
		/* Add to queue */
		vt_fw_add_msg_to_tx_queue(forward_id[instant], msg->msgId, msg->dataLen, msg->data);
	}
}

/*!
 * @brief  This API will get and send out a CAN message to a CAN bus.
 * @param [in]   instant - CAN number (e.g: 0, 1, 2).
 * @return       none.
 */
static inline void _vt_can_get_and_send_message(uint8_t instant)
{
	vt_status_t status;
	flexcan_msgbuff_t msg;
	status_t result = STATUS_ERROR;
	int mb_idx;
	static flexcan_data_info_t dataInfo =
	{
		.data_length = 1U,
		.msg_id_type = FLEXCAN_MSG_ID_STD,
		.enable_brs  = false,
		.fd_enable   = false,
		.is_remote = false,
		.fd_padding  = 0U
	};
	if(tx_flags[instant] == 1)
	{
		status = vt_fw_get_msg_from_tx_queue(instant, &msg.msgId, &msg.dataLen, msg.data);
		if(status == VT_STATUS_SUCCESS)
		{
			dataInfo.data_length = (uint32_t)msg.dataLen;
			/* Try to send message with mbx idx */
			for(mb_idx = 0; mb_idx < 16; mb_idx++)
			{
				result = FLEXCAN_DRV_ConfigTxMb(instant, mb_idx, (const flexcan_data_info_t *)&dataInfo, msg.msgId);
				if(result == STATUS_SUCCESS)
				{
					result = FLEXCAN_DRV_Send(instant, mb_idx, (const flexcan_data_info_t *)&dataInfo, msg.msgId,(const uint8_t *) &msg.data[0]);
					break;
				}
			}
		}
		else
		{
			tx_flags[instant] = 0;
		}
	}
}
#endif

/*------------------------------------------------------------------*
 *                         Public Functions                         *
 *------------------------------------------------------------------*/
/*!
 * @brief  This API will get a CAN message that it received successful.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @return          a pointer to a local message buffer if success.
 *                  NULL if don't have data coming.
 */
flexcan_msgbuff_t * vt_get_msg(uint8_t inst_can)
{
	flexcan_msgbuff_t * msg = NULL;

	msg = &msg_buff[active_buff];
	active_buff = !active_buff;
	FLEXCAN_DRV_RxFifo(inst_can, &msg_buff[active_buff]);
	return msg;
}

/*!
 * @brief  This API will initialize a CAN port.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      bitrate - is a CAN bit rate in vt_can_bitrate_type_t (e.g: VT_BITRATE_125, VT_BITRATE_500).
 * @param [in]      callback - callback function.
 * @param [in]      *callbackParam - pointer to parameter.
 * @return          STATUS_SUCCESS, STATUS_FLEXCAN_MB_OUT_OF_RANGE,
 *                  or STATUS_ERROR.
 */
status_t vt_init_can(uint8_t inst_can, vt_can_bitrate_type_t bitrate, flexcan_callback_t callback, void *callbackParam )
{
	status_t result = STATUS_ERROR;
	vt_can_bitrate_type_t btr = VT_BITRATE_500;

	if(bitrate < VT_BITRATE_UNKNOWN)
		btr = bitrate;
	/* Set bit rate to InitConfig */
	vt_can_InitConfig.bitrate = bitRateTable[(int)btr];
	//canCom_InitConfig.bitrate_cbt = bitRateCbtTable[btr];
	result = FLEXCAN_DRV_Init(inst_can, &vt_can_State, (const flexcan_user_config_t *)&vt_can_InitConfig);
	vt_can_State.callback = callback;
	vt_can_State.callbackParam = callbackParam;
	/* Set buffer to receive CAN message */
	FLEXCAN_DRV_RxFifo(inst_can, &msg_buff[active_buff]);
	/* Disable filter RxFifo */
	FLEXCAN_DRV_SetRxFifoGlobalMask(inst_can, FLEXCAN_MSG_ID_STD, 0x00000000);

	return result;
}

/*!
 * @brief  This API will set a bit-rate to CAN.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      bitrate - is a CAN bit rate in vt_can_bitrate_type_t (e.g: VT_BITRATE_125, VT_BITRATE_500).
 * @return          STATUS_SUCCESS
 *                  or STATUS_ERROR.
 */
status_t vt_set_bitrate_can(uint8_t inst_can, vt_can_bitrate_type_t bitrate)
{
	status_t result = STATUS_ERROR;

	if(bitrate < VT_BITRATE_UNKNOWN)
	{
		FLEXCAN_DRV_SetBitrate(inst_can, (const flexcan_time_segment_t *) &bitRateTable[(int)bitrate]);
		result = STATUS_SUCCESS;
	}

	return result;
}

/*!
 * @brief  This API will detect current bit rate of CAN bus.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      listen_only - enable or disable listen only foe auto detect mode.
 * @return          vt_can_bitrate_type_t (e.g: VT_BITRATE_125, VT_BITRATE_500 or VT_BITRATE_UNKNOWN).
 */
vt_can_bitrate_type_t vt_autodetect_bitrate(uint8_t inst_can, uint8_t listen_only)
{
	status_t result = STATUS_ERROR;
	int i = 0, mb_idx = 0, h = 0;
	flexcan_msgbuff_t recvBuff;
	uint8_t data = 0xDC;
	flexcan_data_info_t dataInfo =
	  {
	    .data_length = 1U,
	    .msg_id_type = FLEXCAN_MSG_ID_STD,
	    .enable_brs  = true,
	    .fd_enable   = false,
	    .fd_padding  = 0U
	  };
	vt_can_bitrate_type_t bitrate[VT_BITRATE_UNKNOWN] = {VT_BITRATE_500, VT_BITRATE_125, VT_BITRATE_250, VT_BITRATE_800, VT_BITRATE_1M };

	for(i = 0; i < (int)VT_BITRATE_UNKNOWN; i++)
	{
		result = vt_init_can(inst_can, bitrate[i], vt_rcv_callback, (void *)NULL);
		if(result == STATUS_SUCCESS)
		{
			/* Repeat receive in 5 times */
			for(h = 0; h < 5; h++)
			{
				/* Wait receiving in 20ms. If success, return this bit-rate */
				if( FLEXCAN_DRV_RxFifoBlocking(inst_can, &recvBuff,30) == STATUS_SUCCESS)
					return bitrate[i];
			}
			if(!listen_only)
			{
				/* Try to send message with mailbox index */
				mb_idx = vt_can_InitConfig.max_num_mb - 1;
				if(FLEXCAN_DRV_ConfigTxMb(inst_can, mb_idx, &dataInfo, 1) == STATUS_SUCCESS)
				{
					result = FLEXCAN_DRV_Send(inst_can, mb_idx, &dataInfo, 1, &data);
					if((result == STATUS_SUCCESS) || (result == STATUS_BUSY))
					{
						/* Wait until the previous FlexCAN send is completed */
						h = 0;
						do{
							result = FLEXCAN_DRV_GetTransferStatus(inst_can, mb_idx);
							if(result == STATUS_SUCCESS)
							{
								return bitrate[i];
							}
						} while(++h < 10000);
					}

					FLEXCAN_DRV_AbortTransfer(inst_can, mb_idx);
				}

			}
		}
	}
	return VT_BITRATE_UNKNOWN;
}

/*!
 * @brief  This API will send a CAN message.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @param [in]      *msgbuff - is a pointer to flexcan message buffer structure.
 * @param [in]      id-type - is ID type of CAN (e.g: FLEXCAN_MSG_ID_STD, FLEXCAN_MSG_ID_EXT).
 * @return          STATUS_SUCCESS
 *                  or STATUS_ERROR.
 */
status_t vt_send_can_msg(uint8_t inst_can, flexcan_msgbuff_t *msgbuff, flexcan_msgbuff_id_type_t id_type)
{
	int i = 0, z = 0;
	status_t result = STATUS_ERROR;

	static flexcan_data_info_t dataInfo =
	{
		.data_length = 1U,
		.msg_id_type = FLEXCAN_MSG_ID_STD,
		.enable_brs  = false,
		.fd_enable   = false,
		.is_remote = false,
		.fd_padding  = 0U
	};

	if(msgbuff == NULL)
		return result;
	dataInfo.data_length = (uint32_t)msgbuff->dataLen;
	dataInfo.msg_id_type = id_type;
	/* Try to send message with mbx idx */
	for(i = 0; i < vt_can_InitConfig.max_num_mb; i++)
	{
		result = FLEXCAN_DRV_ConfigTxMb(inst_can, i, (const flexcan_data_info_t *)&dataInfo, msgbuff->msgId);
		if(result == STATUS_SUCCESS)
		{
			result = FLEXCAN_DRV_Send(inst_can, i, (const flexcan_data_info_t *)&dataInfo, msgbuff->msgId,(const uint8_t *) &msgbuff->data[0]);
			if((result == STATUS_SUCCESS) || (result == STATUS_BUSY))
			{
				/* Wait until the previous FlexCAN send is completed */
				z = 0;
				do{
					result = FLEXCAN_DRV_GetTransferStatus(inst_can, i);
					if(result == STATUS_SUCCESS)
					{
						return result;
					}
				} while(++z < 10000);
			}
			FLEXCAN_DRV_AbortTransfer(inst_can, i);
		}
	}
	return result;
}


/*!
 * @brief  This API will set buffer to Rxfifo to start receive CAN message.
 * @param [in]      inst_can - CAN number (e.g: 0, 1, 2).
 * @return          none.
 */
void vt_start_rcv(uint8_t inst_can)
{
	  /* Set buffer to receive CAN message */
	  FLEXCAN_DRV_RxFifo(inst_can, &msg_buff[active_buff]);
}


#ifdef __cplusplus
}
#endif
/*!
 * @}
 */
/* END vt_can. */
