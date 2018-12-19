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
 
#include "vt_fw_oem.h"

vt_can_bitrate_type_t bitrate0 = VT_BITRATE_UNKNOWN;
#ifdef USING_GATEWAY
vt_can_bitrate_type_t bitrate1 = VT_BITRATE_500;
#endif

int main(void)
{

  /* Initialize Led */
  vt_init_leds();
  /* Initialize RTC */
  vt_rtc_init(VT_RTC_TIMER, &vt_rtcTimer_StartTime, &vt_rtcTimer_AlarmConfig);
  /* Initialize PIT */
  vt_timer_init(VT_INST_PIT, &vt_pit_ChnConfig0);
  /* Initialize firewall OEM */
  vt_fw_oem_init();
  /* Initialize CAN bus */
  vt_init_can(VT_INST_CAN0, VT_BITRATE_500, vt_rcv_callback, NULL);
#ifdef USING_GATEWAY
  vt_init_can(VT_INST_CAN1, VT_BITRATE_500, vt_rcv_callback, NULL);
  vt_start_rcv(VT_INST_CAN1);
#endif

  while(1)
  {
#ifdef USING_GATEWAY
	  if((bitrate0 != VT_BITRATE_UNKNOWN ) && (bitrate1 != VT_BITRATE_UNKNOWN ))
#else
	  if(bitrate0 != VT_BITRATE_UNKNOWN )
#endif
	  {
		  vt_fw_process();
  	  }
	  else
	  {
		  if(bitrate0 == VT_BITRATE_UNKNOWN )
		  {
			  bitrate0 = vt_autodetect_bitrate(VT_INST_CAN0, 0);
			  if(bitrate0 < VT_BITRATE_UNKNOWN)
			  {
				  vt_start_rcv(VT_INST_CAN0);
			  }
		  }
#ifdef USING_GATEWAY
		  if(bitrate1 == VT_BITRATE_UNKNOWN )
		  {
			  bitrate1 = vt_autodetect_bitrate(VT_INST_CAN1, 0);
			  if(bitrate1 < VT_BITRATE_UNKNOWN)
			  {
				  vt_start_rcv(VT_INST_CAN1);
			  }
		  }
#endif
	  }
  }
  /* Add another close code at here */
} 
