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

#ifndef VT_RTC_H_
#define VT_RTC_H_

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*
 *                           Includes                               *
 *------------------------------------------------------------------*/
#include "clockMan1.h"
#include "Cpu.h"
#include "rtc_c55_driver.h"
#include "vt_led.h"

/*------------------------------------------------------------------*
 *                          Define Macro                            *
 *------------------------------------------------------------------*/

/*! @brief Device instance number */
#define VT_RTC_TIMER 0UL

/*------------------------------------------------------------------*
 *                Define Enumeration and Structure                  *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                     Define Callback Functions                    *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                        Global Data Types                         *
 *------------------------------------------------------------------*/

extern rtc_init_config_t     vt_rtcTimer_Config;

extern rtc_timedate_t vt_rtcTimer_StartTime;


extern rtc_state_t vt_rtcTimer_State;


extern rtc_alarm_config_t   vt_rtcTimer_AlarmConfig;

/*------------------------------------------------------------------*
 *                   Callback Function Prototypes                   *
 *------------------------------------------------------------------*/

void vt_rtc_timer_callback(void * callbackParam);

/*------------------------------------------------------------------*
 *                       Function Prototypes                        *
 *------------------------------------------------------------------*/
/*!
 * @brief  This API will initialize RTC.
 * @param [in]   instance - is number of RTC used.
 * @param [in]   *startTime - is a pointer to rtc_timedate_t(struct) to set the time and date.
 * @param [in]   *alarmConfig - is a pointer to rtc_alarm_config_t(struct) to configure alarm trigger.
 * @return       none.
 */
void vt_rtc_init(uint32_t instance, rtc_timedate_t * startTime, rtc_alarm_config_t *alarmConfig);

/*!
 * @brief  This API will set repeated forever for alarm of RTC.
 * @param [in]   instance - is number of RTC used.
 * @param [in]   sec - interval in second to alarm trigger.
 * @return       status.
 */
status_t vt_set_alarm_repeat_forever(uint32_t instance, uint32_t sec);

/*!
 * @brief  This API will set number of repeated for alarm of RTC.
 * @param [in]   instance - is number of RTC used.
 * @param [in]   sec - interval in second to alarm trigger.
 * @param [in]   numberOfRepeats - number of repeat for alarm of RTC.
 * @return       status.
 */
status_t vt_set_alarm_repeat_with_number(uint32_t instance, uint32_t sec, uint32_t numberOfRepeats);

/*------------------------------------------------------------------*
 *                Test Function and Examples                        *
 *------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif


#endif /* VT_RTC_H_ */
