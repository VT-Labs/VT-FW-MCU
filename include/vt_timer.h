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
 
#ifndef VT_TIMER_H_
#define VT_TIMER_H_

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*
 *                           Includes                               *
 *------------------------------------------------------------------*/
#include "Cpu.h"
#include "pit_driver.h"

/*------------------------------------------------------------------*
 *                          Define Macro                            *
 *------------------------------------------------------------------*/
/*! Device instance number */
#define VT_INST_PIT (0U)

/* period in microsecond */
#define VT_PIT_PERIOD (200U)   /* 0.2 millisecond */

/*------------------------------------------------------------------*
 *                Define Enumeration and Structure                  *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                     Define Callback Functions                    *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                        Global Data Types                         *
 *------------------------------------------------------------------*/
/*! Global configuration of pit1 */
extern pit_config_t  vt_pit_InitConfig;
/*! User channel configuration 0 */
extern pit_channel_config_t vt_pit_ChnConfig0;

/*------------------------------------------------------------------*
 *                   Callback Function Prototypes                   *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                       Function Prototypes                        *
 *------------------------------------------------------------------*/
/*!
 * @brief  This API will initialize periodic interrupt timer.
 * @param [in]   instance - is number of PIT used.
 * @param [in]   *channel_config - is a pointer to pit_channel_config_t(struct) to set channel configure.
 * @return       none.
 */
void vt_timer_init(uint32_t instance, pit_channel_config_t *channel_config);

/*------------------------------------------------------------------*
 *                Test Function and Examples                        *
 *------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif


#endif /* VT_TIMER_H_ */
