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

#ifndef VT_FW_OEM_H_
#define VT_FW_OEM_H_

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*
 *                           Includes                               *
 *------------------------------------------------------------------*/
#include "vt_fw_if.h"
#include "vt_timer.h"

/*------------------------------------------------------------------*
 *                          Define macro                            *
 *------------------------------------------------------------------*/
#define VT_MAX_CAN_NUMBER 2

/*------------------------------------------------------------------*
 *                Define Enumeration and Structure                  *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                     Define Callback Functions                    *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                        Global Data Types                         *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                   Callback Function Prototypes                   *
 *------------------------------------------------------------------*/

/*------------------------------------------------------------------*
 *                       Function Prototypes                        *
 *------------------------------------------------------------------*/
/*!
 * @brief  This API will initialize firewall.
 * @param [in]   none.
 * @return       none.
 */
void vt_fw_oem_init(void);

/*------------------------------------------------------------------*
 *                Test Function and Examples                        *
 *------------------------------------------------------------------*/


/*------------------------------------------------------------------*
 *   Put example here
 *------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif



#endif /* VT_FW_OEM_H_ */
