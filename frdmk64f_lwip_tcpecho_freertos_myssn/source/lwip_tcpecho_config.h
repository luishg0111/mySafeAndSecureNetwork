/*
 * lwip_tcecho_freertos_config.h
 *
 *  Created on: Feb 24, 2023
 *      Author: Luis Ángel Hernández García
 */

#ifndef LWIP_TCPECHO_CONFIG_H_
#define LWIP_TCPECHO_CONFIG_H_

/*******************************************************************************
 * Includes
 ******************************************************************************/


/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* IP address configuration. */
#define configIP_ADDR0 192
#define configIP_ADDR1 168
#define configIP_ADDR2 0
#define configIP_ADDR3 102

/* Netmask configuration. */
#define configNET_MASK0 255
#define configNET_MASK1 255
#define configNET_MASK2 255
#define configNET_MASK3 0

/* Gateway address configuration. */
#define configGW_ADDR0 192
#define configGW_ADDR1 168
#define configGW_ADDR2 0
#define configGW_ADDR3 100

/* MAC address configuration. */
#define configMAC_ADDR                     \
    {                                      \
        0x02, 0x12, 0x13, 0x10, 0x15, 0x11 \
    }

/* Address of PHY interface. */
#define EXAMPLE_PHY_ADDRESS BOARD_ENET0_PHY_ADDRESS


#endif /* LWIP_TCPECHO_CONFIG_H_ */
