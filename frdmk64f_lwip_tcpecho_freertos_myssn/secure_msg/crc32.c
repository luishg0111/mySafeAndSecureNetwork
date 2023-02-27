/*
 * crc32.c
 *
 *  Created on: Feb 20, 2023
 *      Author: Luis Ángel Hernández García
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "crc32.h"
#include "crc32_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Types
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Init for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 *          http://reveng.sourceforge.net/crc-catalogue/
 */
void v_InitCrc32( CRC_Type *t_base, uint32_t ui32_seed )
{
    crc_config_t t_config;

    t_config.polynomial         = CRC32_POLY;
    t_config.seed               = ui32_seed;
    t_config.reflectIn          = true;
    t_config.reflectOut         = true;
    t_config.complementChecksum = true;
    t_config.crcBits            = CRC32_BITS;
    t_config.crcResult          = CRC32_RESULTS;

    CRC_Init(t_base, &t_config);

#if defined(CRC32_DEBUG_MODE)
    PRINTF("CRC32_DEBUG_INFO: InitCrc32 completed\r\n");
#endif
}


/*!
 * @brief Calculation for CRC-32.
 * @details Init CRC peripheral module for CRC-32 protocol.
 *          width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926
 *          name="CRC-32"
 */
uint32_t ui32_CRC32(T_MESSAGGES t_data){

#if defined(CRC32_DEBUG_MODE)
	PRINTF("CRC32_DEBUG_INFO: CRC32 response\r\n");
#endif

	/* CRC data */
	CRC_Type *t_base = CRC32_CRC0;
	uint32_t ui32_checksum32;

	/* base and seed */
	v_InitCrc32( t_base, CRC32_INIT_VAL );
	CRC_WriteData( t_base, t_data.ui8_msg, t_data.t_padded_len);
	ui32_checksum32 = CRC_Get32bitResult( t_base );

#if defined(CRC32_DEBUG_MODE)
	PRINTF("CRC32_DEBUG_INFO: CRC32 completed\r\n");
#endif

	return ui32_checksum32;
}
