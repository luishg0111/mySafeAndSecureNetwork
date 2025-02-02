/*
 * secure_msg.h
 *
 *  Created on: Feb 26, 2023
 *      Author: t0ji
 */

#ifndef SECURE_MSG_H_
#define SECURE_MSG_H_

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "crc32.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Types
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern uint8_t aui8_key[16];
extern uint8_t aui8_init_vec[16];
extern struct AES_ctx s_ctx;
extern size_t t_test_string_len, t_padded_len;
extern uint8_t aui8_padded_msg[512];

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void v_aescrc_test_task( void );
void v_recv_cypher_message(T_MESSAGGES t_data);
T_MESSAGGES t_write_cypher_message(uint8_t* pui8_data);
T_MESSAGGES t_encrypt_message_AES(uint8_t* pui8_data);
T_MESSAGGES t_decrypt_message_AES(uint8_t* pui8_data);




#endif /* SECURE_MSG_H_ */
