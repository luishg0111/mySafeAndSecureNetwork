/*
 * secure_msg.c
 *
 *  Created on: Feb 24, 2023
 *      Author: Luis Ángel Hernández García
 */


/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "secure_msg_config.h"
#include "secure_msg.h"
#include "aes.h"
#include "crc32.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Types
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void v_MakeBytesfromLong(uint32_t* ui32_integer, uint8_t aui8_data[]);
void v_MakeLongfromBytes(uint8_t aui8_data[], uint32_t* ui32_integer);
/*******************************************************************************
 * Variables
 ******************************************************************************/
/* AES data */
//Key Size 16 bytes --> 128 bits
uint8_t aui8_key[] = AES_KEY;
//Initialization vector
uint8_t aui8_init_vec[] = AES_INIT_VECT;
struct AES_ctx s_ctx;
size_t t_test_string_len = 0;
size_t t_padded_len = 0;
uint8_t aui8_padded_msg[512] = {0};

/*******************************************************************************
 * Code
 ******************************************************************************/

/* Function used for testing purposes */
void v_aescrc_test_task( void )
{
#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF(" ----TESTING AES CRC32 APIs----\r\n");
#endif
	/*Definition of variables*/
	uint8_t ui8_test_string[] = {"01234567890123456789"};
	T_MESSAGGES t_test_encrypt_string, t_test_decrypt_string;
	uint32_t ui32_checksum32;

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: aescrc_test_task: testing AES and CRC with the test string 01234567890123456789\r\n\n");
	PRINTF("\nTesting AES128\r\n\n");

	PRINTF("SECURE_MSG_DEBUG_INFO: aescrc_test_task: encrypt_message_AES called function\r\n");
#endif
	t_test_encrypt_string = t_encrypt_message_AES(ui8_test_string);

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: aescrc_test_task: Encrypted Message: \r\n");

	/* Print the encrypt message*/
	for(uint8_t ui8_Index=0; ui8_Index < t_test_encrypt_string.t_padded_len; ui8_Index++) {
		PRINTF("0x%02x,", t_test_encrypt_string.ui8_msg[ui8_Index]);
	}
#endif

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("\nTesting CRC32\r\n\n");

	PRINTF("SECURE_MSG_DEBUG_INFO: aescrc_test_task: CRC32 called function\r\n");
#endif
	ui32_checksum32 = ui32_CRC32(t_test_encrypt_string);

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("CRC-32: 0x%08x\r\n", ui32_checksum32);

	PRINTF("SECURE_MSG_DEBUG_INFO: aescrc_test_task: decrypt_message_AES called function\r\n");
#endif
	/* Decrypt the message with AES128*/
	t_test_decrypt_string = t_decrypt_message_AES(t_test_encrypt_string.ui8_msg);

#if defined(SECURE_MSG_DEBUG_MODE)
	/* Print the decrypt message*/
	for(uint8_t ui8_Index = 0; ui8_Index < t_test_decrypt_string.t_padded_len; ui8_Index++) {
		PRINTF("0x%02x,", t_test_decrypt_string.ui8_msg[ui8_Index]);
	}

	/*Print messages in UART for debug purposes */
    PRINTF("SECURE_MSG_DEBUG_INFO: TEST_SUCCESS\r\n");
    PRINTF("SECURE_MSG_DEBUG_INFO: Continue to real client - server connection...\r\n");
	PRINTF("\r\n");
#endif

}


T_MESSAGGES t_encrypt_message_AES(uint8_t* pui8_data)
{
	T_MESSAGGES t_new_msg;
	/* Init the AES context structure */
	AES_init_ctx_iv(&s_ctx, aui8_key, aui8_init_vec);

	/* To encrypt an array its lenght must be a multiple of 16 so we add zeros */
	t_test_string_len = strlen( (const char*) pui8_data);
	t_padded_len = t_test_string_len + (16 - (t_test_string_len%16) );
	memcpy(aui8_padded_msg, pui8_data, t_test_string_len);

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: encrypt_message_AES\r\n");
	//Encrypt Buffer on CBC Mode
	PRINTF("SECURE_MSG_DEBUG_INFO: Encrypting buffer on CBC mode...\r\n");
#endif
	//Reference: void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
	AES_CBC_encrypt_buffer(&s_ctx, aui8_padded_msg, t_padded_len);

	t_new_msg.ui8_msg = aui8_padded_msg;
	t_new_msg.t_padded_len = t_padded_len;
#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: Message encrypted \r\n");
#endif
	return t_new_msg;
}

T_MESSAGGES t_decrypt_message_AES(uint8_t* pui8_data)
{
	/*Definition of variables*/
	T_MESSAGGES t_new_msg;
	uint8_t ui8_message_len = 0;
	/* Init the AES context structure */
	AES_init_ctx_iv(&s_ctx, aui8_key, aui8_init_vec);

	t_test_string_len = strlen( (const char*)pui8_data );
	t_padded_len = t_test_string_len;
	memcpy(aui8_padded_msg, pui8_data, t_test_string_len);
#if defined(SECURE_MSG_DEBUG_MODE)
	//Decrypt buffer on CBC mode
	//Reference:void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
	PRINTF("SECURE_MSG_DEBUG_INFO: Decrypting buffer on CBC mode...\r\n");
#endif
	AES_CBC_decrypt_buffer(&s_ctx, aui8_padded_msg, t_padded_len);

	for(uint8_t ui8_Index = 0; ui8_Index < t_padded_len; ui8_Index++ )
	{
		if(aui8_padded_msg[ui8_Index] == 0)
		{
			ui8_message_len = ui8_Index;
			break;
		}
	}

	t_new_msg.ui8_msg = aui8_padded_msg;
	t_new_msg.t_padded_len = ui8_message_len;

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: Decrypted message completed \r\n");
#endif

	return t_new_msg;
}


void v_recv_cypher_message(T_MESSAGGES t_data)
{
	/*Definition of variables*/
	uint8_t ui8_Counter = 0;
	uint8_t aui8_Bytes[128];
	uint8_t aui8_crcBytes[4];
	T_MESSAGGES t_split_crc;
	T_MESSAGGES t_split_aes;
	uint32_t ui32_orig_checksum =  0;
	uint32_t ui32_calc_checksum =  0;

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: This is the encrypted message with CRC \r\n");
	for(uint8_t ui8_Index = 0; ui8_Index < t_data.t_padded_len; ui8_Index++)
	{
		PRINTF("%02x", aui8_Bytes[ui8_Index]);
	}
	PRINTF("\r\n\n");

	PRINTF("SECURE_MSG_DEBUG_INFO: Getting body message bytes \r\n");
#endif
	for(uint8_t ui8_Index = 0; ui8_Index < (uint8_t)(t_data.t_padded_len - (size_t)4); ui8_Index++)
	{
		aui8_Bytes[ui8_Index] = t_data.ui8_msg[ui8_Index];
	}

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: Getting CRC bytes \r\n");
#endif
	for(uint8_t ui8_Index = (uint8_t)(t_data.t_padded_len - (size_t)4); ui8_Index < (uint8_t)(t_data.t_padded_len) ; ui8_Index++)
	{
		aui8_crcBytes[ui8_Counter] = t_data.ui8_msg[ui8_Index];
		ui8_Counter++;
	}

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: Convert CRC bytes from the message to int \r\n");
#endif
	v_MakeLongfromBytes(&aui8_crcBytes[0], &ui32_orig_checksum);

	/*for (uint8_t ui8_Index = 0; ui8_Index < 4; ui8_Index++)
	{
		ui32_orig_checksum = ui32_orig_checksum + ( aui8_crcBytes[ui8_Index] *  pow(256,ui8_Index) );
	}*/

	t_split_crc.ui8_msg = aui8_Bytes;
	t_split_crc.t_padded_len =  t_data.t_padded_len - (size_t)4;

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: Calculating CRC32\r\n");
#endif
	ui32_calc_checksum = ui32_CRC32(t_split_crc);

#if defined(SECURE_MSG_DEBUG_MODE)
	/*Print messages in UART for debug purposes */
	PRINTF("SECURE_MSG_DEBUG_INFO: Checksum comparison\r\n");
#endif

	if(ui32_orig_checksum == ui32_calc_checksum)
	{
#if defined(SECURE_MSG_DEBUG_MODE)
		PRINTF("SECURE_MSG_DEBUG_INFO: calculated checksum tx %u checksum bytes %02x, Original checksum tx %u checksum bytes %02x \r\n",
				ui32_calc_checksum ,ui32_calc_checksum, ui32_orig_checksum, ui32_orig_checksum);
		PRINTF("SECURE_MSG_DEBUG_INFO: Checksum OK! Decrypting message...\r\n");
#endif
		t_split_aes = t_decrypt_message_AES(aui8_Bytes);

#if defined(SECURE_MSG_DEBUG_MODE)
		PRINTF("SECURE_MSG_DEBUG_INFO: Decrypted message: \r\n\n");
		for(uint8_t ui8_Index = 0; ui8_Index<t_split_aes.t_padded_len; ui8_Index++)
		{
			PRINTF("%c", t_split_aes.ui8_msg[ui8_Index]);
		}
		PRINTF("\r\n\n");
#endif
	}
	else
	{
#if defined(SECURE_MSG_DEBUG_MODE)
		PRINTF("SECURE_MSG_DEBUG_INFO: calculated checksum tx %u checksum bytes %02x, Original checksum tx %u checksum bytes %02x \r\n",
				ui32_calc_checksum ,ui32_calc_checksum, ui32_orig_checksum, ui32_orig_checksum);
		PRINTF("SECURE_MSG_DEBUG_INFO: Checksum NOT OK: Checksum does not match \r\n\n");
#endif
	}
#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: Finished \r\n\n\n");
#endif

}

T_MESSAGGES t_write_cypher_message(uint8_t* pui8_data)
{
	/*Definition of variables*/
	uint8_t ui8_Counter = 0;
	uint8_t aui8_crcBytes[4];
	T_MESSAGGES t_split_aes;
	T_MESSAGGES t_encrypted_msg;
	uint32_t ui32_calc_checksum =  0;

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: This is the message before encrypted \r\n");
	for(uint8_t ui8_Index = 0; ui8_Index < strlen( (const char*) pui8_data); ui8_Index++)
	{
		PRINTF("%c", pui8_data[ui8_Index]);
	}
	PRINTF("\r\n\n");
#endif

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: Encrypting message: \r\n\n");
#endif
	t_split_aes = t_encrypt_message_AES(pui8_data);

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: Encrypted message: \r\n\n");
	for(uint8_t ui8_Index = 0; ui8_Index<t_split_aes.t_padded_len; ui8_Index++)
	{
		PRINTF("%02x", t_split_aes.ui8_msg[ui8_Index]);
	}
	PRINTF("\r\n\n");
#endif

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: Calculating CRC32\r\n");
#endif
	ui32_calc_checksum = ui32_CRC32(t_split_aes);

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: Convert CRC message from int to bytes  \r\n");
#endif
	v_MakeBytesfromLong(&ui32_calc_checksum, &aui8_crcBytes[0]);

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: calculated checksum tx %u checksum bytes %02x\r\n", ui32_calc_checksum ,ui32_calc_checksum);
#endif

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: Building the message \r\n");
#endif
	/* Building the encrypted message with crc*/
	t_encrypted_msg.ui8_msg = t_split_aes.ui8_msg;

	for(uint8_t ui8_Index = (uint8_t)(t_split_aes.t_padded_len); ui8_Index < (uint8_t)(t_split_aes.t_padded_len + (size_t)4) ; ui8_Index++)
	{
		t_encrypted_msg.ui8_msg[ui8_Index] = aui8_crcBytes[ui8_Counter];
		ui8_Counter++;
	}

	t_encrypted_msg.t_padded_len =  (t_split_aes.t_padded_len + (size_t)4);

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: This is the full frame with CRC  \r\n");
	for(uint8_t ui8_Index = 0; ui8_Index < t_encrypted_msg.t_padded_len ; ui8_Index++)
	{
		PRINTF("%02x", t_encrypted_msg.ui8_msg[ui8_Index]);
	}
	PRINTF("\r\n\n");
#endif

#if defined(SECURE_MSG_DEBUG_MODE)
	PRINTF("SECURE_MSG_DEBUG_INFO: Finished \r\n");
#endif
	return t_encrypted_msg;

}

void v_MakeBytesfromLong(uint32_t* ui32_integer, uint8_t aui8_data[])
{
	aui8_data[0] = ((*ui32_integer) >> 24) & 0xFF;
	aui8_data[1] = ((*ui32_integer) >> 16) & 0xFF;
	aui8_data[2] = ((*ui32_integer) >> 8) & 0xFF;
	aui8_data[3] = ((*ui32_integer)) & 0xFF;
}

void v_MakeLongfromBytes(uint8_t aui8_data[], uint32_t* ui32_integer)
{
	*ui32_integer =  (aui8_data[0]);
	*ui32_integer |= (aui8_data[1] << 8);
	*ui32_integer |= (aui8_data[2] << 16);
	*ui32_integer |= (aui8_data[3] << 24);

}
