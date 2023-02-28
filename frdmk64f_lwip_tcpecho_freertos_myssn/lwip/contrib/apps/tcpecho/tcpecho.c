/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include "tcpecho.h"

#include "lwip/opt.h"

#if LWIP_NETCONN

#include "lwip/sys.h"
#include "lwip/api.h"

#include "secure_msg/secure_msg.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* IP address configuration. */
#ifndef clientIP_ADDR0
#define clientIP_ADDR0 192
#endif
#ifndef clientIP_ADDR1
#define clientIP_ADDR1 168
#endif
#ifndef clientIP_ADDR2
#define clientIP_ADDR2 0
#endif
#ifndef clientIP_ADDR3
#define clientIP_ADDR3 100
#endif

/*-----------------------------------------------------------------------------------*/
static void 
tcpecho_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);

  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 7);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, IP_ADDR_ANY, 10000);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /*TEST AES CRC FUNCTIONS BEFORE TO ESTABLISH THE CONNECTION*/
  //v_aescrc_test_task();
  /* Tell connection to go into listening mode. */
  netconn_listen(conn);

  while(1)
  {
	  PRINTF("\n\nSECURE_MSG_DEBUG_INFO: Waiting for new connection \r\n");
      /* Grab new connection. */
      err = netconn_accept(conn, &newconn);
      /*printf("accepted new connection %p\n", newconn);*/
      /* Process the new connection. */
      if (err == ERR_OK)
      {
        struct netbuf *buf;
        void *data;
        u16_t len;
        T_MESSAGGES t_new_msg;
        const char *message1 = "Message received successfully";

        PRINTF("SECURE_MSG_DEBUG_INFO: Connection Accepted. Waiting for receive messages\r\n");

        while ((err = netconn_recv(newconn, &buf)) == ERR_OK)
        {
        	/*This function is used to obtain a pointer to and the length of a block of data in the netbuf buf.*/
            netbuf_data(buf, &data, &len);
            t_new_msg.ui8_msg = data;
            t_new_msg.t_padded_len = len;

            /*Use function to evaluate message for decrypting */
            v_recv_cypher_message(t_new_msg);
            do
            {
            	/*Use function to encrypt the message response  */
            	t_new_msg = v_write_cypher_message((uint8_t*) message1);
            	data =  t_new_msg.ui8_msg;
            	len = t_new_msg.t_padded_len;
            	netbuf_data(buf, &data, &len);
            	err = netconn_write(newconn, data, len, NETCONN_COPY);

  #if 0
            	if (err != ERR_OK) {
            		printf("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
            	}
  #endif
            }while (netbuf_next(buf) >= 0);
            netbuf_delete(buf);
        }
        /*printf("Got EOF, looping\n");*/
        /* Close connection and discard connection identifier. */
        netconn_close(newconn);
        netconn_delete(newconn);
      }
  }
}

static void
tcpecho_client_thread(void *arg)
{
  struct netconn *conn;
  err_t err;
  u8_t max_iterations = 8;
  /* IP address configuration. */
  ip4_addr_t server_addr;

  IP4_ADDR(&server_addr, clientIP_ADDR0, clientIP_ADDR1, clientIP_ADDR2, clientIP_ADDR3);
  LWIP_UNUSED_ARG(arg);

  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 7);
#else /* LWIP_IPV6 */
  /* Create a new connection identifier. */
  conn = netconn_new(NETCONN_TCP);

  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  err = netconn_connect(conn, &server_addr, 10000);
  if(err == ERR_OK)
  {
	  PRINTF("Server Connected \n\r");
  }
  else
  {
	  PRINTF("Connection error \"%s\"\n\r", lwip_strerr(err));
  }
#endif /* LWIP_IPV6 */

  while (max_iterations--)
  {
      struct netbuf *buf;
      void *data;
      u16_t len;
      T_MESSAGGES t_new_msg;
      const char *messages[8] = {"Mensaje de prueba 123",
    		  	  	  	  	  	 "Otro mensaje de prueba 234",
								 "Mas pruebas 567",
								 "Mas pruebas 890",
								 "Seguimos probando",
								 "Esto sigue siendo una prueba",
								 "Hola, yo de nuevo",
								 "Si, 8 mensajes de prueba"};
/*
      const char *message2 = "Otro mensaje de prueba 234";
      const char *message3 = "Mas pruebas 567";
      const char *message4 = "Mas pruebas 890";
      const char *message5 = "Seguimos probando";
      const char *message6 = "Esto sigue siendo una prueba";
      const char *message7 = "Hola, yo de nuevo";
      const char *message8 = "Si, 8 mensajes de prueba";
*/

      t_new_msg = v_write_cypher_message((uint8_t*) messages[max_iterations-1]);
	  data =  t_new_msg.ui8_msg;
	  len = t_new_msg.t_padded_len;

      if((err = netconn_write(conn, data, len, NETCONN_COPY)) != ERR_OK)
      {
    	  PRINTF("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
    	  break;
      }

      if((err = netconn_recv(conn, &buf)) != ERR_OK)
      {
    	  PRINTF("tcpecho: netconn_recv: error \"%s\"\n", lwip_strerr(err));
    	  break;
      }
      else
      {
          t_new_msg.ui8_msg = data;
          t_new_msg.t_padded_len = len;
          v_recv_cypher_message(t_new_msg);
      }

      PRINTF("Data Received:");
      do
      {
    	  netbuf_data(buf, &data, &len);
    	  char* ptrdata = (char*)data;
    	  for(int index = 0; index < len; index++)
    	  {
    		  PRINTF("%c", ptrdata[index]);
    	  }
      }while (netbuf_next(buf) >= 0);
      PRINTF("\n\r");
      netbuf_delete(buf);

      vTaskDelay(1000/portTICK_PERIOD_MS);
      /*printf("Got EOF, looping\n");*/
  }
  /* Close connection and discard connection identifier. */
  netconn_close(conn);
  netconn_delete(conn);

  vTaskDelete(NULL);
}
/*-----------------------------------------------------------------------------------*/
void
tcpecho_init(void)
{
	sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
	//sys_thread_new("tcpecho_thread", tcpecho_client_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}
/*-----------------------------------------------------------------------------------*/

#endif /* LWIP_NETCONN */
