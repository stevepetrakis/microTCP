/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIB_MICROTCP_H_
#define LIB_MICROTCP_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

/*
 * Several useful constants
 */
#define MICROTCP_ACK_TIMEOUT_US 200000
#define MICROTCP_MSS 1400
#define MICROTCP_RECVBUF_LEN 8192
#define MICROTCP_WIN_SIZE MICROTCP_RECVBUF_LEN
#define MICROTCP_INIT_CWND (3 * MICROTCP_MSS)
#define MICROTCP_INIT_SSTHRESH MICROTCP_WIN_SIZE

#define MICROTCP_DEFAULT_CONTROL 0
#define MICROTCP_FIN_CONTROL 1
#define MICROTCP_SYN_CONTROL 2
#define MICROTCP_RST_CONTROL 4
#define MICROTCP_ACK_CONTROL 8
#define MICROTCP_SYN_ACK_CONTROL 12

/*
  * Error codes
*/
#define MICROTCP_HANDSHAKE_FAILED 10

/*
  * Debugging macros
*/
#define MICROTCP_HANDSHAKE_DEBUG 0
#define MICROTCP_PACKET_DEBUG 1
#define MICROTCP_PRINT_PACKET 1

/**
 * Possible states of the microTCP socket
 *
 * NOTE: You can insert any other possible state
 * for your own convenience
 */
typedef enum
{
  LISTEN,
  WAIT_HANDSHAKE,
  ESTABLISHED,
  CLOSING_BY_PEER,
  CLOSING_BY_HOST,
  CLOSED,
  INVALID
} mircotcp_state_t;

typedef enum {
  SLOW_START,
  CONGESTION_AVOIDANCE
} congestion_state_t;


/**
 * This is the microTCP socket structure. It holds all the necessary
 * information of each microTCP socket.
 *
 * NOTE: Fill free to insert additional fields.
 */
typedef struct
{
  int sd;                       /**< The underline UDP socket descriptor */
  mircotcp_state_t state;       /**< The state of the microTCP socket */
  size_t init_win_size;         /**< The window size negotiated at the 3-way handshake */
  size_t curr_win_size;         /**< The current window size */

  struct sockaddr_in *server_address;
  socklen_t server_address_len;

  struct sockaddr_in *client_address;
  socklen_t client_address_len;

  uint8_t *recvbuf;             /**< The *receive* buffer of the TCP
                                     connection. It is allocated during the connection establishment and
                                     is freed at the shutdown of the connection. This buffer is used
                                     to retrieve the data from the network. */
  size_t buf_fill_level;        /**< Amount of data in the buffer */

  size_t cwnd;
  size_t ssthresh;

  size_t seq_number;            /**< Keep the state of the sequence number */
  size_t ack_number;            /**< Keep the state of the ack number */
  size_t expected_ack_number;   /**< Keep the state of the expected ack number */

  uint64_t packets_send;
  uint64_t packets_received;
  uint64_t packets_lost;
  uint64_t bytes_send;
  uint64_t bytes_received;
  uint64_t bytes_lost;
  uint64_t duplicate_acks;
  congestion_state_t congestion_state;
} microtcp_sock_t;


/**
 * microTCP header structure
 * NOTE: DO NOT CHANGE!
 */
typedef struct
{
  uint32_t seq_number;          /**< Sequence number */
  uint32_t ack_number;          /**< ACK number */
  uint16_t control;             /**< Control bits (e.g. SYN, ACK, FIN) */
  uint16_t window;              /**< Window size in bytes */
  uint32_t data_len;            /**< Data length in bytes (EXCLUDING header) */
  uint32_t future_use0;         /**< 32-bits for future use */
  uint32_t future_use1;         /**< 32-bits for future use */
  uint32_t future_use2;         /**< 32-bits for future use */
  uint32_t checksum;            /**< CRC-32 checksum, see crc32() in utils folder */
} microtcp_header_t;

typedef struct {
  microtcp_header_t header;
  void *data;
} microtcp_packet_t;

typedef enum {
  SERVER,
  CLIENT
} peer_t;

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol);

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len);

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len);

/**
 * Blocks waiting for a new connection from a remote peer.
 *
 * @param socket the socket structure
 * @param address pointer to store the address information of the connected peer
 * @param address_len the length of the address structure.
 * @return ATTENTION despite the original accept() this function returns
 * 0 on success or -1 on failure
 */
int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len);

int
microtcp_shutdown(microtcp_sock_t *socket, int how);

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags);

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags);


//custom functions
int send_packet_to(microtcp_sock_t *socket, microtcp_packet_t *packet,peer_t peer);
int recover_packet_from(microtcp_sock_t *socket, microtcp_packet_t *packet,peer_t peer);

int isPacketSYN(microtcp_packet_t packet);
int isPacketACK(microtcp_packet_t packet);
int isPacketFIN(microtcp_packet_t packet);
int isPacketSYNACK(microtcp_packet_t packet);

microtcp_packet_t createPacket(microtcp_sock_t *socket,void *data,size_t data_length,int control,int window);

//delete
void print_packet(microtcp_packet_t *packet);
void printIP(struct sockaddr_in *address);

#endif /* LIB_MICROTCP_H_ */
