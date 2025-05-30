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

#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <time.h>

//remove
#include <netinet/in.h>
#include <arpa/inet.h>

int packet_ack_number = 0;

microtcp_sock_t microtcp_socket (int domain, int type, int protocol)
{
  microtcp_sock_t new_socket;
  if ((new_socket.sd = socket(domain,type,protocol)) == -1) {
    perror("SOCKET COULD NOT BE OPENED");
    exit(EXIT_FAILURE);
  }

  srand(time(NULL));
  new_socket.state = CLOSED;
  new_socket.init_win_size = MICROTCP_WIN_SIZE;
  new_socket.curr_win_size = 0;
  new_socket.recvbuf = (uint8_t *) malloc(sizeof(uint8_t) * MICROTCP_RECVBUF_LEN);
  new_socket.buf_fill_level = 0;
  new_socket.cwnd = MICROTCP_INIT_CWND;
  new_socket.ssthresh = MICROTCP_INIT_SSTHRESH;
  new_socket.seq_number = rand() % 1000;
  // new_socket.seq_number = 0;
  new_socket.ack_number = 0;
  new_socket.expected_ack_number = new_socket.seq_number;
  new_socket.packets_send = 0;
  new_socket.packets_received = 0;
  new_socket.packets_lost = 0;
  new_socket.bytes_send = 0 ;
  new_socket.bytes_received = 0;
  new_socket.bytes_lost = 0;
  new_socket.duplicate_acks = 0;
  return new_socket;
}

int microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
    if (bind(socket->sd, address, address_len) == -1) {
        perror("Error binding socket");
        return -1;
    }

    socket->server_address = address;
    socket->server_address_len = address_len;
    socket->state = LISTEN;
    printf("Listening for connections...\n");
    return EXIT_SUCCESS;
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len)
{
  socket->server_address = address;
  socket->server_address_len = address_len;

  if (connect(socket->sd, address, address_len) == -1) {
      perror("Error connecting to server");
      // close(socket->sd);
      return MICROTCP_HANDSHAKE_FAILED;
  }

  // Send blank message to server
  sendto(socket->sd, NULL, 0, 0, (struct sockaddr *) socket->server_address, socket->server_address_len);

  // // Connection established
  // socket->state = ESTABLISHED;
  socket->state = WAIT_HANDSHAKE;
  // Three way handshake
  // Send SYN
  if(MICROTCP_HANDSHAKE_DEBUG)
    printf("Sending SYN\n");
  microtcp_packet_t packet = createPacket(socket,0,0,MICROTCP_SYN_CONTROL,0);
  send_packet_to(socket,&packet,SERVER);
  // print_packet(&packet);
  if(MICROTCP_PACKET_DEBUG)
    printf("Expecting SYN-ACK\n");

  // Expecting SYN-ACK
  recover_packet_from(socket,&packet,CLIENT);
  socket->ack_number = packet.header.seq_number;
  // print_packet(&packet);
  if(!isPacketSYNACK(packet))
  {
    if(MICROTCP_PACKET_DEBUG)
      printf("SYN-ACK not received\n");
    return MICROTCP_HANDSHAKE_FAILED;
  }
  if(MICROTCP_PACKET_DEBUG)
    printf("SYN-ACK Received\n");

  // Send ACK
  if(MICROTCP_PACKET_DEBUG)
    printf("Sending ACK\n");
  packet = createPacket(socket,0,0,MICROTCP_ACK_CONTROL,MICROTCP_WIN_SIZE);
  send_packet_to(socket,&packet,SERVER);
  socket->curr_win_size = MICROTCP_WIN_SIZE;
  // print_packet(&packet);
  socket->state = ESTABLISHED;
  return EXIT_SUCCESS;
}

int microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
  socket->client_address = address;
  socket->client_address_len = address_len;
  // Wait for blank message from client
  recvfrom(socket->sd, NULL, 0, 0, socket->client_address, &socket->client_address_len);
  printf("Client Connected Address: %d\n",socket->client_address->sin_addr.s_addr);
  
  // Connection established
  socket->state = ESTABLISHED;

  // Three way handshake
  microtcp_packet_t packet;
  
  // Expecting SYN packet
  if(MICROTCP_HANDSHAKE_DEBUG)
    printf("Expecting SYN\n");
  recover_packet_from(socket,&packet,CLIENT);
  // socket->ack_number = packet.header.seq_number;
  // socket->init_win_size = packet.header.window;
  // print_packet(&packet);
  if(!isPacketSYN(packet))
  {
    if(MICROTCP_HANDSHAKE_DEBUG)
      printf("SYN not received\n");
    return MICROTCP_HANDSHAKE_FAILED;
  }
  if(MICROTCP_HANDSHAKE_DEBUG)
    printf("SYN received\n");

  // Send SYN-ACK packet
  if(MICROTCP_HANDSHAKE_DEBUG)
    printf("Sending SYN-ACK\n");
  packet = createPacket(socket,0,0,MICROTCP_SYN_ACK_CONTROL,MICROTCP_WIN_SIZE);
  send_packet_to(socket,&packet,CLIENT);
  // print_packet(&packet);
  
  // Expecting ACK packet
  recover_packet_from(socket,&packet,CLIENT);
  socket->init_win_size = packet.header.window;
  socket->curr_win_size = packet.header.window;
  socket->ack_number = packet.header.seq_number;
  // print_packet(&packet);
  if(!isPacketACK(packet))
  {
    // print_header(packet.header);
    if(MICROTCP_HANDSHAKE_DEBUG)
      printf("ACK not received\n");
    return MICROTCP_HANDSHAKE_FAILED;
  }
  if(MICROTCP_HANDSHAKE_DEBUG)
    printf("ACK Received\n");

  socket->congestion_state = SLOW_START;
  // return client_socket;
}

int microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  microtcp_packet_t fin_packet = createPacket(socket,NULL,0,MICROTCP_FIN_CONTROL,0);
  send_packet_to(socket,&fin_packet,SERVER);
  socket->state = CLOSED;
  free(socket->recvbuf);
  close(socket->sd);
}

ssize_t microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
  if(socket->state != ESTABLISHED) {
    printf("Socket not connected\n");
    // return -1;
    exit(-1);
  }

  microtcp_packet_t packet = createPacket(socket, buffer, length, MICROTCP_DEFAULT_CONTROL, 0);
  ssize_t packet_size = send_packet_to(socket,&packet,0);
  

  socket->expected_ack_number += packet.header.data_len;

  socket->curr_win_size += packet_size;
  // print_packet(&packet);

  //retransmission timer
  struct timeval timeout;
  // timeout.tv_sec = 0;
  // timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
      // perror("setsockopt");
  }

  // Wait for ACK
  microtcp_packet_t ack_packet;
  int ack_bytes_received = recover_packet_from(socket,&ack_packet,SERVER);

  // retransmit
  if(ack_bytes_received == -1)
  {
    printf("\nACK not received. Retransmitting packet\n");
    send_packet_to(socket,&packet,0);
    ack_bytes_received = recover_packet_from(socket,&ack_packet,SERVER);
  }

  // check if ACK is correct else retransmit
  if(ack_packet.header.ack_number != socket->expected_ack_number) {
    //retransmit
    send_packet_to(socket,&packet,0);
    ack_bytes_received = recover_packet_from(socket,&ack_packet,SERVER);
  }

  while(isPacketACK(ack_packet) && ack_packet.header.ack_number != socket->expected_ack_number && socket->duplicate_acks <= 3) {
    if(ack_packet.header.ack_number == socket->ack_number) {
      socket->duplicate_acks++;
    }
    ack_bytes_received = recover_packet_from(socket,&ack_packet,SERVER);
  }
  if(socket->cwnd <= socket->ssthresh) {
    socket->congestion_state = SLOW_START;
  }
  else {
    socket->congestion_state = CONGESTION_AVOIDANCE;
  }
  // after the checks the ACK has been received successfully
  if(socket->congestion_state == SLOW_START) {
    socket->cwnd *= MICROTCP_MSS;
  }
  else if(socket->congestion_state == CONGESTION_AVOIDANCE) {
    socket->cwnd += MICROTCP_MSS;
  }

  socket->curr_win_size = ack_packet.header.window;

  if(socket->duplicate_acks > 3) {
    //retransmit
    send_packet_to(socket,&packet,0);
  }
  else {
    //congestion avoidance
    socket->cwnd += MICROTCP_MSS;
    socket->ssthresh = socket->cwnd / 2;
    socket->cwnd = (socket->cwnd / 2) + 1;
  }

  socket->duplicate_acks = 0;

  // print_packet(&ack_packet);
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  if(socket->state != ESTABLISHED) {
    printf("Socket not connected\n");
    return -1;
  }
  microtcp_packet_t packet;
  ssize_t bytes_recovered = recover_packet_from(socket,&packet,CLIENT);

  // print_packet(&packet);

  //until the correct packet is received
  //while
  if(bytes_recovered == -1) {
    microtcp_packet_t duplicate_ack = createPacket(socket,NULL,0,MICROTCP_ACK_CONTROL,0);
    duplicate_ack.header.ack_number = packet.header.seq_number;
    ssize_t duplicate_ack_bytes = send_packet_to(socket,&duplicate_ack,CLIENT);
    //wait for new packet
    bytes_recovered = recover_packet_from(socket,&packet,CLIENT);
  }

  //check if seq number is correct
  if(packet.header.seq_number != (socket->ack_number - packet.header.data_len))
  {
    printf("Invalid SEQ Number received\nSEQ Number expected: %d\nSEQ Number Received: %d\n",socket->ack_number,packet.header.seq_number);
    printf("Sending duplicate ACK...\n");
    microtcp_packet_t duplicate_ack = createPacket(socket,NULL,0,MICROTCP_ACK_CONTROL,0);
    duplicate_ack.header.ack_number = packet.header.seq_number;
    send_packet_to(socket,&duplicate_ack,CLIENT);
  }
  
  // printf("Bytes Received %d\n",socket->bytes_received);

  // print_packet(&packet);

  //copy packet data to buffer
  for(int i = 0; i < packet.header.data_len; i++) {
    memcpy(buffer + i, packet.data + i, 1);
  }

  //add null terminator
  memcpy(buffer + packet.header.data_len, "\0", 1);

  //copy buffer to socket recvbuf
  for(int i = 0; i < packet.header.data_len; i++) {
    memcpy(socket->recvbuf + socket->buf_fill_level + i, buffer + i, 1);
  }
  socket->buf_fill_level += packet.header.data_len;

  socket->curr_win_size -= packet.header.data_len;

  // send ACK
  if(bytes_recovered != -1) {
    microtcp_packet_t ack_packet = createPacket(socket,NULL,0,MICROTCP_ACK_CONTROL,socket->curr_win_size);
    send_packet_to(socket,&ack_packet,CLIENT);
    //increase window by Y since packet was sent
    socket->curr_win_size += bytes_recovered;
  }
}

void print_packet(microtcp_packet_t *packet) {
  if(!packet) {
    // printf("Packet is NULL\n");
    return;
  }
  // assert(packet);
  
  if(!MICROTCP_PRINT_PACKET) return;

  microtcp_header_t header = packet->header;
  void *data = packet->data;
  printf("\n\n------PACKET---------\n");
  printf("-----PACKET HEADER-----\n");
  printf("seq_number: %d\n", header.seq_number);
  printf("ack_number: %d\n", header.ack_number);
  printf("control: %d\n", header.control);
  printf("window: %d\n", header.window);
  printf("data_len: %d\n", header.data_len);
  printf("future_use0: %d\n", header.future_use0);
  printf("future_use1: %d\n", header.future_use1);
  printf("future_use2: %d\n", header.future_use2);
  printf("checksum: %d\n", header.checksum);
  printf("Header Bytes:\n");
  for (int i = 0; i < sizeof(microtcp_header_t); i++) {
    printf("%02x ", *((unsigned char *) &header + i));
  }
  printf("\n");
  if(header.data_len > 0 && data) {
    printf("-----PACKET DATA-----\n");
    printf("ASCII Data: %s\n", (char *) data);
    printf("Data Bytes:\n");
    for (int i = 0; i < header.data_len; i++) {
      printf("%02x ", *((unsigned char *) data + i));
    }
    printf("\n");
  }
  printf("----END OF PACKET-----\n\n\n");
}

int isPacketSYNACK(microtcp_packet_t packet) {
  return packet.header.control == MICROTCP_SYN_ACK_CONTROL;
}

int isPacketSYN(microtcp_packet_t packet) {
  return packet.header.control == MICROTCP_SYN_CONTROL;
}

int isPacketACK(microtcp_packet_t packet) {
  return packet.header.control == MICROTCP_ACK_CONTROL;
}

int isPacketFIN(microtcp_packet_t packet) {
  return packet.header.control == MICROTCP_FIN_CONTROL;
}

int isPacketRST(microtcp_packet_t packet) {
  return packet.header.control == MICROTCP_RST_CONTROL;
} 

int isPacketDefault(microtcp_packet_t packet) {
  return packet.header.control == MICROTCP_DEFAULT_CONTROL;
}

/*
  * Sends a packet to a peer
  * @param socket the socket structure
  * @param packet the packet to be sent
  * @param peer the peer to send the packet to
*/
int send_packet_to(microtcp_sock_t *socket,microtcp_packet_t *packet,peer_t peer) {
  if(socket->state != ESTABLISHED && socket->state != WAIT_HANDSHAKE) {
    printf("Socket not connected\n");
    return -1;
  }

  ssize_t header_bytes_sent;
  ssize_t payload_bytes_sent;
  ssize_t total_bytes_sent = 0;
  struct sockaddr_in *address;
  socklen_t address_len;
  if(peer == CLIENT){
    address = socket->client_address;
    address_len = socket->client_address_len;
  }
  else{
    address = socket->server_address;
    address_len = socket->server_address_len;
  }

  ssize_t total_packet_size = sizeof(microtcp_header_t) + packet->header.data_len;
  // packet->header.checksum = crc32((uint8_t*)packet, sizeof(microtcp_header_t) + packet->header.data_len);
  header_bytes_sent = sendto(socket->sd,&packet->header,sizeof(microtcp_header_t),0,(struct sockaddr *)address,address_len);
  total_bytes_sent += header_bytes_sent;
  if(packet->header.data_len > 0) {
    payload_bytes_sent = sendto(socket->sd,packet->data,packet->header.data_len,0,(struct sockaddr *)address,address_len);
  } else {
    sendto(socket->sd,NULL,0,0,(struct sockaddr *)address,address_len);
    payload_bytes_sent = 0;
  }

  if (header_bytes_sent == -1) {
    perror("Error sending data");
    socket->packets_lost++;
    socket->bytes_lost += sizeof(microtcp_header_t) + packet->header.data_len;
    return -1;
  }
  socket->bytes_send += total_bytes_sent;
  socket->packets_send++;

  socket->seq_number += payload_bytes_sent;
  socket->ack_number += socket->ack_number + payload_bytes_sent;

  return total_bytes_sent;
}
/*
  * Recovers a packet from a peer
  * @param socket the socket structure
  * @param packet the packet to be recovered
  * @param peer the peer to recover the packet from
*/
int recover_packet_from(microtcp_sock_t *socket, microtcp_packet_t *packet,peer_t peer){
  if(socket->state != ESTABLISHED && socket->state != WAIT_HANDSHAKE) {
    printf("Socket not connected\n");
    // return -1;
    exit(-1);
  }

  struct sockaddr_in *address;
  socklen_t address_len;
  ssize_t total_bytes = 0;
  ssize_t header_bytes_received;
  ssize_t payload_bytes_received;
  address = NULL;
  address_len = 0;

  //recover header
  header_bytes_received = recvfrom(socket->sd, &packet->header, sizeof(microtcp_header_t), 0, (struct sockaddr *)address, address_len);
  if (header_bytes_received == -1) {
    perror("Error receiving data");
    printf("Header bytes not received");
    socket->packets_lost++;
    socket->bytes_lost += sizeof(microtcp_header_t) + packet->header.data_len;
    // exit(-1);
    return -1;
  }

  // CHECKS
  // Special Packets Filtering
  if(isPacketRST(*packet)) {
    printf("Received RST packet. Closing connection.\n");
    microtcp_shutdown(socket,SHUT_RDWR);
    exit(-1);
  }
  else if(isPacketFIN(*packet)) {
    printf("Received FIN packet. Closing Connection\n");
    microtcp_shutdown(socket,SHUT_RDWR);
    exit(-1);
  }

  // // ACK mismatch
  // if(packet->header.ack_number != socket->ack_number) {
  //   microtcp_packet_t rst_packet = createPacket(socket,NULL,0,MICROTCP_RST_CONTROL,0);
  //   send_packet_to(socket,&rst_packet,CLIENT);
  //   printf("Invalid ACK Number received\nACK Number expected: %d\nACK Number Received: %d\n",socket->ack_number,packet->header.ack_number);
  //   microtcp_shutdown(socket,SHUT_RDWR);
  // }  

  total_bytes += header_bytes_received;
  //recover payload
  if(packet->header.data_len > 0) {
    payload_bytes_received = recvfrom(socket->sd, packet->data, packet->header.data_len, 0, (struct sockaddr*)address, address_len);
    total_bytes += payload_bytes_received;
    
    if(payload_bytes_received == -1) {
      perror("Error receiving data");
      printf("Payload bytes not received\n");
      socket->packets_lost++;
      socket->bytes_lost += sizeof(microtcp_header_t) + packet->header.data_len;
      return -1;
    }
    socket->bytes_received += total_bytes;

    socket->seq_number += payload_bytes_received;
  }
  else {
    recvfrom(socket->sd,NULL,0,0,(struct sockaddr *)address, address_len);
  }
  
  socket->ack_number = packet->header.seq_number + packet->header.data_len;

  // CRC32 Check
  if(packet->header.checksum != crc32((uint8_t*)packet->data, packet->header.data_len)) 
  {
    printf("CRC32 Check Failed. Packet is corrupted\n");
    return -1;
  }

  socket->packets_received++;
  return total_bytes;
}

void extractData(void *packet,size_t packet_length, microtcp_header_t header,void *buffer)
{
  //extract header data from packet
  memcpy(&header, packet, sizeof(microtcp_header_t));
  //extract payload data from packet
  memcpy(buffer, packet + sizeof(microtcp_header_t), packet_length - sizeof(microtcp_header_t));
}

microtcp_packet_t createPacket(microtcp_sock_t *socket,void *data,size_t data_length,int control,int window) {
  if(data_length+sizeof(microtcp_header_t) > MICROTCP_RECVBUF_LEN) {
    printf("Cannot create packet over %d bytes. Your packet bytes: %d\n",MICROTCP_RECVBUF_LEN,sizeof(microtcp_header_t) + data_length);
    exit(-1);
  }
  microtcp_packet_t packet;
  packet.header.seq_number = socket->seq_number;
  packet.header.ack_number = socket->ack_number;
  packet.header.control = control;
  packet.header.window = window;
  packet.header.data_len = data_length;
  packet.header.future_use0 = 0;
  packet.header.future_use1 = 0;
  packet.header.future_use2 = 0;
  if(data_length > 0)
  {
    packet.header.checksum = crc32((uint8_t*)data, data_length);
  }
  else {
    packet.header.checksum = 0;
  }
  // packet.header.checksum = crc32((uint8_t*)&packet, sizeof(microtcp_header_t) + data_length);
  packet.data = data;
  return packet;
}

void printIP(struct sockaddr_in *address) {
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(address->sin_addr), ip, INET_ADDRSTRLEN);
  printf("IP Address: %s\n", ip);
}

// microtcp_packet_t assemblePacket(microtcp_sock_t)