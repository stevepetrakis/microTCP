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

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */
#include "../lib/microtcp.h"
#include <stddef.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc,char **argv) {
    microtcp_sock_t socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //IPPROTO_UDP
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(8080);
    address.sin_addr.s_addr = INADDR_ANY;
    microtcp_bind(&socket, (struct sockaddr*) &address, sizeof(address));
    char buffer[1024];
    int client = microtcp_accept(&socket, (struct sockaddr*)&address, sizeof(address));
    if(client == MICROTCP_HANDSHAKE_FAILED) {
        printf("Three way handshake failed.\n");
        printf("Disconnecting Client\n");
    }
    printf("Client Connected\n");
    while(1) {
        microtcp_recv(&socket, buffer, 1024, 0);
        printf("Buffer: %s\n",buffer);    
    }
}
