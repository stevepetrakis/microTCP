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
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
// #include <arpa/inet.h>
// #define CLIENT_DEBUG 1


int
main(int argc, char **argv)
{
    microtcp_sock_t socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    char buffer[1024];
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(8080);
    // address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_addr.s_addr = INADDR_ANY;
    microtcp_connect(&socket, (struct sockaddr*)&address, sizeof(address));
    microtcp_send(&socket, "mplampla", sizeof(char) * strlen("mplampla"), 0);

    microtcp_send(&socket, "mplampla2", sizeof(char) * strlen("mplampla2"), 0);

    microtcp_shutdown(&socket, SHUT_RDWR);
}
