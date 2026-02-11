/*
 *   Portspoof  - Service Signature Emulator  / Exploitation Framework Frontend
 *   Copyright (C) 2012 Piotr Duszynski <piotr[at]duszynski.eu>
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the
 *   Free Software Foundation; either version 2 of the License, or (at your
 *   option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *   See the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, see <http://www.gnu.org/licenses>.
 *
 *   Linking portspoof statically or dynamically with other modules is making
 *   a combined work based on Portspoof. Thus, the terms and conditions of
 *   the GNU General Public License cover the whole combination.
 *
 *   In addition, as a special exception, the copyright holder of Portspoof
 *   gives you permission to combine Portspoof with free software programs or
 *   libraries that are released under the GNU LGPL. You may copy
 *   and distribute such a system following the terms of the GNU GPL for
 *   Portspoof and the licenses of the other code concerned.
 *
 *   Note that people who make modified versions of Portspoof are not obligated
 *   to grant this special exception for their modified versions; it is their
 *   choice whether to do so. The GNU General Public License gives permission
 *   to release a modified version without this exception; this exception
 *   also makes it possible to release a modified version which carries
 *   forward this exception.
 */


#ifndef CONNECTION_H
#define CONNECTION_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <vector>
#include <cstdint>
#include <ctime>

#define SO_ORIGINAL_DST 80
#define MAX_CONN 16384
#define EPOLL_BATCH 256

class Configuration;

struct conn_state
{
    int fd;
    uint16_t dst_port;
    uint8_t phase; /* 0=unused 1=sending 2=tarpit */
    uint8_t bhvr;
    uint32_t send_off;
    const std::vector<char>* sig;
    std::vector<char>* sig_owned; /* for fuzzer mode, caller frees */
    uint64_t t_accept;
    uint32_t t_timeout;
    uint32_t gen;
};

void set_nonblock(int fd);
int get_ipstr(int fd, char* ipstr);
void run_epoll(int listenfd, int epfd, int shutfd,
               struct conn_state* cs, int maxfd, Configuration* conf);


#endif