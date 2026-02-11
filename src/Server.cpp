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


#include "Server.h"

static int g_shutfd = -1;

static void sig_shutdown(int sig)
{
    (void)sig;
    if (g_shutfd >= 0)
    {
        uint64_t v = 1;
        if (write(g_shutfd, &v, sizeof(v)) < 0)
        {
            /* best effort */
        }
    }
}


Server::Server(Configuration* configuration)
{
    this->configuration = configuration;
    this->cstates = NULL;

    raise_fdlimit();

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        maxfd = (int)rl.rlim_cur;
    }
    else
    {
        maxfd = MAX_CONN;
    }
    /* cap it to something sane */
    if (maxfd > 65536)
        maxfd = 65536;

    cstates = (struct conn_state*)calloc(maxfd, sizeof(struct conn_state));
    if (!cstates)
    {
        perror("calloc conn_state");
        exit(1);
    }
    for (int i = 0; i < maxfd; i++)
        cstates[i].fd = -1;

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0)
    {
        perror("epoll_create1");
        exit(1);
    }

    shutfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (shutfd < 0)
    {
        perror("eventfd");
        exit(1);
    }
    g_shutfd = shutfd;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = shutfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, shutfd, &ev);

    /* tcp listen socket */
    listenfd = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listenfd == -1)
    {
        perror("Socket creation error");
        exit(1);
    }

    int reuse = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&my_name, 0, sizeof(my_name));
    my_name.sin_family = PF_INET;

    if (configuration->getConfigValue(OPT_IP))
    {
        fprintf(stdout, "-> Binding to iface: %s\n",
                configuration->getBindIP().c_str());
        inet_aton(configuration->getBindIP().c_str(), &my_name.sin_addr);
    }
    else
    {
        my_name.sin_addr.s_addr = INADDR_ANY;
    }

    if (configuration->getConfigValue(OPT_PORT))
    {
        fprintf(stdout, "-> Binding to port: %d\n",
                configuration->getPort());
        my_name.sin_port = htons(configuration->getPort());
    }
    else
    {
        my_name.sin_port = htons(DEFAULT_PORT);
    }

    status = bind(listenfd, (struct sockaddr*)&my_name, sizeof(my_name));
    if (status == -1)
    {
        perror("Binding error");
        exit(1);
    }

    status = listen(listenfd, 1024);
    if (status == -1)
    {
        perror("Listen set error");
        exit(1);
    }

    /* listen socket into epoll, level-triggered */
    ev.events = EPOLLIN;
    ev.data.fd = listenfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);

    setup_signals();

    return;
}


Server::~Server()
{
    if (cstates) free(cstates);
    if (epfd >= 0) close(epfd);
    if (listenfd >= 0) close(listenfd);
    if (shutfd >= 0) close(shutfd);
}


void Server::setup_signals()
{
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_shutdown;
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}


void Server::raise_fdlimit()
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        if (rl.rlim_cur < rl.rlim_max)
        {
            rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }
}


bool Server::run()
{
    run_epoll(listenfd, epfd, shutfd, cstates, maxfd, configuration);
    return true;
}