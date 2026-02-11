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

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <queue>
#include <utility>

#include "connection.h"
#include "Configuration.h"

extern Configuration* configuration;

struct timeout_entry
{
    uint64_t expiry;
    int fd;
    uint32_t gen;
    bool operator>(const timeout_entry& o) const { return expiry > o.expiry; }
};

typedef std::priority_queue<timeout_entry, std::vector<timeout_entry>,
                            std::greater<timeout_entry>> timeout_heap;

static uint64_t mono_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


int get_ipstr(int fd, char* ipstr)
{
    socklen_t len;
    struct sockaddr_storage addr;

    len = sizeof(struct sockaddr_storage);
    if (getpeername(fd, (struct sockaddr*)&addr, &len) < 0)
    {
        ipstr[0] = '?';
        ipstr[1] = '\0';
        return 0;
    }

    if (addr.ss_family == AF_INET)
    {
        struct sockaddr_in* s = (struct sockaddr_in*)&addr;
        inet_ntop(AF_INET, &s->sin_addr, ipstr, INET_ADDRSTRLEN);
    }
    else
    {
        struct sockaddr_in6* s = (struct sockaddr_in6*)&addr;
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    }
    return 1;
}


void set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0)
    {
        perror("fcntl F_GETFL");
        return;
    }
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
        perror("fcntl F_SETFL");
}


static void conn_close(int fd, int epfd, struct conn_state* cs, int* nactive)
{
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);

    if (cs[fd].sig_owned)
    {
        delete cs[fd].sig_owned;
        cs[fd].sig_owned = NULL;
    }
    cs[fd].phase = 0;
    cs[fd].fd = -1;
    (*nactive)--;
}


/*
 * Drain accept queue. For each new connection:
 *  - get original dst port (iptables REDIRECT)
 *  - look up signature
 *  - register in epoll for writing the banner
 *
 * If we're at capacity, evict the oldest connection to make room.
 */
static void do_accept(int listenfd, int epfd, struct conn_state* cs,
                      int maxfd, Configuration* conf, int* nactive, timeout_heap& heap)
{
    struct sockaddr_in peer;
    socklen_t peerlen;
    struct sockaddr_in orig;
    socklen_t origlen;
    int fd;
    uint64_t now = mono_now();

    for (;;)
    {
        peerlen = sizeof(peer);
        fd = accept(listenfd, (struct sockaddr*)&peer, &peerlen);
        if (fd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            perror("accept");
            break;
        }

        if (fd >= maxfd)
        {
            /* fd too large for our tracking array — close it,
             * then evict the connection nearest to expiry to
             * free a slot for the next accept() call. */
            close(fd);
            int victim = -1;
            uint64_t earliest = UINT64_MAX;
            for (int v = 0; v < maxfd; v++)
            {
                if (cs[v].phase == 0)
                    continue;
                uint64_t exp = cs[v].t_accept + cs[v].t_timeout;
                if (exp < earliest)
                {
                    earliest = exp;
                    victim = v;
                }
            }
            if (victim >= 0)
                conn_close(victim, epfd, cs, nactive);
            continue;
        }

        set_nonblock(fd);

        /* get the port the scanner was actually aiming for */
        origlen = sizeof(orig);
        uint16_t dport = DEFAULT_PORT;
        if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST,
                       (struct sockaddr*)&orig, &origlen) == 0)
        {
            dport = ntohs(orig.sin_port);
        }

        /* look up the banner for this port */
        const std::vector<char>* sigptr = NULL;
        std::vector<char>* owned = NULL;

        if (conf->isFuzzing())
        {
            owned = new std::vector<char>(conf->mapPort2Signature(dport));
            sigptr = owned;
        }
        else
        {
            sigptr = conf->getSignaturePtr(dport);
        }

        cs[fd].fd = fd;
        cs[fd].dst_port = dport;
        cs[fd].send_off = 0;
        cs[fd].sig = sigptr;
        cs[fd].sig_owned = owned;
        cs[fd].t_accept = now;
        uint32_t base_ms = conf->getPortTimeout(dport);
        uint32_t spread = base_ms / 5;
        if (spread > 0)
            base_ms = base_ms - spread / 2 + rand() % (spread + 1);
        cs[fd].t_timeout = base_ms;
        cs[fd].bhvr = conf->getPortBehavior(dport);

        struct epoll_event ev;
        ev.data.fd = fd;

        if (cs[fd].bhvr == BHVR_WAIT ||
            cs[fd].bhvr == BHVR_SILENT)
        {
            cs[fd].phase = 2;
            ev.events = EPOLLIN | EPOLLET;
        }
        else
        {
            cs[fd].phase = 1;
            ev.events = EPOLLOUT | EPOLLET;
        }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
        {
            perror("epoll_ctl ADD");
            close(fd);
            cs[fd].phase = 0;
            cs[fd].fd = -1;
            cs[fd].sig_owned = NULL;
            if (owned) delete owned;
            continue;
        }

        cs[fd].gen++;
        heap.push({now + cs[fd].t_timeout, fd, cs[fd].gen});
        (*nactive)++;

        /* log it */
        char ipstr[INET6_ADDRSTRLEN];
        memset(ipstr, 0, sizeof(ipstr));
        get_ipstr(fd, ipstr);

        char msg[MAX_LOG_MSG_LEN];
        memset(msg, 0, sizeof(msg));
        snprintf(msg, MAX_LOG_MSG_LEN,
                 "%d # Service_probe # SIGNATURE_SEND # source_ip:%s # dst_port:%d\n",
                 (int)time(NULL), ipstr, (int)dport);
        Utils::log_write(configuration, msg);

        if (conf->getConfigValue(OPT_DEBUG))
            fprintf(stdout, "accept fd=%d port=%d timeout=%ums active=%d\n",
                    fd, dport, cs[fd].t_timeout, *nactive);
    }
}


/*
 * Push as much of the banner as the socket will take.
 */
static void do_send(int fd, int epfd, struct conn_state* cs, int* nactive)
{
    struct conn_state* c = &cs[fd];

    if (!c->sig || c->sig->size() == 0)
    {
        c->phase = 2;
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = fd;
        epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
        return;
    }

    const char* buf = c->sig->data() + c->send_off;
    int remain = c->sig->size() - c->send_off;
    ssize_t n;

    while (remain > 0)
    {
        n = send(fd, buf, remain, MSG_NOSIGNAL);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return; /* will get another EPOLLOUT */
            return; /* broken pipe or similar, timeout will reap it */
        }
        c->send_off += n;
        buf += n;
        remain -= n;
    }

    /* done sending, hold until timeout */
    c->phase = 2;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
}


/*
 * Tarpit / hold phase: drain incoming data, keep socket alive.
 * WAIT modes haven't sent their banner yet so we do that first.
 */
static void do_tarpit(int fd, int epfd, struct conn_state* cs, int* nactive)
{
    struct conn_state* c = &cs[fd];
    char junk[4096];
    ssize_t n;

    for (;;)
    {
        n = recv(fd, junk, sizeof(junk), 0);
        if (n > 0)
        {
            if (c->bhvr == BHVR_WAIT)
            {
                c->phase = 1;
                c->send_off = 0;
                struct epoll_event ev;
                ev.events = EPOLLOUT | EPOLLET;
                ev.data.fd = fd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
                do_send(fd, epfd, cs, nactive);
                return;
            }
            continue; /* eat it */
        }
        if (n == 0)
        {
            conn_close(fd, epfd, cs, nactive);
            return;
        }
        /* n < 0 */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return; /* drained, keep holding */
        conn_close(fd, epfd, cs, nactive);
        return;
    }
}


static void do_timeouts(struct conn_state* cs, int epfd,
                        timeout_heap& heap, uint64_t now, int* nactive)
{
    while (!heap.empty())
    {
        const timeout_entry& top = heap.top();
        if (top.expiry > now)
            break;

        int fd = top.fd;
        uint32_t gen = top.gen;
        heap.pop();

        if (cs[fd].phase == 0)
            continue; /* already closed */
        if (cs[fd].gen != gen)
            continue; /* stale entry, fd was recycled */

        conn_close(fd, epfd, cs, nactive);
    }
}


void run_epoll(int listenfd, int epfd, int shutfd,
               struct conn_state* cs, int maxfd, Configuration* conf)
{
    struct epoll_event events[EPOLL_BATCH];
    timeout_heap heap;
    int nactive = 0;
    int running = 1;

    while (running)
    {
        int n = epoll_wait(epfd, events, EPOLL_BATCH, 10);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }

        uint64_t now = mono_now();

        for (int i = 0; i < n; i++)
        {
            int fd = events[i].data.fd;

            if (fd == shutfd)
            {
                running = 0;
                break;
            }

            if (fd == listenfd)
            {
                do_accept(listenfd, epfd, cs, maxfd, conf,
                          &nactive, heap);
                continue;
            }

            if (events[i].events & (EPOLLERR | EPOLLHUP))
            {
                if (cs[fd].phase)
                    conn_close(fd, epfd, cs, &nactive);
                continue;
            }

            if (events[i].events & EPOLLOUT)
            {
                if (cs[fd].phase == 1)
                    do_send(fd, epfd, cs, &nactive);
            }

            if (events[i].events & EPOLLIN)
            {
                if (cs[fd].phase == 2)
                    do_tarpit(fd, epfd, cs, &nactive);
            }
        }

        do_timeouts(cs, epfd, heap, now, &nactive);
    }

    /* shutdown: close everything still alive */
    for (int i = 0; i < maxfd; i++)
    {
        if (cs[i].phase)
            conn_close(i, epfd, cs, &nactive);
    }
}