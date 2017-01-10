/*
 resp.c
 como
 
 BSD 2-Clause License
 
 Copyright (c) 2017, Zhou Chong <zhouchonghz AT gmail.com>
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 
 * Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 
 * Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "resp.h"
#include "mm.h"
#include "log.h"

#include <ev.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

typedef struct resp_reader
{
    RESPServer *srv;
    struct ev_loop *loop;
    
    
    
}RESPReader;

struct resp_server
{
    int port;
    struct ev_loop *loop;
    
    int list_fd;
    ev_io list_watcher;
    
    int reader_num;
    RESPReader *readers;
};

bool net_set_socket_addr_reuse(int socket_fd)
{
    int yes = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
    {
        log_error("setsockopt SO_REUSEADDR failed: [%s]", strerror(errno));
        return false;
    }
    return true;
}

static int net_listen(int port, int backlog)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        log_error("could not create socket fd");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    
    net_set_socket_addr_reuse(fd);
    
    if (bind(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        log_error("failed at bind");
        close(fd);
        return -2;
    }
    
    if(listen(fd,backlog) != 0)
    {
        log_error("failed at listen");
        close(fd);
        return -3;
    }
    
    return fd;
}

int net_accept(int listen_fd, struct sockaddr_in *client_add)
{
    int add_len = sizeof(struct sockaddr_in);
    return accept(listen_fd, (struct sockaddr *)client_add, (socklen_t*)(&add_len));
}

void callback_accept(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    if(EV_ERROR & revents)
    {
        log_error("accept error events [%d], msg: [%s]",revents, strerror(errno));
        return;
    }
    
    RESPServer *srv = (RESPServer *)(watcher->data);

    struct sockaddr_in client_add;
    int  client_fd = net_accept(srv->list_fd, &client_add);
    if(net_set_socket_addr_reuse(client_fd) == false)
    {
        log_warn("set client socket reuse failed");
    }
    if (client_fd < 0)
    {
        log_error("accept failed [%s]",strerror(errno));
        return;
    }
    log_debug("client [%s] connected",inet_ntoa(client_add.sin_addr));

    ev_io *client_watcher = (ev_io*) mm_malloc(sizeof(struct ev_io));

    
//    ev_io_init(client_watcher, read_cb, client_fd, EV_READ);
//    ev_io_start(loop, w_client);
}

RESPServer *resp_new_server(int port, int readers)
{
    RESPServer *result = (RESPServer *)mm_malloc(sizeof(RESPServer));
    result->port = port;
    result->loop = ev_loop_new(EVFLAG_AUTO);
    result->list_fd = -1;
    
    result->reader_num = readers;
    result->readers = (RESPReader *)mm_malloc(sizeof(RESPReader) * result->reader_num);
    for(int i = 0; i<(result->reader_num); i++)
    {
        result->readers[i].srv = result;
        result->readers[i].loop = ev_loop_new(EVFLAG_AUTO);
    }

    return result;
}

void resp_server_start(RESPServer *srv)
{
    srv->list_fd = net_listen(srv->port, 5);
    srv->list_watcher.data = srv;

    ev_io_init(&(srv->list_watcher), callback_accept, srv->list_fd, EV_READ);
    ev_io_start(srv->loop, &(srv->list_watcher));
    
    do
    {
        
    }while(ev_run (srv->loop, 0));
}
