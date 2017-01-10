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
#include <glib.h>

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

typedef struct resp_client RESPClient;

typedef struct resp_reader RESPReader;
typedef enum resp_reader_task_type{NEW_CLIENT} RESPReaderTaskType;
typedef struct resp_reader_task RESPReaderTask;

struct resp_client
{
    RESPReader *reader;
    int fd;
    struct sockaddr_in *add;
    ev_io watcher;
    
    char *buff_in;
    size_t buff_in_cap;
    off_t buff_in_head;
    off_t buff_in_tail;
    
};

struct resp_reader_task
{
    RESPReaderTaskType type;
    void *data;
    size_t data_len;
};

struct resp_reader
{
    char *name;
    
    RESPServer *srv;
    struct ev_loop *loop;
    GThread *thread;
    
    GHashTable *clients;
    
    ev_async notifier;
    GQueue *task_queue;
};

struct resp_server
{
    int port;
    struct ev_loop *loop;
    
    int list_fd;
    ev_io list_watcher;
    
    int reader_num;
    int read_ptr;
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

static RESPReaderTask *reader_task_new(RESPReaderTaskType type, void *data, size_t data_len)
{
    RESPReaderTask *result = (RESPReaderTask *)mm_malloc(sizeof(RESPReaderTask));
    result->type = type;
    result->data = data;
    result->data_len = data_len;
    return result;
}

static void client_cb_read(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    RESPClient *client = (RESPClient *)(watcher->data);
    ssize_t read_count = read(client->fd, client->buff_in, client->buff_in_cap - 1);
    client->buff_in[read_count] = '\0';
    log_debug("client_cb_read [%s]",client->buff_in);
}

static void reader_task_new_client(void *data, size_t data_len)
{
    RESPClient *client = (RESPClient *)data;
    
    client->buff_in_cap = 1024;
    client->buff_in_head = 0;
    client->buff_in_tail = 0;
    client->buff_in = (char *)mm_malloc(client->buff_in_cap);
    
    ev_io_init(&(client->watcher), client_cb_read, client->fd, EV_READ);
    ev_io_start(client->reader->loop, &(client->watcher));
    client->watcher.data = client;
    
    g_hash_table_add (client->reader->clients,client);
}

static RESPClient *client_new(RESPReader *reader, int fd, struct sockaddr_in *add)
{
    RESPClient *result = (RESPClient *)mm_malloc(sizeof(RESPClient));
    result->reader = reader;
    result->fd = fd;
    result->add = add;
    return result;
}

void reader_cb_task(struct ev_loop *loop, ev_async * watcher, int revents)
{
    RESPReader *reader = (RESPReader *)watcher->data;
    RESPReaderTask *task = (RESPReaderTask *)g_queue_pop_head (reader->task_queue);
    while(task != NULL)
    {
        if(task->type == NEW_CLIENT)
        {
            reader_task_new_client(task->data, task->data_len);
        }
        mm_free(task);
        task = (RESPReaderTask *)g_queue_pop_head (reader->task_queue);
    }
}

gpointer reader_loop (gpointer data)
{
    RESPReader *reader = (RESPReader *)data;
    do{}while(ev_run(reader->loop, 0));
    return NULL;
}

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    RESPServer *srv = (RESPServer *)(watcher->data);

    if(EV_ERROR & revents)
    {
        log_error("accept error events [%d], msg: [%s]",revents, strerror(errno));
        return;
    }

    struct sockaddr_in *client_add = (struct sockaddr_in *)mm_malloc(sizeof(struct sockaddr_in));
    int  client_fd = net_accept(srv->list_fd, client_add);
    if (client_fd < 0)
    {
        log_error("accept failed [%s]",strerror(errno));
        return;
    }
    if(net_set_socket_addr_reuse(client_fd) == false)
    {
        log_warn("set client socket reuse failed");
    }

    log_debug("client [%s:%d] connected",inet_ntoa(client_add->sin_addr),client_add->sin_port);

    RESPClient *client = client_new(&(srv->readers[(srv->read_ptr)++]), client_fd, client_add);
    RESPReaderTask *task = reader_task_new(NEW_CLIENT, client, 0);
    g_queue_push_tail (client->reader->task_queue, task);

    ev_async_send(client->reader->loop, &(client->reader->notifier));
}

RESPServer *resp_new_server(int port, int readers)
{
    RESPServer *result = (RESPServer *)mm_malloc(sizeof(RESPServer));
    result->port = port;
    result->loop = ev_loop_new(EVFLAG_AUTO);
    result->list_fd = -1;
    result->list_watcher.data = result;
    
    result->reader_num = readers;
    result->readers = (RESPReader *)mm_malloc(sizeof(RESPReader) * result->reader_num);
    for(int i = 0; i<(result->reader_num); i++)
    {
        result->readers[i].name = g_strdup_printf("resp[%d]:reader[%d]", srv->port, i);
        result->readers[i].srv = result;
        result->readers[i].loop = ev_loop_new(EVFLAG_AUTO);
        result->readers[i].task_queue = g_queue_new();
        result->readers[i].clients = g_hash_table_new(g_direct_hash, g_direct_equal);
    }

    return result;
}


void resp_server_start(RESPServer *srv)
{
    srv->list_fd = net_listen(srv->port, 5);
    
    for(int i = 0; i<(srv->reader_num); i++)
    {
        ev_async_init(&(srv->readers[i].notifier), reader_cb_task);
        ev_async_start(srv->readers[i].loop, &(srv->readers[i].notifier));
        srv->readers[i].notifier.data = &(srv->readers[i]);
        srv->readers[i].thread = g_thread_new (srv->readers[i].name, reader_loop, &(srv->readers[i]));
    }

    ev_io_init(&(srv->list_watcher), accept_cb, srv->list_fd, EV_READ);
    ev_io_start(srv->loop, &(srv->list_watcher));
    
    srv->read_ptr = 0;
    do{}while(ev_run (srv->loop, 0));
}
