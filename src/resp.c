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

typedef enum resp_protocol_status
{
    PROTOCOL_ERR,
    REQ_STAR, REQ_READY,
    ARGS_COUNT, ARGS_COUNT_LF,
    ARG_LEN_DOLL, ARG_LEN, ARG_LEN_LF,
    ARG, ARG_LF
}RESPProtocolStatus;

typedef enum resp_reader_task_type{NEW_CLIENT} RESPReaderTaskType;
typedef struct resp_reader RESPReader;
typedef struct resp_reader_task RESPReaderTask;

typedef struct resp_cmd RESPCommand;


struct resp_client
{
    RESPReader *reader;
    int fd;
    struct sockaddr_in *add;
    ev_io watcher;
    
    char *buff_in;
    size_t buff_in_cap;
    off_t buff_in_free;
    off_t buff_in_head;
    off_t buff_in_tail;
    off_t buff_in_parse;

    RESPProtocolStatus pro_status;
    RESPCommand *pro_cmd;
};

struct resp_cmd
{
    size_t args_cap;
    size_t args_count;
    char **args;
    size_t *arg_lens;
    off_t arg_ptr;
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
    
    size_t cmd_strus_count;
    GTrashStack *cmd_strus;
    RESPCommand *cmd;
    
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

static RESPCommand *reader_get_cmd_strut(RESPReader *reader, size_t min_cap);




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



static RESPClient *client_new(RESPReader *reader, int fd, struct sockaddr_in *add)
{
    RESPClient *result = (RESPClient *)mm_malloc(sizeof(RESPClient));
    result->reader = reader;
    result->fd = fd;
    result->add = add;
    return result;
}

static inline bool client_buff_in_expand(RESPClient *client, size_t min_cap)
{
    if(min_cap > client->buff_in_cap)
    {
        while((client->buff_in_cap) < min_cap)
        {
            (client->buff_in_cap) *= 2;
        }
        
        char *old_buff = client->buff_in;
        client->buff_in = mm_malloc(client->buff_in_cap);
        memcpy(client->buff_in, old_buff + (client->buff_in_free), (client->buff_in_tail) - (client->buff_in_free));
        (client->buff_in_tail) = (client->buff_in_tail) - (client->buff_in_free);
        (client->buff_in_head) = (client->buff_in_head) - (client->buff_in_free);
        client->buff_in_free = 0;
        mm_free(old_buff);
        return true;
    }
    return false;
}
static inline char *client_buff_in_init(RESPClient *client)
{
    client->buff_in_cap = 1024;
    client->buff_in_free = 0;
    client->buff_in_head = 0;
    client->buff_in_tail = 0;
    client->buff_in = (char *)mm_malloc(client->buff_in_cap);
}

static inline char *client_buff_in_tail(RESPClient *client)
{
    return (client->buff_in) + (client->buff_in_tail);
}

static inline size_t client_buff_in_space(RESPClient *client)
{
    return (client->buff_in_cap) - (client->buff_in_tail);
}

static inline size_t client_buff_in_len(RESPClient *client)
{
    return (client->buff_in_tail) - (client->buff_in_head);
}

static inline off_t client_buff_in_tail_incr(RESPClient *client, off_t incr)
{
    (client->buff_in_tail) += incr;
}

static RESPCommand *client_buff_in_process(RESPClient *client)
{
    char *buff = client->buff_in;
    off_t tail = client->buff_in_tail;

    off_t head = client->buff_in_head;
    off_t parse = client->buff_in_parse;
    RESPProtocolStatus status = client->pro_status;
    RESPCommand *cmd = client->pro_cmd;
    
    while((tail - head) > 0 && status != PROTOCOL_ERR && status != REQ_READY)
    {
        if(status == REQ_STAR)
        {
            if(buff[head] == '*')
            {
                head++;
                parse = head;
                status = ARGS_COUNT;
            }
            else
            {
                status = PROTOCOL_ERR;
            }
        }
        else if(status == ARGS_COUNT)
        {
            if(buff[head] == '\r')
            {
                status = ARGS_COUNT_LF;
            }
            head++;
        }
        else if(status == ARGS_COUNT_LF)
        {
            if(buff[head] == '\n')
            {
                size_t args_count = g_ascii_strtoull (buff+parse, NULL, 10);
                cmd = reader_get_cmd_strut(client->reader, args_count);
                cmd->args_count = args_count;
                cmd->arg_ptr = 0;
                head++;
                status = ARG_LEN_DOLL;
            }
            else
            {
                status = PROTOCOL_ERR;
            }
        }
        else if(status == ARG_LEN_DOLL)
        {
            if(buff[head] == '$')
            {
                head++;
                parse = head;
                status = ARG_LEN;
            }
            else
            {
                status = PROTOCOL_ERR;
            }
        }
        else if(status == ARG_LEN)
        {
            if(buff[head] == '\r')
            {
                cmd->arg_lens[cmd->arg_ptr] = g_ascii_strtoull (buff+parse, NULL, 10);
                status = ARG_LEN_LF;
            }
            head++;
        }
        else if(status == ARG_LEN_LF)
        {
            if(buff[head] == '\n')
            {
                status = ARG;
                head++;
                cmd->args[cmd->arg_ptr] = buff + head;
            }
            else
            {
                status = PROTOCOL_ERR;
            }
        }
        else if(status == ARG)
        {
            if(buff[head] == '\r')
            {
                if((head - (cmd->args[cmd->arg_ptr] - buff)) == cmd->arg_lens[cmd->arg_ptr])
                {
                    (cmd->arg_ptr)++;
                    status = ARG_LF;
                    head++;
                }
                else
                {
                    status = PROTOCOL_ERR;
                }
            }
            else
            {
                head++;
            }
        }
        else if(status == ARG_LF)
        {
            if(buff[head] == '\n')
            {
                head++;
                (cmd->arg_ptr)++;
                if((cmd->arg_ptr) < (cmd->args_count))
                {
                    status = ARG_LEN_DOLL;
                }
                else
                {
                    status = REQ_READY;
                }
            }
            else
            {
                status = PROTOCOL_ERR;
            }
        }
    }
    
    client->buff_in_head = head;
    client->buff_in_parse = parse;
    client->pro_status = status;
    client->pro_cmd = cmd;
}

static void client_cb_read(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    RESPClient *client = (RESPClient *)(watcher->data);
    
    while(true)
    {
        if(client_buff_in_space(client) == 0)
        {
            client_buff_in_expand(client, (client->buff_in_cap) * 2);
        }
        ssize_t read_count = read(client->fd, client_buff_in_tail(client), client_buff_in_space(client));
        client_buff_in_tail_incr(client, read_count);
        printf("-------zc: buff [%s], head [%d], tail [%d]\n",client->buff_in,client->buff_in_head, client->buff_in_tail);
        
        if(client_buff_in_len(client) > 0)
        {
            client_buff_in_process(client);
            printf("---------zc: pro_status = [%d] \n",client->pro_status);
            
            if(client->pro_status == REQ_READY)
            {
                printf("--------zc:cmd of [%d] args processed\n",client->pro_cmd->args_count);
                client->pro_cmd = NULL;
                client->pro_status = REQ_STAR;
            }
            
        }
        else
        {
            break;
        }
    }

}

static RESPCommand *reader_get_cmd_strut(RESPReader *reader, size_t min_cap)
{
    RESPCommand * stru = NULL;
    if(reader->cmd_strus_count > 0)
    {
        stru = g_trash_stack_pop(&(reader->cmd_strus));
        (reader->cmd_strus_count)--;
    }
    else
    {
        stru = (RESPCommand *)mm_malloc(sizeof(RESPCommand));
        stru->args_cap = 0;
        stru->args = NULL;
        stru->arg_lens = NULL;
    }
    
    if((stru->args_cap) < min_cap)
    {
        while((stru->args_cap) < min_cap)
        {
            if((stru->args_cap) == 0 )
            {
                stru->args_cap = 16;
            }
            else
            {
                (stru->args_cap) *= 2;
            }
        }
        mm_free(stru->arg_lens);
        mm_free(stru->args);
        stru->args = mm_malloc(sizeof(char *) * (stru->args_cap));
        stru->arg_lens = mm_malloc(sizeof(size_t) * (stru->args_cap));
    }
    return stru;
}

static RESPReaderTask *reader_task_new(RESPReaderTaskType type, void *data, size_t data_len)
{
    RESPReaderTask *result = (RESPReaderTask *)mm_malloc(sizeof(RESPReaderTask));
    result->type = type;
    result->data = data;
    result->data_len = data_len;
    return result;
}

static void reader_task_new_client(void *data, size_t data_len)
{
    RESPClient *client = (RESPClient *)data;
    
    client_buff_in_init(client);
    client->pro_status = REQ_STAR;
    
    ev_io_init(&(client->watcher), client_cb_read, client->fd, EV_READ);
    ev_io_start(client->reader->loop, &(client->watcher));
    client->watcher.data = client;
    
    g_hash_table_add (client->reader->clients,client);
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
        result->readers[i].name = g_strdup_printf("resp[%d]:reader[%d]", result->port, i);
        result->readers[i].srv = result;
        result->readers[i].loop = ev_loop_new(EVFLAG_AUTO);
        result->readers[i].task_queue = g_queue_new();
        result->readers[i].clients = g_hash_table_new(g_direct_hash, g_direct_equal);
        result->readers[i].cmd_strus = NULL;
        result->readers[i].cmd_strus_count = 0;
        result->readers[i].cmd = NULL;
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
