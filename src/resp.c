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
#include <glib/gprintf.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
/*
    TODOs:
        [1]make reader task queue as lockless circular buffer
        [2]pooling and reuse client objects as RESPCommands like
 */

typedef struct resp_client RESPClient;

typedef enum resp_protocol_status
{
    PROTOCOL_ERR,
    REQ_STAR, REQ_READY,
    ARGS_COUNT, ARGS_COUNT_LF,
    ARG_LEN_DOLL, ARG_LEN, ARG_LEN_LF,
    ARG, ARG_LF
}RESPProtocolStatus;

typedef enum resp_reader_task_type{NEW_CLIENT, REPLY_READY} RESPReaderTaskType;
typedef struct resp_reader RESPReader;
typedef struct resp_reader_task RESPReaderTask;
typedef struct resp_client_buff RESPClientBuffer;

struct resp_client_buff
{
    size_t global_offset;
    char *buff;
    size_t free;
    size_t cap;
    size_t head;
    size_t tail;
    size_t parse;
};

struct resp_client
{
    bool is_closed;
    RESPReader *reader;
    int fd;
    struct sockaddr_in *add;
    ev_io watcher;
    
    RESPClientBuffer *buff_in;

    RESPProtocolStatus pro_status;
    RESPCommand *pro_cmd;
    
    GQueue *req_queue;
};

struct resp_conn
{
    RESPClient *client;
    RESPCommand *cmd;
};

struct resp_cmd
{
    size_t args_cap;
    size_t args_count;
    size_t *args;   //global offsets
    size_t *arg_lens;
    size_t arg_ptr;
    
    char *reply;
    size_t reply_cap;
    size_t reply_size;
    size_t reply_ptr;
    
    RESPConnection conn;
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
    GMutex task_queue_sync;
};  

struct resp_server
{
    int port;
    struct ev_loop *loop;
    RESPCommandProcess *proc;
    
    int list_fd;
    ev_io list_watcher;
    
    int reader_num;
    int read_ptr;
    RESPReader *readers;
};

static RESPCommand *reader_get_cmd_stru(RESPReader *reader, RESPClient *client, size_t min_cap);
static void reader_return_cmd_stru(RESPReader *reader, RESPCommand *cmd);



static int io_set_fd_blocking(int fd, int blocking)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
    {
        log_error("fcntl(F_GETFL) failed");
        return -1;
    }
    
    if (blocking)
    {
        flags &= ~O_NONBLOCK;
    }
    else
    {
        flags |= O_NONBLOCK;
    }
    
    if (fcntl(fd, F_SETFL, flags) == -1)
    {
        log_error("io_set_fd_blocking(%d,%d) failed", fd, blocking);
        return -2;
    }
    return 0;
}

int net_set_socket_tcp_no_delay(int socket_fd)
{
    int yes = 1;
    if (setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) == -1)
    {
        log_error("setsockopt(TCP_NODELAY) failed");
        return -1;
    }
    return 0;
}

static bool net_set_socket_addr_reuse(int socket_fd)
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

static int net_accept(int listen_fd, struct sockaddr_in *client_add)
{
    int add_len = sizeof(struct sockaddr_in);
    return accept(listen_fd, (struct sockaddr *)client_add, (socklen_t*)(&add_len));
}

static inline void cmd_serialize_error_vformat(RESPCommand *cmd, size_t max_len, const char *fmt, va_list args)
{
    max_len += 10;
    if((cmd->reply_cap) < max_len)
    {
        while((cmd->reply_cap) < max_len)
        {
            if(cmd->reply_cap == 0)
            {
                cmd->reply_cap = 64;
            }
            else
            {
                (cmd->reply_cap) *= 2;
            }
        }
        mm_free(cmd->reply);
        cmd->reply = mm_malloc(cmd->reply_cap);
    }
    
    memcpy(cmd->reply, "-ERR ", 5);
    gint len = g_vsnprintf (cmd->reply + 5, cmd->reply_cap - 5 -2, fmt, args);
    len = len +5;
    for(int i = 5; i<len; i++)
    {
        if(cmd->reply[i] == '\r' || cmd->reply[i] == '\n')
        {
            cmd->reply[i] = ' ';
        }
    }
    cmd->reply[len] = '\r';
    cmd->reply[len+1] = '\n';

    cmd->reply_size = len +2;
}

static inline void cmd_serialize_list(RESPCommand *cmd, char **vals, size_t *v_sizes, size_t val_num)
{
    int total_len = 0;
    for(int i = 0; i<val_num; i++)
    {
        total_len += v_sizes[i] + 50;
    }
    total_len += 50;
    
    if((cmd->reply_cap) < total_len)
    {
        while((cmd->reply_cap) < total_len)
        {
            if(cmd->reply_cap == 0)
            {
                cmd->reply_cap = 64;
            }
            else
            {
                (cmd->reply_cap) *= 2;
            }
        }
        mm_free(cmd->reply);
        cmd->reply = mm_malloc(cmd->reply_cap);
    }

    int ptr = 0;
    ptr += g_sprintf ((cmd->reply)+ptr, "*%lu\r\n", val_num);
    for(int i = 0; i<val_num; i++)
    {
        if(vals[i] == NULL)
        {
            ptr += g_sprintf ((cmd->reply)+ptr, "$-1\r\n");
        }
        else
        {
            ptr += g_sprintf ((cmd->reply)+ptr, "$%lu\r\n", v_sizes[i]);
            memcpy((cmd->reply)+ptr, vals[i], v_sizes[i]);
            ptr += v_sizes[i];
            (cmd->reply)[ptr++] = '\r';
            (cmd->reply)[ptr++] = '\n';
        }
    }
    cmd->reply_size = ptr;
}



static inline void client_buff_in_init(RESPClient *client)
{
    client->buff_in = (RESPClientBuffer *)mm_malloc(sizeof(RESPClientBuffer));
    client->buff_in->cap = 1024;
    client->buff_in->head = 0;
    client->buff_in->tail = 0;
    client->buff_in->free = 0;
    client->buff_in->buff = (char *)mm_malloc(client->buff_in->cap);
    client->buff_in->global_offset = 0;
}

static inline void client_buff_in_destory(RESPClient *client)
{
    mm_free(client->buff_in->buff);
    mm_free(client->buff_in);
}

static inline bool client_buff_in_compact(RESPClient *client)
{
    if(client->buff_in->free > 0)
    {
        memmove(client->buff_in->buff, (client->buff_in->buff) + (client->buff_in->free), (client->buff_in->tail) - (client->buff_in->free));
        (client->buff_in->global_offset) += (client->buff_in->free);
        (client->buff_in->tail) = (client->buff_in->tail) - (client->buff_in->free);
        (client->buff_in->head) = (client->buff_in->head) - (client->buff_in->free);
        (client->buff_in->parse) = (client->buff_in->parse) - (client->buff_in->free);
        client->buff_in->free = 0;
        return true;
    }
    else
    {
        return false;
    }
}

static inline bool client_buff_in_expand(RESPClient *client, size_t min_cap)
{
    if(min_cap > (client->buff_in->cap))
    {
        while((client->buff_in->cap) < min_cap)
        {
            (client->buff_in->cap) *= 2;
        }
        (client->buff_in->buff) = mm_realloc(client->buff_in->buff, client->buff_in->cap);
        return true;
    }
    return false;
}

static inline char *client_buff_in_tail(RESPClient *client)
{
    return (client->buff_in->buff) + (client->buff_in->tail);
}

static inline size_t client_buff_in_space(RESPClient *client)
{
    return (client->buff_in->cap) - (client->buff_in->tail);
}

static inline size_t client_buff_in_len(RESPClient *client)
{
    return (client->buff_in->tail) - (client->buff_in->head);
}

static inline void client_buff_in_tail_incr(RESPClient *client, off_t incr)
{
    (client->buff_in->tail) += incr;
}

static void client_buff_in_set_free(RESPClient *client, size_t free_global)
{
    client->buff_in->free = (free_global - client->buff_in->global_offset);
}

static void client_buff_in_process(RESPClient *client)
{
    char *buff = client->buff_in->buff;
    size_t tail = client->buff_in->tail;
    size_t global_off0 = client->buff_in->global_offset;

    size_t head = client->buff_in->head;
    size_t parse = client->buff_in->parse;
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
                cmd = reader_get_cmd_stru(client->reader, client, args_count);
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
                cmd->args[cmd->arg_ptr] = head+global_off0;
            }
            else
            {
                status = PROTOCOL_ERR;
            }
        }
        else if(status == ARG)
        {
            if((head - (cmd->args[cmd->arg_ptr] - global_off0)) == cmd->arg_lens[cmd->arg_ptr])
            {
                if(buff[head] == '\r')
                {
                    status = ARG_LF;
                }
                else
                {
                    status = PROTOCOL_ERR;
                }
            }
            head++;
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
    
    client->buff_in->head = head;
    client->buff_in->parse = parse;
    client->pro_status = status;
    client->pro_cmd = cmd;
}

static RESPClient *client_new(RESPReader *reader, int fd, struct sockaddr_in *add)
{
    RESPClient *result = (RESPClient *)mm_malloc(sizeof(RESPClient));
    result->is_closed = false;
    result->reader = reader;
    result->fd = fd;
    result->add = add;
    return result;
}

static void client_destory(RESPClient *client)
{
    if(client->is_closed)
    {
        RESPCommand *cmd = (RESPCommand *)g_queue_pop_head (client->req_queue);
        while(cmd != NULL)
        {
            reader_return_cmd_stru(client->reader, cmd);
            cmd = (RESPCommand *)g_queue_pop_head(client->req_queue);
        }
        g_queue_free(client->req_queue);
        client->req_queue = NULL;
        
        client_buff_in_destory(client);
        mm_free(client);
    }
}

static void client_close(RESPClient *client)
{
    g_hash_table_remove(client->reader->clients, client);
    ev_io_stop(client->reader->loop, &(client->watcher));
    client->watcher.data = NULL;
    close(client->fd);
    client->is_closed = true;
}

static void client_flush_cmd_replies(RESPClient *client)
{
    RESPCommand *cmd = (RESPCommand *)g_queue_peek_head (client->req_queue);
    while(cmd != NULL && (cmd->reply_size) > 0)
    {
        ssize_t write_result = write(client->fd, (cmd->reply) + (cmd->reply_ptr), (cmd->reply_size) - (cmd->reply_ptr));
        
        if(write_result < 0)
        {
            cmd = (RESPCommand *)g_queue_pop_head (client->req_queue);
            reader_return_cmd_stru(client->reader, cmd);
            log_error("try to write [%lu] bytes of reply failed, return=[%ld], msg=[%s], disconnect",cmd->reply_size,write_result,strerror(errno));
            client_close(client);
            break;
        }
        else
        {
            (cmd->reply_ptr) += write_result;
            if((cmd->reply_ptr) < (cmd->reply_size))
            {
                break;
            }
            else
            {
                client_buff_in_set_free(client, cmd->args[cmd->args_count - 1] + cmd->arg_lens[cmd->args_count-1] + 2);
                cmd = (RESPCommand *)g_queue_pop_head (client->req_queue);
                reader_return_cmd_stru(client->reader, cmd);
                cmd = (RESPCommand *)g_queue_peek_head (client->req_queue);
            }
        }
    }
}

static void client_read(RESPClient *client)
{
    while(true)
    {
        if(client_buff_in_space(client) == 0)
        {
            client_buff_in_compact(client);
        }
        if(client_buff_in_space(client) == 0)
        {
            client_buff_in_expand(client, (client->buff_in->cap) * 2);
        }
        
        ssize_t read_count = read(client->fd, client_buff_in_tail(client), client_buff_in_space(client));
        if(read_count > 0)
        {
            client_buff_in_tail_incr(client, read_count);
        }
        else if(read_count == 0)
        {
            client_close(client);   //EOF
            break;
        }
        else
        {
            if(errno != 11) //errno==11 means there is no more data temprarily
            {
                log_warn("read client failed [%s], disconnect",strerror(errno));
                client_close(client);
                break;
            }
        }
        
        if(client_buff_in_len(client) > 0)
        {
            client_buff_in_process(client);
            if(client->pro_status == REQ_READY)
            {
                client->pro_cmd->reply_size = 0;
                g_queue_push_tail (client->req_queue, client->pro_cmd);
                (*(client->reader->srv->proc))(&(client->pro_cmd->conn), client->pro_cmd);
                client->pro_cmd = NULL;
                client->pro_status = REQ_STAR;
            }
            else if(client->pro_status == PROTOCOL_ERR)
            {
                log_warn("invalid protocol from client, disconnect");
                client_close(client);
                break;
            }
        }
        else
        {
            break;
        }
    }
}

static void client_write(RESPClient *client)
{
    client_flush_cmd_replies(client);
}

static void client_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    RESPClient *client = (RESPClient *)(watcher->data);

    if(!(client->is_closed) && (revents & EV_WRITE))
    {
        client_write(client);
    }
    
    if(!(client->is_closed) && (revents & EV_READ))
    {
        client_read(client);
    }

    if(client->is_closed)
    {
        client_destory(client);
    }
}

static RESPCommand *reader_get_cmd_stru(RESPReader *reader, RESPClient *client, size_t min_cap)
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
        stru->conn.cmd = stru;
        stru->args_cap = 0;
        stru->args = NULL;
        stru->arg_lens = NULL;
        stru->reply = NULL;
        stru->reply_cap = 0;
    }
    
    stru->conn.client = client;
    stru->reply_size = 0;
    stru->reply_ptr = 0;
    
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
        stru->args = mm_malloc(sizeof(size_t) * (stru->args_cap));
        stru->arg_lens = mm_malloc(sizeof(size_t) * (stru->args_cap));
    }
    return stru;
}

static void reader_return_cmd_stru(RESPReader *reader, RESPCommand *cmd)
{
    if(reader->cmd_strus_count < (1024*1024))
    {
        g_trash_stack_push (&(reader->cmd_strus),cmd);
        (reader->cmd_strus_count)++;
    }
    else
    {
        mm_free(cmd->arg_lens);
        mm_free(cmd->args);
        mm_free(cmd->reply);
        mm_free(cmd);
    }
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
    client->req_queue = g_queue_new ();
    
    net_set_socket_tcp_no_delay(client->fd);
    io_set_fd_blocking(client->fd, 0);
    ev_io_init(&(client->watcher), client_cb, client->fd, EV_READ|EV_WRITE);
    ev_io_start(client->reader->loop, &(client->watcher));
    client->watcher.data = client;
    g_hash_table_add (client->reader->clients,client);
}

static void reader_cb_task(struct ev_loop *loop, ev_async * watcher, int revents)
{
    RESPReader *reader = (RESPReader *)watcher->data;
    g_mutex_lock(&(reader->task_queue_sync));
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
    g_mutex_unlock(&(reader->task_queue_sync));
}

static gpointer reader_loop (gpointer data)
{
    RESPReader *reader = (RESPReader *)data;
    do{}while(ev_run(reader->loop, 0));
    return NULL;
}

static void reader_enqueue_task(RESPReader *reader, RESPReaderTask *task)
{
    g_mutex_lock(&(reader->task_queue_sync));
    g_queue_push_tail(reader->task_queue, task);
    g_mutex_unlock(&(reader->task_queue_sync));
    
    ev_async_send(reader->loop, &(reader->notifier));
}

static void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
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

    RESPClient *client = client_new(&(srv->readers[srv->read_ptr]), client_fd, client_add);
    (srv->read_ptr) = ((srv->read_ptr) + 1) % (srv->reader_num);
  
    RESPReaderTask *task = reader_task_new(NEW_CLIENT, client, 0);
    reader_enqueue_task(client->reader, task);
}

RESPServer *resp_new_server(int port, RESPCommandProcess *proc, int readers)
{
    RESPServer *result = (RESPServer *)mm_malloc(sizeof(RESPServer));
    result->proc = proc;
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
        g_mutex_init(&(result->readers[i].task_queue_sync));
    }

    return result;
}

void resp_server_start(RESPServer *srv)
{
    srv->list_fd = net_listen(srv->port, 5);
    
    if(srv->list_fd >= 0)
    {
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
    else
    {
        log_error("listen on port [%d] failed, fd=[%d]", srv->port, srv->list_fd);
    }
}

size_t resp_cmd_get_args_count(RESPCommand *cmd)
{
    return cmd->args_count;
}

char *resp_cmd_get_arg(RESPCommand *cmd, off_t index)
{
    return cmd->conn.client->buff_in->buff + (cmd->args[index] - cmd->conn.client->buff_in->global_offset);
}

size_t *resp_cmd_get_arg_lens(RESPCommand *cmd)
{
    return cmd->arg_lens;
}

void resp_reply_list(RESPConnection *con, char **vals, size_t *v_sizes, size_t val_num)
{
    cmd_serialize_list(con->cmd, vals, v_sizes, val_num);
}

void resp_reply_error(RESPConnection *con, size_t max_len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap,fmt);
    cmd_serialize_error_vformat(con->cmd, max_len, fmt, ap);
    va_end(ap);
}
