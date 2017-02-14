/*
 test_resp_async_echo.c
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
#include "mm.h"

#include <glib.h>
#include <stdio.h>

struct test_cmd
{
    RESPConnection *con;
    RESPCommand *cmd;
};

static int process_count = 10;
static int worker_count = 50;
static GThreadPool *worker_pool;

void echo(gpointer data, gpointer user_data)
{
    struct test_cmd *c = (struct test_cmd *)data;
    char **args = (char **)mm_malloc(sizeof(char *) * resp_cmd_get_args_count(cmd));
    for(int i = 0; i<resp_cmd_get_args_count(cmd); i++)
    {
        args[i] = resp_cmd_get_arg(c->cmd, i);
    }
    resp_reply_list(c->con, args, resp_cmd_get_arg_lens(c->cmd), resp_cmd_get_args_count(cmd));
    mm_free(args);
}

void async_echo(RESPConnection *con, RESPCommand *cmd)
{
    struct test_cmd *c = (struct test_cmd *)mm_malloc(sizeof(struct test_cmd));
    c->cmd = cmd;
    c->con = con;
    g_thread_pool_push (worker_pool, c, NULL);
}

int main(int argc, char **argv)
{
    char *cfg_path = NULL;
    if(argc > 1)
    {
        cfg_path = argv[1];
    }
    init_and_desc_test(cfg_path);
    
    worker_pool = g_thread_pool_new (echo, NULL, worker_count, true, NULL);
    RESPServer *srv = resp_new_server(1234, async_echo, process_count);
    resp_server_start(srv);
}
