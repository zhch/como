/*
 test_resp_echo.c
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
#include "resp.h"
#include <stdio.h>
#include <glib.h>
#include <stdbool.h>

static int port = 1234;
static int reader_count = 2;

static void init_and_desc_test(char *cfg_path)
{
    if(cfg_path != NULL)
    {
        GKeyFile *cfg_file = g_key_file_new();
        gboolean ret = g_key_file_load_from_file (cfg_file, cfg_path, G_KEY_FILE_NONE, NULL);
        if(ret == false)
        {
            printf("try to load cfgs from [%s] failed",cfg_path);
            exit(0);
        }
        
        port = g_key_file_get_integer(cfg_file, "test_resp_echo", "port",NULL);
        reader_count = g_key_file_get_integer(cfg_file, "test_resp_echo", "reader",NULL);
        g_key_file_free(cfg_file);
    }
    
    printf("******* test_resp_echo STARTED ********\n");
    printf("         port: %d\n", port);
    printf(" reader_count: %d\n",reader_count);
    printf("******* ************************ ********\n");
}

void echo(RESPConnection *con, RESPCommand *cmd)
{
    char **args = (char **)mm_malloc(sizeof(char *) * resp_cmd_get_args_count(cmd));
    for(int i = 0; i<resp_cmd_get_args_count(cmd); i++)
    {
        args[i] = resp_cmd_get_arg(cmd, i);
    }
    resp_reply_list(con, args, resp_cmd_get_arg_lens(cmd), resp_cmd_get_args_count(cmd));
    mm_free(args);
}

int main(int argc, char **argv)
{
    char *cfg_path = NULL;
    if(argc > 1)
    {
        cfg_path = argv[1];
    }
    init_and_desc_test(cfg_path);
    
    RESPServer *srv = resp_new_server(port, echo, reader_count);
    resp_server_start(srv);
}
