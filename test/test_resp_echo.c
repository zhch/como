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

static int port = 1234;
static int reader_count = 1;

void echo(RESPConnection *con, RESPCommand *cmd)
{
    char **args = (char **)mm_malloc(sizeof(char *) * resp_cmd_get_args_count(cmd));
    for(int i = 0; i<resp_cmd_get_args_count(cmd); i++)
    {
        printf("-------zc:echo arg[%d] len = [%lu]\n",i,resp_cmd_get_arg_lens(cmd)[i]);
        args[i] = resp_cmd_get_arg(cmd, i);
    }
    resp_reply_list(con, args, resp_cmd_get_arg_lens(cmd), resp_cmd_get_args_count(cmd));
    mm_free(args);
}

int main(int argc, char **argv)
{
    RESPServer *srv = resp_new_server(port, echo, reader_count);
    resp_server_start(srv);
}
