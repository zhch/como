/*
 como.c
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

#include <glib.h>
#include <ev.h>

#include "como.h"
#include "log.h"
#include "mm.h"
#include "resp.h"

void cmd_proc(RESPConnection *con, RESPCommand *cmd)
{
    printf("--------zc:cmd of [%lu] args processed\n", resp_cmd_get_args_count(cmd));
    resp_reply_list(con, resp_cmd_get_args(cmd), resp_cmd_get_arg_lens(cmd), resp_cmd_get_args_count(cmd));
}

int main(int argc, char **argv)
{
    log_info("hello como\n");
    log_info("glib version [%d.%d.%d]\n",GLIB_MAJOR_VERSION,GLIB_MINOR_VERSION,GLIB_MICRO_VERSION);
    log_info("libev version [%d.%d]\n",ev_version_major (), ev_version_minor ());
    
    RESPServer *srv = resp_new_server(1234, cmd_proc, 1);
    log_debug("resp_new_server done\n");
    
    log_debug("resp server started\n");
    resp_server_start(srv);
    log_debug("resp server exit\n");

    return 0;
}
