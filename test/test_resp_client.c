/*
 test_resp_client.c
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
#include <hiredis.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

static char *server_ip = "127.0.0.1";
static int server_port = 1234;
static int thread_count = 1;
static GPtrArray *thread_arr;
static long op_per_thread = 10000;

static GRand *random;
static gint32 max_arg_count = 4;
static gint32 max_arg_len = 4;

char **rand_args(int arg_count, size_t **arg_lens)
{
    char **result = (char **)mm_malloc(arg_count * sizeof(char *));
    (*arg_lens) = (size_t *)mm_malloc(arg_count * sizeof(size_t));
    for(int i = 0; i< arg_count; i++)
    {
        (*arg_lens)[i] = g_rand_int_range(random, 1, max_arg_len);
        result[i] = (char *)mm_malloc((*arg_lens)[i]);
    }
    return result;
}

gpointer thread_loop(gpointer data)
{
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    redisContext *c = redisConnectWithTimeout(server_ip, server_port, timeout);
    if (c == NULL || c->err)
    {
        if (c)
        {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        }
        else
        {
            printf("Connection error: can't allocate redis context\n");
        }
        exit(1);
    }
    
    for(long i = 0; i<op_per_thread; i++)
    {
        gint32 arg_count = g_rand_int_range(random, 1, max_arg_count);
        size_t *arg_lens;
        char **args = rand_args(arg_count, &arg_lens);
        redisReply *reply = (redisReply *)redisCommandArgv(c, arg_count, (const char **)args, arg_lens);
        if(reply->type == REDIS_REPLY_ARRAY)
        {
            if(reply->elements == arg_count)
            {
                bool match = true;
                for(int j = 0; j<arg_count; j++)
                {
                    if((reply->element[j]->len == arg_lens[j]) && (memcmp(reply->element[j]->str, args[j], arg_lens[j]) == 0))
                    {

                    }
                    else
                    {
                        match = false;
                        printf("WRONG reply at [%d]\n", j);
                        break;
                    }
                }
                
                if(!match)
                {
                    break;
                }
                else
                {
                    printf("[%ld][%d] args req PASS\n",i, arg_count);
                }
                
            }
            else
            {
                printf("WRONG reply length: [%lu], arg_count [%d]\n",reply->elements,arg_count);

            }
        }
        else
        {
            printf("WRONG reply type: [%d]\n",reply->type);
            break;
        }
        
        mm_free(arg_lens);
        mm_free(args);
        arg_lens = NULL;
        args = NULL;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    random = g_rand_new ();
    thread_arr = g_ptr_array_new ();

    for(int i = 0; i< thread_count; i++)
    {
        GThread *t = g_thread_new ("loop", thread_loop, NULL);
        g_ptr_array_add (thread_arr, t);
    }
    
    for(int i = 0; i< thread_count; i++)
    {
        
        GThread *t = (GThread *)g_ptr_array_index(thread_arr, i);
        g_thread_join(t);
    }
}
