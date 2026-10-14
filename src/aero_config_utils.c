/*
 * aero_config_utils.c
 *
 * Copyright 2026 The Boeing Company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include "jansson.h"
#include "aero.h"
#include <syslog.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include "aero_config_utils.h"

static char *config_file = "/etc/network/aerod.json";

const char *json_plural(size_t count)
{
    return count == 1 ? "" : "s";
}

void print_json_array(json_t *element, int inDent)
{
    size_t i;
    size_t size = json_array_size(element);
    print_json_indent(inDent);

    printf("JSON Array of %lld element%s:\n", (long long)size, json_plural(size));
    for (i = 0; i < size; i++)
    {
        DisplayConfiguration(json_array_get(element, i), inDent + 2);
    }
}

void print_json_string(json_t *element, int inDent)
{
    print_json_indent(inDent);
    printf("JSON String: \"%s\"\n", json_string_value(element));
}

void print_json_integer(json_t *element, int inDent)
{
    print_json_indent(inDent);
    printf("JSON Integer: \"%" JSON_INTEGER_FORMAT "\"\n", json_integer_value(element));
}

void print_json_real(json_t *element, int inDent)
{
    print_json_indent(inDent);
    printf("JSON Real: %f\n", json_real_value(element));
}

void print_json_true(json_t *element, int inDent)
{
    (void)element;
    print_json_indent(inDent);
    printf("JSON True\n");
}

void print_json_false(json_t *element, int inDent)
{
    (void)element;
    print_json_indent(inDent);
    printf("JSON False\n");
}

void print_json_null(json_t *element, int inDent)
{
    (void)element;
    print_json_indent(inDent);
    printf("JSON Null\n");
}

void print_json_object(json_t *element, int inDent)
{
    size_t size;
    const char *key;
    json_t *value;

    print_json_indent(inDent);
    size = json_object_size(element);

    printf("JSON Object of %lld pair%s:\n", (long long)size, json_plural(size));
    json_object_foreach(element, key, value)
    {
        print_json_indent(inDent + 2);
        printf("JSON Key: \"%s\"\n", key);
        DisplayConfiguration(value, inDent + 2);
    }
}

void print_json_indent(int inDent)
{
    int i;
    for (i = 0; i < inDent; i++)
    {
        putchar(' ');
    }
}

json_t *LoadConfiguration(const char *FileName)
{
    json_t *readPtr;
    json_error_t error;

    readPtr = json_load_file(FileName, 0, &error);
    if (!readPtr)
    {
        syslog(LOG_ERR, "Error loading configuration file on line %d: %s", error.line, error.text);
        fprintf(stderr, "json error on line %d: %s\n", error.line, error.text);
        return (json_t *)0;
    }
    else
        return readPtr;
}

json_t *loadInterfaceTrafficSelectors(const char *FileName, int nodetype, struct aero_interface *nodeLink)
{
    json_t *obj, *val1, *val2, *val3, *val4, *val5;
    json_error_t err;
    size_t index1, index2;
    const char *key1, *key2, *key3, *key4;
    /*allocate memory for the interface pointer*/
    nodeLink = malloc(sizeof(struct aero_interface));
    /*load configure file*/
    obj = json_load_file(FileName, 0, &err);
    if (json_is_object(obj))
    {
        printf("json configuration file read: %d elements\n", (int)json_object_size(obj));
    }
    else
    {
        printf("error in %s\n", FileName);
    }
    /*read and iterate over every configuration parameter*/
    json_object_foreach(obj, key1, val1)
    {
        /*reading nodetype (command line overrides config file)*/
        if ((!strcmp(key1, "nodeType")) && (nodetype == AERO_NODETYPE_NONE))
        {
            key2 = json_string_value(val1);
            printf("Found nodetype %s\n", key2);
            if (!strcmp(key2, "Client"))
            {
                nodetype = AERO_NODETYPE_CLIENT;
            }
            else if ((!strcmp(key2, "Proxy")) || (!strcmp(key2, "Server")) ||
                     (!strcmp(key2, "P/S")) || (!strcmp(key2, "Proxy/Server")))
            {
                nodetype = AERO_NODETYPE_PROXY;
            }
            else if (!strcmp(key2, "Gateway"))
            {
                nodetype = AERO_NODETYPE_GATEWAY;
            }
            else
            {
                printf("Nodetype unrecognized\n");
            }
        }
        /*if required get omniaddress,mnp,reachabletime and others here*/
        /*load interface values*/

        if (!strcmp(key1, "interface"))
        {
            printf("Found interface section in the configure file\n");
            json_array_foreach(val1, index1, val2)
            {
                /*reading interface name*/
                if ((val3 = json_object_get(val2, "name")))
                {
                    strncpy((char *)(nodeLink->name), (char *)(json_string_value(val3)), (IF_NAMESIZE - 1));
                    printf("Interface name : %s\n", nodeLink->name);
                }

                /*add interface type, interface provider and interface index*/
                if ((val3 = json_object_get(val2, "tsadv")))
                {
                    json_array_foreach(val3, index2, val4)
                    {
                        if ((val5 = json_object_get(val4, "tsFormat")))
                        {
                            key3 = json_string_value(val5);
                            printf("key3 : %s\n", key3);

                            /*IPv6 parameters for in traffic selectors*/
                            if (!strcmp(key3, "IPv6"))
                            {
                                if ((val5 = json_object_get(val4, "tsFlags")))
                                {
                                    printf("***********************ipv6 in tsadv***************************\n");
                                    key4 = json_string_value(val5);

                                    *(nodeLink->in_param.aero_ts.tsv6.tsFlags) = *key4;

                                    for (int i = 0; i < (TOTALFLAGS - 1); i++)
                                    {
                                        if (key4[i] == 'A')
                                        {
                                            val5 = json_object_get(val4, "startSrc");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSrc");
                                            memcpy(nodeLink->in_param.aero_ts.tsv6.startSrc, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                            
                                        }
                                        else if (key4[i] == 'B')
                                        {
                                            val5 = json_object_get(val4, "endSrc");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endSrc");
                                            
                                            memcpy(nodeLink->in_param.aero_ts.tsv6.endSrc, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                        }
                                        else if (key4[i] == 'C')
                                        {
                                            val5 = json_object_get(val4, "startDst");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDst");
                                            
                                            memcpy(nodeLink->in_param.aero_ts.tsv6.startDst, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                        }
                                        else if (key4[i] == 'D')
                                        {
                                            val5 = json_object_get(val4, "endDst");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDst");
                                            
                                            memcpy(nodeLink->in_param.aero_ts.tsv6.endDst, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                        }
                                        else if (key4[i] == 'E')
                                        {
                                            val5 = json_object_get(val4, "startIpsec");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startIpsec");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.startIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'F')
                                        {
                                            val5 = json_object_get(val4, "endIpsec");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endIpsec");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.endIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'G')
                                        {
                                            val5 = json_object_get(val4, "startFL");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startFL");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.startFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'H')
                                        {
                                            val5 = json_object_get(val4, "endFL");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endFL");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.endFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'I')
                                        {
                                            val5 = json_object_get(val4, "startSport");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSport");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.startSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'J')
                                        {
                                            val5 = json_object_get(val4, "endSport");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endSport");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.endSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'K')
                                        {
                                            val5 = json_object_get(val4, "startDs");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDs");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.startDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'L')
                                        {
                                            val5 = json_object_get(val4, "endDs");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDs");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.endDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'M')
                                        {
                                            val5 = json_object_get(val4, "startProt");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startProt");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.startProt = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'N')
                                        {
                                            val5 = json_object_get(val4, "endProt");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endProt");
                                            
                                            nodeLink->in_param.aero_ts.tsv6.endProt = json_integer_value(val5);
                                        }
                                        else
                                        {
                                            printf("flag not selected \n");
                                        }

                                    } /*for loop*/
                                } /*tsflags*/
                            }
                            else if (!strcmp(key3, "IPv4"))
                            {
                                printf("********************ipv4 in tsadv***************************\n");
                                if ((val5 = json_object_get(val4, "tsFlags")))
                                {
                                    key4 = json_string_value(val5);
                                    *(nodeLink->in_param.aero_ts.tsv4.tsFlags) = *key4;
                                    printf("flags in ipv4 :%s \n", key4);
                                    for (int i = 0; i < (TOTALFLAGS - 1); i++)
                                    {
                                        if (key4[i] == 'A')
                                        {
                                            val5 = json_object_get(val4, "startSrc");
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSrc");
                                            memcpy(nodeLink->in_param.aero_ts.tsv4.startSrc, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'B')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endSrc");
                                            val5 = json_object_get(val4, "endSrc");
                                            memcpy(nodeLink->in_param.aero_ts.tsv4.endSrc, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'C')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDst");
                                            val5 = json_object_get(val4, "startDst");
                                            memcpy(nodeLink->in_param.aero_ts.tsv4.startDst, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'D')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDst");
                                            val5 = json_object_get(val4, "endDst");
                                            memcpy(nodeLink->in_param.aero_ts.tsv4.endDst, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'E')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startIpsec");
                                            val5 = json_object_get(val4, "startIpsec");
                                            nodeLink->in_param.aero_ts.tsv4.startIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'F')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endIpsec");
                                            val5 = json_object_get(val4, "endIpsec");
                                            nodeLink->in_param.aero_ts.tsv4.endIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'G')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startFL");
                                            val5 = json_object_get(val4, "startFL");
                                            nodeLink->in_param.aero_ts.tsv4.startFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'H')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endFL");
                                            val5 = json_object_get(val4, "endFL");
                                            nodeLink->in_param.aero_ts.tsv4.endFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'I')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSport");
                                            val5 = json_object_get(val4, "startSport");
                                            nodeLink->in_param.aero_ts.tsv4.startSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'J')
                                        {
                                            val5 = json_object_get(val4, "endSport");
                                            nodeLink->in_param.aero_ts.tsv4.endSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'K')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDs");
                                            val5 = json_object_get(val4, "startDs");
                                            nodeLink->in_param.aero_ts.tsv4.startDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'L')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDs");
                                            val5 = json_object_get(val4, "endDs");
                                            nodeLink->in_param.aero_ts.tsv4.endDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'M')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startProt");
                                            val5 = json_object_get(val4, "startProt");
                                            nodeLink->in_param.aero_ts.tsv4.startProt = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'N')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endProt");
                                            val5 = json_object_get(val4, "endProt");
                                            nodeLink->in_param.aero_ts.tsv4.endProt = json_integer_value(val5);
                                        }
                                        else
                                        {
                                            printf("flag not selected \n");
                                        }
                                    } /*forloop*/
                                } /*tsflags*/
                            } /*ipv4*/
                        } /*tsformat*/
                    } /*json array foreach*/
                } /*tsadv*/
                if ((val3 = json_object_get(val2, "tsloc")))
                {
                    json_array_foreach(val3, index2, val4)
                    {
                        if ((val5 = json_object_get(val4, "tsFormat")))
                        {
                            key3 = json_string_value(val5);
                            printf("key3 : %s\n", key3);
                            if (!strcmp(key3, "IPv6"))
                            {
                                printf("***********ipv6 in tsloc************\n");
                                if ((val5 = json_object_get(val4, "tsFlags")))
                                {
                                    key4 = json_string_value(val5);
                                    *(nodeLink->out_param.aero_ts.tsv6.tsFlags) = *key4;
                                    for (int i = 0; i < (TOTALFLAGS - 1); i++)
                                    {
                                        if (key4[i] == 'A')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSrc");
                                            val5 = json_object_get(val4, "startSrc");
                                            memcpy(nodeLink->out_param.aero_ts.tsv6.startSrc, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                        }
                                        else if (key4[i] == 'B')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endSrc");
                                            val5 = json_object_get(val4, "endSrc");
                                            memcpy(nodeLink->out_param.aero_ts.tsv6.endSrc, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                        }
                                        else if (key4[i] == 'C')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDst");
                                            val5 = json_object_get(val4, "startDst");
                                            memcpy(nodeLink->out_param.aero_ts.tsv6.startDst, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                        }
                                        else if (key4[i] == 'D')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDst");
                                            val5 = json_object_get(val4, "endDst");
                                            memcpy(nodeLink->out_param.aero_ts.tsv6.endDst, (const void *)json_string_value(val5), sizeof(IPV6_ADDRLEN));
                                        }
                                        else if (key4[i] == 'E')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startIpsec");
                                            val5 = json_object_get(val4, "startIpsec");
                                            nodeLink->out_param.aero_ts.tsv6.startIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'F')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endIpsec");
                                            val5 = json_object_get(val4, "endIpsec");
                                            nodeLink->out_param.aero_ts.tsv6.endIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'G')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startFL");
                                            val5 = json_object_get(val4, "startFL");
                                            nodeLink->out_param.aero_ts.tsv6.startFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'H')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endFL");
                                            val5 = json_object_get(val4, "endFL");
                                            nodeLink->out_param.aero_ts.tsv6.endFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'I')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSport");
                                            val5 = json_object_get(val4, "startSport");
                                            nodeLink->out_param.aero_ts.tsv6.startSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'J')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endSport");
                                            val5 = json_object_get(val4, "endSport");
                                            nodeLink->out_param.aero_ts.tsv6.endSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'K')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDs");
                                            val5 = json_object_get(val4, "startDs");
                                            nodeLink->out_param.aero_ts.tsv6.startDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'L')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDs");
                                            val5 = json_object_get(val4, "endDs");
                                            nodeLink->out_param.aero_ts.tsv6.endDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'M')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startProt");
                                            val5 = json_object_get(val4, "startProt");
                                            nodeLink->out_param.aero_ts.tsv6.startProt = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'N')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endProt");
                                            val5 = json_object_get(val4, "endProt");
                                            nodeLink->out_param.aero_ts.tsv6.endProt = json_integer_value(val5);
                                        }
                                        else
                                        {
                                            printf("flag not selected \n");
                                        }
                                    } /*for loop*/
                                } /*tsflags*/
                            } /*ipv6*/
                            else if (!strcmp(key3, "IPv4"))
                            {
                                printf("***********ipv4 in tsloc************\n");
                                if ((val5 = json_object_get(val4, "tsFlags")))
                                {
                                    key4 = json_string_value(val5);
                                    *(nodeLink->out_param.aero_ts.tsv4.tsFlags) = *key4;
                                    for (int i = 0; i < (TOTALFLAGS - 1); i++)
                                    {
                                        if (key4[i] == 'A')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSrc");
                                            val5 = json_object_get(val4, "startSrc");
                                            memcpy(nodeLink->out_param.aero_ts.tsv4.startSrc, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'B')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endSrc");
                                            val5 = json_object_get(val4, "endSrc");
                                            memcpy(nodeLink->out_param.aero_ts.tsv4.endSrc, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'C')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDst");
                                            val5 = json_object_get(val4, "startDst");
                                            memcpy(nodeLink->out_param.aero_ts.tsv4.startDst, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'D')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDst");
                                            val5 = json_object_get(val4, "endDst");
                                            memcpy(nodeLink->out_param.aero_ts.tsv4.endDst, (const void *)json_string_value(val5), sizeof(IPV4_ADDRLEN));
                                        }
                                        else if (key4[i] == 'E')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startIpsec");
                                            val5 = json_object_get(val4, "startIpsec");
                                            nodeLink->out_param.aero_ts.tsv4.startIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'F')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endIpsec");
                                            val5 = json_object_get(val4, "endIpsec");
                                            nodeLink->out_param.aero_ts.tsv4.endIpsec = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'G')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startFL");
                                            val5 = json_object_get(val4, "startFL");
                                            nodeLink->out_param.aero_ts.tsv4.startFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'H')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endFL");
                                            val5 = json_object_get(val4, "endFL");
                                            nodeLink->out_param.aero_ts.tsv4.endFL = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'I')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startSport");
                                            val5 = json_object_get(val4, "startSport");
                                            nodeLink->out_param.aero_ts.tsv4.startSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'J')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endSport");
                                            val5 = json_object_get(val4, "endSport");
                                            nodeLink->out_param.aero_ts.tsv4.endSport = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'K')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startDs");
                                            val5 = json_object_get(val4, "startDs");
                                            nodeLink->out_param.aero_ts.tsv4.startDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'L')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endDs");
                                            val5 = json_object_get(val4, "endDs");
                                            nodeLink->out_param.aero_ts.tsv4.endDs = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'M')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "startProt");
                                            val5 = json_object_get(val4, "startProt");
                                            nodeLink->out_param.aero_ts.tsv4.startProt = json_integer_value(val5);
                                        }
                                        else if (key4[i] == 'N')
                                        {
                                            printf("Traffic Selector parameter for %c is %s \n", key4[i], "endProt");
                                            val5 = json_object_get(val4, "endProt");
                                            nodeLink->out_param.aero_ts.tsv4.endProt = json_integer_value(val5);
                                        }
                                        else
                                        {
                                            printf("flag not selected \n");
                                        }
                                    } /*for loop*/
                                } /*tsFlags*/
                            } /*ipv4/ipv6*/
                        } /*tsFormat*/
                    } /*json foreach obj3*/
                } /*tsadv/tsloc*/
            } /*json foreach obj2*/
        } /*strcmp interface*/
    } /*json foreach obj1*/

    return obj;

} /*function closure*/

void DisplayConfiguration(json_t *readConfig, int inDent)
{

    switch (json_typeof(readConfig))
    {
    case JSON_OBJECT:
        print_json_object(readConfig, inDent);
        break;
    case JSON_ARRAY:
        print_json_array(readConfig, inDent);
        break;
    case JSON_STRING:
        print_json_string(readConfig, inDent);
        break;
    case JSON_INTEGER:
        print_json_integer(readConfig, inDent);
        break;
    case JSON_REAL:
        print_json_real(readConfig, inDent);
        break;
    case JSON_TRUE:
        print_json_true(readConfig, inDent);
        break;
    case JSON_FALSE:
        print_json_false(readConfig, inDent);
        break;
    case JSON_NULL:
        print_json_null(readConfig, inDent);
        break;
    default:
    {
        fprintf(stderr, "unrecognized JSON type %d\n", json_typeof(readConfig));
        syslog(LOG_ERR, "unrecognized JSON type %d\n", json_typeof(readConfig));
    }
    }
}

/**
 * @brief Initialize the interface local cache
 *
 * This function initializes the interface local cache with an initial capacity
 * of `initialCapacity` and a size of 0.
 *
 * @param cache Pointer to the interface local cache to be initialized
 * @param initialCapacity The initial capacity of the cache
 *
 * @throws None
 */

void initinterfaceLocalCache(interfaceLocalCache *cache, size_t initialCapacity)
{
    cache->entries = malloc(initialCapacity * sizeof(aeroInterfaceInfo));
    if (cache->entries == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for local cache\n");
        exit(EXIT_FAILURE);
    }
    cache->size = 0;
    cache->capacity = initialCapacity;
}

/**
 * @brief Function to initialize and append to the interface local cache
 *
 * This function initializes the interface local cache with an initial capacity
 * of `initialCapacity` and a size of 0.
 *
 * @param cache Pointer to the interface local cache to be initialized
 * @param ifIndex The interface index
 * @param ifName The interface name
 *
 * @throws None
 *
 * @details
 * 1. If the size of cache is equal to the capacity, it doubles the capacity.
 * 2. It checks if the reallocation of memory was successful. If it is not, it prints an error message and exits the program.
 * 3. It adds the new entry to the cache.
 */
void appendToCache(interfaceLocalCache *cache, int ifIndex, const char *ifName)
{

    if (cache->size == cache->capacity)
    {
        size_t newCapacity = cache->capacity * 2;
        aeroInterfaceInfo *newEntries = realloc(cache->entries, newCapacity * sizeof(aeroInterfaceInfo));
        if (newEntries == NULL)
        {
            fprintf(stderr, "Failed to reallocate memory for local cache\n");
            exit(EXIT_FAILURE);
        }
        cache->entries = newEntries;
        cache->capacity = newCapacity;
    }

    /* Add the new entry */
    cache->entries[cache->size].ifIndex = ifIndex;
    cache->entries[cache->size].ifName = strdup(ifName);
    cache->size++;
}

/* Function to free the local cache */
void freeLocalCache(interfaceLocalCache *cache)
{
    for (size_t i = 0; i < cache->size; i++)
    {
        free(cache->entries[i].ifName);
    }
    free(cache->entries);
    cache->entries = NULL;
    cache->size = 0;
    cache->capacity = 0;
}

/** Load a JSON file into a JSON object. */
json_t *loadConfigFile(char *config_file)
{
    json_error_t error;
    json_t *rootConf = json_load_file(config_file, 0, &error);
    if (rootConf == NULL)
    {
        printf("Error loading JSON file: %s\n", error.text);
        return NULL;
    }
    else
    {
        syslog(LOG_INFO, "JSON file loaded successfully\n");
    }
    return rootConf;
}

/**
 * Create a new interface from a JSON object.
 *
 * @param json The JSON object containing the interface details.
 * @return A pointer to a newly allocated Interface struct.
 * @throws None
 */
aeroNodeInterface *createInterface(json_t *json, json_t *rootJson)
{
    interfaceLocalCache ifCache;
    initinterfaceLocalCache(&ifCache, 10);
    aeroNodeInterface *interface = malloc(sizeof(aeroNodeInterface));
    if (interface == NULL) 
    {
        fprintf(stderr, "Memory allocation failed for interface\n");
        return NULL; 
    }
    interface->ifName = json_string_value(json_object_get(json, "ifName"));
    uint8_t ifIndex = if_nametoindex(interface->ifName);
    syslog(LOG_INFO, "Interface name %s has Interface index of %d\n", interface->ifName, ifIndex);
    appendToCache(&ifCache, ifIndex, interface->ifName);
    interface->ifType = json_string_value(json_object_get(json, "ifType"));
    interface->ifProvider = json_string_value(json_object_get(json, "ifProvider"));
    interface->ifMetric = json_string_value(json_object_get(json, "ifMetric"));
    interface->ifGroup = json_string_value(json_object_get(json, "ifGroup"));
    interface->nodeType = json_string_value(json_object_get(rootJson, "nodeType"));
    if (interface->nodeType == NULL) 
    {
        fprintf(stderr, "nodeType not found in JSON\n");
    }
    interface->MNP = json_string_value(json_object_get(rootJson, "MNP"));
    if (interface->MNP == NULL) 
    {
        fprintf(stderr, "MNP not found in JSON\n");
    }
    interface->ReachableTime = json_integer_value(json_object_get(rootJson, "ReachableTime"));
    interface->DepartTime = json_integer_value(json_object_get(rootJson, "DepartTime"));
    const char *omniAddressStr = json_string_value(json_object_get(rootJson, "omniAddress"));
    if (omniAddressStr == NULL)
     {
        fprintf(stderr, "Error: omniAddress not found or is not a string\n");
        free(interface);
        return NULL; 
     }
    if (inet_pton(AF_INET6, omniAddressStr, &interface->omniAddress) != 1) 
    {
        fprintf(stderr, "Invalid IPv6 address: %s\n", omniAddressStr);
        free(interface);
        return NULL; 
    }
    json_t *prlv4 = json_object_get(json, "prlv4");
    size_t prlv4_size = json_array_size(prlv4);
    interface->prlv4 = malloc((prlv4_size + 1) * sizeof(char *));
    for (size_t i = 0; i < prlv4_size; i++)
    {
        interface->prlv4[i] = json_string_value(json_array_get(prlv4, i));
    }
    interface->prlv4[prlv4_size] = NULL;

    json_t *prlv6 = json_object_get(json, "prlv6");
    size_t prlv6_size = json_array_size(prlv6);
    interface->prlv6 = malloc((prlv6_size + 1) * sizeof(char *));
    for (size_t i = 0; i < prlv6_size; i++)
    {
        interface->prlv6[i] = json_string_value(json_array_get(prlv6, i));
    }
    interface->prlv6[prlv6_size] = NULL;

    interface->tsadv = json_object_get(json, "tsadv");
    interface->tsloc = json_object_get(json, "tsloc");

    freeLocalCache(&ifCache);

    return interface;
}

/**
 * Frees the memory allocated for an aeroNodeInterface struct.
 *
 * @param interface The interface to free.
 */
void destroyInterface(aeroNodeInterface *interface)
{
    /* Free the dynamically allocated prlv4 and prlv6 arrays */
    free(interface->prlv4);
    free(interface->prlv6);

    /* Free the aeroNodeInterface struct itself */
    free(interface);
}

/**
 * Creates a new parameter list.
 *
 * This function allocates memory for a new aeroParamList struct and initializes
 * its head and tail pointers to NULL, indicating that the list is empty.
 *
 * @return A pointer to the newly created aeroParamList struct.
 */
aeroParamList *createParamList()
{
    /* Allocate memory for a new aeroParamList struct */
    aeroParamList *list = malloc(sizeof(aeroParamList));

    /* Initialize the head and tail pointers to NULL */
    list->head = NULL;
    list->tail = NULL;

    /* Return the newly created aeroParamList struct */
    return list;
}

/**
 * Appends a new node containing the given interface to the end of the
 * provided list.
 *
 * @param list The list to append the node to.
 * @param interface The interface to append.
 */
void appendToList(aeroParamList *list, aeroNodeInterface *interface)
{
    /* Allocate memory for a new aeroNode */
    aeroNode *newNode = malloc(sizeof(aeroNode));
    newNode->data = interface;
    newNode->next = NULL;
    if (list->head == NULL)
    {
        list->head = newNode;
        list->tail = newNode;
    }
    else
    {
        list->tail->next = newNode;
        list->tail = newNode;
    }
}

/**
 * Destroys a parameter list, freeing all resources associated with it.
 *
 * @param list The list to be destroyed.
 */
void destroyParamList(aeroParamList *list)
{
    /* Initialize a pointer to the current node */
    aeroNode *current = list->head;
    /* Traverse the list and free each node */
    while (current != NULL)
    {
        aeroNode *next = current->next;
        destroyInterface(current->data);
        free(current);
        current = next;
    }
    free(list);
}

/**
 * Parses a JSON array and appends the parsed interfaces to a parameter list.
 *
 * @param jsonArr The JSON array to parse.
 * @param list    The parameter list to append the interfaces to.
 */
void parseJSON(json_t *jsonArr, aeroParamList *list, json_t *rootJson)
{
    /* Check if the JSON array is valid */
    if (json_is_array(jsonArr))
    {
        size_t size = json_array_size(jsonArr);
        for (size_t i = 0; i < size; i++)
        {
            json_t *element = json_array_get(jsonArr, i);
            aeroNodeInterface *interface = createInterface(element,rootJson);
            appendToList(list, interface);
        }
    }
}

/**
 * Prints the details of a given interface to the system log.
 *
 * @param interface The interface to print details of.
 */
void printInterface(aeroNodeInterface *interface)
{
    char omniAddressStr[INET6_ADDRSTRLEN];
    syslog(LOG_INFO, "Interface Name: %s", interface->ifName);
    syslog(LOG_INFO, "Interface Type: %s", interface->ifType);
    syslog(LOG_INFO, "Interface Provider: %s", interface->ifProvider);
    syslog(LOG_INFO, "Interface Metric: %s", interface->ifMetric);
    syslog(LOG_INFO, "Interface Group: %s", interface->ifGroup);
    syslog(LOG_INFO, "Node Type: %s", interface->nodeType);
    if (inet_ntop(AF_INET6, &interface->omniAddress, omniAddressStr, sizeof(omniAddressStr)) != NULL) 
    {
        syslog(LOG_INFO, "Omni Address: %s", omniAddressStr);
    } else 
    {
        syslog(LOG_ERR, "Failed to convert omniAddress to string");
    }
    syslog(LOG_INFO, "MNP: %s", interface->MNP);
    syslog(LOG_INFO, "Reachable Time: %d", interface->ReachableTime);
    syslog(LOG_INFO, "Depart Time: %d", interface->DepartTime);
    syslog(LOG_INFO, "PRLv4 Addresses:");
    for (size_t i = 0; interface->prlv4[i] != NULL; i++)
    {
        syslog(LOG_INFO, "%s", interface->prlv4[i]);
    }

    syslog(LOG_INFO, "PRLv6 Addresses:");
    for (size_t i = 0; interface->prlv6[i] != NULL; i++)
    {
        syslog(LOG_INFO, "%s", interface->prlv6[i]);
    }

    syslog(LOG_INFO, "tsadv:");
    json_dumpf(interface->tsadv, stdout, JSON_INDENT(2));

    syslog(LOG_INFO, "tsloc:");
    json_dumpf(interface->tsloc, stdout, JSON_INDENT(2));

    syslog(LOG_INFO, "\n");

    syslog(LOG_INFO, "\n");
}

/**
 * Reloads the configuration file and prints the details of each interface.
 *
 * This function performs the following steps:
 * 1. Loads the configuration file.
 * 2. Creates a parameter list.
 * 3. Retrieves the "interface" JSON array from the configuration.
 * 4. Parses the JSON array and appends the interfaces to the parameter list.
 * 5. Prints the details of each interface.
 * 6. Destroys the parameter list.
 * 7. Decrements the reference count of the configuration JSON object.
 */
void reloadConfigFile()
{
    json_t *reloadConf = loadConfigFile(config_file);
    aeroParamList *reloadList = createParamList();
    json_t *interfaceArray = json_object_get(reloadConf, "interface");
    parseJSON(interfaceArray, reloadList, reloadConf);
    aeroNode *current = reloadList->head;

    while (current != NULL)
    {
        aeroNodeInterface *interface = current->data;
        printInterface(interface);
        current = current->next;
    }

    /* Destroy the parameter list */ 
    /*destroyParamList(reloadList);*/

    /* Decrement the reference count of the configuration JSON object */ 
    json_decref(reloadConf);
}
