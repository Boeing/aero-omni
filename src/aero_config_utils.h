/*
 * aero_config_utils.h
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

#ifndef _AERO_CONFIG_UTILS_H_INCLUDED_
#define _AERO_CONFIG_UTILS_H_INCLUDED_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <net/if.h>
#include "jansson.h"
/* #include "aero.h" */
#define NodeType "nodetype"
#define NODE_TYPE_SIZE 20
#define IP_TYPE 10
#define TOTALFLAGS 14
#define IPV6_ADDRLEN 20
#define IPV4_ADDRLEN 8

struct aero_v6_params
{
    char tsFormat[IP_TYPE];
    char tsFlags[TOTALFLAGS];
    char startSrc[IPV6_ADDRLEN];
    char endSrc[IPV6_ADDRLEN];
    char startDst[IPV6_ADDRLEN];
    char endDst[IPV6_ADDRLEN];
    json_int_t startIpsec;
    json_int_t endIpsec;
    json_int_t startFL;
    json_int_t endFL;
    json_int_t startSport;
    json_int_t endSport;
    json_int_t startDs;
    json_int_t endDs;
    json_int_t startProt;
    json_int_t endProt;
};

struct aero_v4_params
{
    char tsFormat[IP_TYPE];
    char tsFlags[TOTALFLAGS];
    char startSrc[IPV4_ADDRLEN];
    char endSrc[IPV4_ADDRLEN];
    char startDst[IPV4_ADDRLEN];
    char endDst[IPV4_ADDRLEN];
    json_int_t startIpsec;
    json_int_t endIpsec;
    json_int_t startFL;
    json_int_t endFL;
    json_int_t startSport;
    json_int_t endSport;
    json_int_t startDs;
    json_int_t endDs;
    json_int_t startProt;
    json_int_t endProt;
};

struct aero_traffic_selector
{
    union
    {
        struct aero_v6_params tsv6;
        struct aero_v4_params tsv4;
    } aero_ts;
};

struct aero_interface
{
    char name[IF_NAMESIZE];
    /*add interface index, interface type,interface provider*/
    struct aero_traffic_selector in_param;
    struct aero_traffic_selector out_param;
};

/** @brief Display if count is singular or plural
 * @param[in] count variable which contains the value of count
 * @param[out] const char " " if count = 1
 *                        "s"    count != 1
 * @return Void.
 */
const char *json_plural(size_t count);

/** @brief Display Json array
 * @param[in] element json pointer to string
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_array(json_t *element, int inDent);

/** @brief Display Json string
 * @param[in] element json pointer to string
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_string(json_t *element, int inDent);

/** @brief Display Json integer
 * @param[in] element json pointer to integer
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_integer(json_t *element, int inDent);

/** @brief Display Json real number
 * @param[in] element json pointer to real number
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_real(json_t *element, int inDent);

/** @brief Display Json True boolean value
 * @param[in] element json pointer to true
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_true(json_t *element, int inDent);

/** @brief Display Json False boolean value
 * @param[in] element json pointer to false
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_false(json_t *element, int inDent);

/** @brief Display Json NULL value
 * @param[in] element json pointer to NULL value
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_null(json_t *element, int inDent);

/** @brief Display Json object
 * @param[in] element json pointer to object
 * @param[in] inDent indentation value
 * @return Void.
 */
void print_json_object(json_t *element, int inDent);

/** @brief Display Json indentation
 * @param[in] inDent json pointer to indentation value
 * @return Void.
 */
void print_json_indent(int inDent);

/** @brief Display Json indentation
 * @param[in] Filename Pointer to configuration file
 * @param[out] json pointer to the read configuration file
 * @return Void.
 */
json_t *LoadConfiguration(const char *FileName);

/** @brief Display configuration file
 * @param[in] readConfig json pointer to read configuration file
 * @param[in] inDent indentation for displaying json contents
 * @return Void.
 */
void DisplayConfiguration(json_t *readConfig, int inDent);

/** @brief Load configurations from the configure file
 * @param[in] Filename Pointer to configuration file
 * @param[in] nodetype corresponding interger for the node type
 * @param[in] interface structure loaded with all the values in the configuration file
 * @return json_t
 * */
json_t *loadInterfaceTrafficSelectors(const char *FileName, int nodetype, struct aero_interface *);

/**
 * @struct aeroNodeInterface
 * @brief Struct representing the interface configuration
 *
 * This structure holds the details of an interface configuration.
 * Each field represents a different parameter of the interface.
 */
typedef struct
{
    const char *ifName;
    const char *ifType;
    const char *ifProvider;
    const char *ifMetric;
    const char *ifGroup;
    const char **prlv4;
    const char **prlv6;
    json_t *tsadv;
    json_t *tsloc;
    const char *nodeType;
    struct in6_addr omniAddress;
    const char *MNP;
    int ReachableTime;
    int DepartTime;
} aeroNodeInterface;

/**
 * @struct aeroNode
 * @brief Struct representing a node in the linked list of interface configurations
 *
 * This structure represents a node in a linked list that holds
 * interface configurations. Each node contains a pointer to an
 * aeroNodeInterface struct, which holds the details of an interface
 * configuration, and a pointer to the next node in the list.
 */
typedef struct aeroNode
{
    aeroNodeInterface *data;
    struct aeroNode *next;
} aeroNode;

/**
 * @struct aeroParamList
 * @brief Struct representing the linked list of interface configurations
 *
 * This structure represents a linked list of interface configurations.
 * Each node in the list contains a pointer to an aeroNode struct,
 * which contains the details of an interface configuration.
 */
typedef struct
{
    aeroNode *head;
    aeroNode *tail;
} aeroParamList;

/** @brief Create a linked list of interface configurations from a JSON object */
aeroParamList *createParamList();

/** @brief Destroy a linked list of interface configurations */
void destroyParamList(aeroParamList *list);

/** @brief Add an interface configuration to the linked list */
void appendToList(aeroParamList *list, aeroNodeInterface *interface);

/** @brief Parse a JSON object and create a linked list of interface configurations */
void parseJSON(json_t *json, aeroParamList *list, json_t *rootJson);

/** @brief Display a linked list of interface configurations */
void printInterface(aeroNodeInterface *interface);

/** @brief Destroy an interface configuration */
void destroyInterface(aeroNodeInterface *interface);

/** @brief Create an interface configuration from a JSON object */
aeroNodeInterface *createInterface(json_t *json, json_t *rootJson);

/** @brief Load configurations from the configuration file */
json_t *loadConfigFile(char *config_file);

/** @brief Reload configurations from the configuration file */
void reloadConfigFile();

/* Define a struct to hold ifIndex and ifName */
typedef struct
{
    int ifIndex;
    char *ifName;
} aeroInterfaceInfo;

/* Define a struct for the cache */
typedef struct
{
    aeroInterfaceInfo *entries;
    size_t size;
    size_t capacity;
} interfaceLocalCache;

/* Define a function to initialize the cache */
void initinterfaceLocalCache(interfaceLocalCache *cache, size_t initialCapacity);

/* Define a function to append to the cache */
void appendToCache(interfaceLocalCache *cache, int ifIndex, const char *ifName);

/* Define a function to free the cache */
void freeLocalCache(interfaceLocalCache *cache);
#endif
