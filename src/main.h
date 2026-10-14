/*
 * main.h       main
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

#ifndef _MAIN_H_INCLUDED_
#define _MAIN_H_INCLUDED_

/**
 * 0  base verbosity
 * >0 more verbose
 * <0 less verbose
 **/
extern int verbose;

extern int nodetype;
extern int json_fd;
extern int omni_fd;
extern int udp4_fd;
extern int udp6_fd;
extern int ip4_fd;
extern int ip6_fd;
extern int eth_fd;
extern int rtnl_fd;
extern struct in6_addr omni_null;
extern struct in6_addr omni_mla;
extern struct in6_addr omni_gua;
extern struct in6_addr omni_arm;
extern struct in6_addr omni_ads;
extern struct in6_addr omni_adras;
extern struct in6_addr omni_snm;
extern struct in6_addr omni_any;
extern struct sockaddr_in omni_rv4;
extern struct sockaddr_in6 omni_rv6;
extern char *iot_ifname;
#ifdef AERO_DPDK
extern struct rte_mempool *mp;
extern struct rte_ip_frag_tbl *frag_tbl;
extern struct rte_ip_frag_death_row *death_row;
#endif

/* Protocol Constants */
#define DHCPV6_CLIENT_PORT	546
#define DHCPV6_SERVER_PORT	547
#endif
