/*
 * aero.h     Main loop for processing all control and data plane messages
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

#ifndef _AERO_H_INCLUDED_
#define _AERO_H_INCLUDED_

/* needed to make sendmmsg() work */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <bits/endian.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include "aero_config_utils.h"

#ifdef AERO_DPDK
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#ifdef AERO_NOTYET
#include "ip_frag/rte_ip_frag.h"
#else
#include <rte_ip_frag.h>
#endif

void aero_pre_system_init();
int rte_init_mem(void);
int aero_eal_init();
int initialise_eal(int omnic, char **omniv);
#endif /* AERO_DPDK */

#define AERO_NODETYPE_NONE 0
#define AERO_NODETYPE_CLIENT 1
#define AERO_NODETYPE_PROXY 2
#define AERO_NODETYPE_GATEWAY 3
#define AERO_JSON 1

#pragma pack (push,1)

/* OMNI Option Structures */

/* OMNI Sub-Option headers */
struct omniSubHdr {
    uint8_t subType;
    uint8_t subLen;
};

struct omniSubOpt {
    struct omniSubHdr subHdr;	/* Sub-Option Type/Len */
    uint8_t subData[0];		/* Sub-Option Data (variable) */
};

/* OMNI Option trailer */
struct omniTrail {
    uint8_t omniLen;
    uint8_t authOffset;
    uint16_t omniChk;
};

/* OMNI Sub-Option Types */
#define OMNI_SUBOPT_NULL	0
#define OMNI_SUBOPT_CGA		1
#define OMNI_SUBOPT_AUTH	2
#define OMNI_SUBOPT_TIME	3
#define OMNI_SUBOPT_NONCE	4
#define OMNI_SUBOPT_TRUST	5
#define OMNI_SUBOPT_CERT	6
#define OMNI_SUBOPT_HMAC	7
#define OMNI_SUBOPT_NODEID	8
#define OMNI_SUBOPT_NSYNC	9
#define OMNI_SUBOPT_IFATTR	10
#define OMNI_SUBOPT_TSEL	11
#define OMNI_SUBOPT_GEO		12
#define OMNI_SUBOPT_PIM		13
#define OMNI_SUBOPT_FRAGREP	14
#define OMNI_SUBOPT_PSCTL	15
#define OMNI_SUBOPT_PIO		16
#define OMNI_SUBOPT_RIO		17
#define OMNI_SUBOPT_DHCPv6	18

/* 0 */
struct omniNull {
    struct omniSubHdr null;
    uint8_t pad[0];
};

/* 1 */
struct omniCGA {
    struct omniSubHdr cga;
    uint8_t padLen;
    uint8_t res1;
    uint8_t cgaParams[0];
};

/* 2 */
struct omniRSA {
    struct omniSubHdr rsa;
    uint16_t res1;
    uint8_t keyHash[16];
    uint8_t signature[0];
};

/* 3 */
struct omniTimeStamp {
    struct omniSubHdr ts;
    uint8_t res1[6];
    uint8_t timeStamp[8];
};

/* 4 */
struct omniNonce {
    struct omniSubHdr non;
    uint8_t nonce[0];
};

/* 5 */
struct omniTrust {
    struct omniSubHdr trust;
    uint8_t nameType;
    uint8_t padLen;
    uint8_t anchorBody[0];
};
#define OMNI_TRUST_DER		1
#define OMNI_TRUST_FQDN		2

/* 6 */
struct omniCert {
    struct omniSubHdr cert;
    uint8_t certType;
    uint8_t res1;
    uint8_t certBody[0];
};
#define OMNI_CERT_X509v3	1

/* 7 */
struct omniHmac {
    struct omniSubHdr hm;
    unsigned int D:1;
    unsigned int res1:15;
    uint32_t keyId;
    uint8_t hmac[0];
};

/* 8 */
struct omniNodeID {
    struct omniSubHdr nid;
    uint8_t padLen;
    uint8_t idType;
    union {
	struct in6_addr nid_un_mla;
	uint8_t nid_un_uuid[16];
	uint8_t nid_un_nai[0];
	uint8_t nid_un_fqdn[0];
	struct in_addr nid_un_ipv4;
	struct in6_addr nid_un_ipv6;
    } nodeId_un;
};
#define OMNI_NIDTYPE_MLA	0
#define OMNI_NIDTYPE_UUID	1
#define OMNI_NIDTYPE_NAI	2
#define OMNI_NIDTYPE_FQDN	3
#define OMNI_NIDTYPE_IPV4	4
#define OMNI_NIDTYPE_RID	5
#define OMNI_NIDTYPE_IPV6	6

#define nid_mla		nodeId_un.nid_un_mla
#define nid_uuid	nodeId_un.nid_un_uuid
#define nid_nai		nodeId_un.nid_un_nai
#define nid_fqdn	nodeId_un.nid_un_fqdn
#define nid_ipv4	nodeId_un.nid_un_ipv4
#define nid_ipv6	nodeId_un.nid_un_ipv6

/* 9 */
struct omniNsync {
    struct omniSubHdr nsync;
    unsigned int O:1;
    unsigned int P:1;
    unsigned int res1:14;
    uint32_t fhs_ifIndex;
    uint32_t lhs_ifIndex;
    unsigned int scale:4;
    unsigned int res2:4;
    unsigned int flags:8;
    unsigned int window:16;
    uint8_t seqNum[8];
    uint8_t ackNum[8];
};
#define OMNI_NSYNC_CWR	0x80
#define OMNI_NSYNC_ECE	0x40
#define OMNI_NSYNC_URG	0x20
#define OMNI_NSYNC_ACK	0x10
#define OMNI_NSYNC_PSH	0x08
#define OMNI_NSYNC_RST	0x04
#define OMNI_NSYNC_SYN	0x02
#define OMNI_NSYNC_FIN	0x01

/* 10 */
struct omniIfAttr {
    struct omniSubHdr ifa;
    uint8_t srt;
    uint8_t fmt;
    uint32_t ifIndex;
    uint32_t ifType;
    uint32_t ifProvider;
    uint32_t ifMetric;
    uint32_t ifGroup;
    struct in6_addr lhs_mla;
    union {
	uint8_t unx_null[0];
	uint8_t unx_eui48[6];
	uint8_t unx_eui64[8];
	struct in_addr unx_ipv4;
	struct in6_addr unx_ipv6;
	struct {
	    struct in_addr addr;
	    uint16_t port;
	} unx_v4udp;
	struct {
	    struct in6_addr addr;
	    uint16_t port;
	} unx_v6udp;
    } unx_un;
};
#define OMNI_FMT_F	0x80
#define OMNI_FMT_M	0x40
#define OMNI_FMT_T	0x20
#define OMNI_FMT_UNSPEC	0x00
#define OMNI_FMT_MANET	0x01
#define OMNI_FMT_EUI48	0x02
#define OMNI_FMT_EUI64	0x03
#define OMNI_FMT_IPV4	0x04
#define OMNI_FMT_IPV6	0x06
#define OMNI_FMT_UDPV4	0x07
#define OMNI_FMT_UDPV6	0x08

#define lhs_unx_null	unx_un.unx_null
#define lhs_unx_eui48	unx_un.unx_eui48
#define lhs_unx_eui64	unx_un.unx_eui64
#define lhs_unx_ipv4	unx_un.unx_ipv4
#define lhs_unx_ipv6	unx_un.unx_ipv6
#define lhs_unx_v4udp	unx_un.unx_v4udp
#define lhs_unx_v6udp	unx_un.unx_v6udp

/* 11 */
struct omniTsel {
    struct omniSubHdr tsel;
    uint8_t fmt;
    uint8_t padLen;
    uint32_t ifIndex;
    uint16_t bits;
    uint16_t res1;
    uint8_t data[0];
};
#define OMNI_TSEL_A	0x8000
#define OMNI_TSEL_B	0x4000
#define OMNI_TSEL_C	0x2000
#define OMNI_TSEL_D	0x1000
#define OMNI_TSEL_E	0x0800
#define OMNI_TSEL_F	0x0400
#define OMNI_TSEL_G	0x0200
#define OMNI_TSEL_H	0x0100
#define OMNI_TSEL_I	0x0080
#define OMNI_TSEL_J	0x0040
#define OMNI_TSEL_K	0x0020
#define OMNI_TSEL_L	0x0010
#define OMNI_TSEL_M	0x0008
#define OMNI_TSEL_N	0x0004

/* 12 */
struct omniGeo {
    struct omniSubHdr geo;
    uint8_t padLen;
    uint8_t type;
    uint8_t coord[0];
};
#define OMNI_GEO_NULL	0

/* 13 */
struct omniPimSm {
    struct omniSubHdr pim;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int type:4;
    unsigned int vers:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int vers:4;
    unsigned int type:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    uint8_t padLen;
    uint8_t msg[0];
};

/* 14 */
struct omniFragRep {
    struct omniSubHdr frag;
    uint16_t fpLen;
    unsigned int flowLabel:20;
    unsigned int L:1;
    unsigned int P:1;
    unsigned int MRU:10;
    uint8_t ident[8];
    uint8_t bitmap[8];
};

/* 15 */
struct omniPSCtl {
    struct omniSubHdr psctl;
    unsigned int M:1;
    unsigned int P:1;
    unsigned int N:1;
    unsigned int A:1;
    unsigned int R:1;
    unsigned int C:1;
    unsigned int res1:10;
    uint32_t res2;
    struct in6_addr mla;
};

/* 16 */
struct omniPIO {
    struct omniSubHdr pio;
    uint8_t prefLen;
    unsigned int L:1;
    unsigned int A:1;
    unsigned int R:1;
    unsigned int P:1;
    unsigned int res1:4;
    uint32_t valid;
    uint32_t preferred;
    uint32_t res2;
    uint8_t prefix[0];
};

/* 17 */
struct omniRIO {
    struct omniSubHdr rio;
    uint8_t prefLen;
    unsigned int res1:3;
    unsigned int prf:2;
    unsigned int res2:3;
    uint32_t lifetime;
    uint8_t prefix[0];
};

/* 18 */
struct omniDHCPv6 {
    struct omniSubHdr dhc;
    uint8_t padLen;
    uint8_t res1;
    uint8_t msgType;
    uint8_t transID[3];
    uint8_t opts[0];
};

/* Segment Routing Header (RFC8754) */
struct omniSRH {
    struct ip6_rthdr rh;
    uint8_t lastEnt;
    uint8_t flags;
    uint16_t tag;
    /* followed by 0 or more SIDs */
    struct in6_addr sid[0];
};

struct omniSRHtrail {
    uint8_t tlvObj[0];
};
#define OMNI_SRH_TYPE	4

#pragma pack (pop)

/* Pending DHCPv6; RA */
struct aeroPendDHC {
    struct rte_mbuf *m;
    void *base;
    uint16_t l;
};

struct aeroPendRA {
    struct rte_mbuf *m;
    struct aeroPendDHC dh1;
    struct ip6_hdr *om6;
    struct ip6_hdr *ip6;
    struct timeval rcv;
    void *base;
    int sid;
};

struct aeroPendRS {
    struct rte_mbuf *m;
    struct ip6_hdr *om6;
    struct timeval sent;
    int sid;
};

/*
 * AERO Neighbor Cache entry. Each cache entry is on three lists - one
 * keyed on MLA, another keyed on MAC address and a third keyed on a
 * monotonically-increasing index value. Lookup is based on the least
 * significant octet of the key, and is used to determine a list bucket
 * which may include multiple entries.
 */
struct aeroNCE {
    uint8_t state;
    struct aeroNCE *nextMLA;
    struct aeroNCE *prevMLA;
    struct aeroNCE *nextIND;
    struct aeroNCE *prevIND;
    struct in6_addr ip6_nbr;
    struct in6_addr ip6_mla;
    struct in6_addr ip6_gua;
    struct sockaddr_in lldst;
    uint8_t eth_addr[ETH_ALEN];
    struct omniIfAttr *ifa[10];
    struct aeroPendRA ra;
    uint32_t ident;
    uint32_t index;
    uint32_t mfs;
    uint32_t isClient;
    uint32_t manet;
};

/*
 * AERO Potential Router List. The key is based on the mod-256 of the
 * V4ADDR, and is used to determine a list bucket which may include
 * multiple entries.
 */
struct aeroPRL {
    uint8_t state;
    struct aeroPRL *nextMOD;
    struct aeroPRL *prevMOD;
    struct sockaddr_in rtr;
    struct sockaddr_in6 mla;
    struct aeroPendRS rs;
};

/* Neighbor states */
#define NUD_INCOMPLETE	0x01
#define NUD_REACHABLE	0x02
#define NUD_STALE	0x04
#define NUD_DELAY	0x08
#define NUD_PROBE	0x10
#define NUD_FAILED	0x20

/* Dummy states */
#define NUD_NOARP	0x40
#define NUD_PERMANENT	0x80
#define NUD_NONE	0x00
#define NUD_DEPARTED	NUD_NONE

extern struct aeroNCE *aeroNcacheByMAC[];
extern struct aeroNCE *aeroNcacheByMLA[];

#pragma pack (push,1)
/*
 * AERO/OMNI DHCPv6 Message and Options
 */
struct aeroDHCPv6Msg {
    uint8_t msgType;
    uint8_t transID[3];
    uint8_t opts[0];
};

struct aeroDHCPv6Opt {
    uint16_t option_code;
    uint16_t option_len;
    uint8_t opt_data[0];
};

struct aeroDHCPv6Opt_duid_en {
    uint16_t code;		/* Client ID */
    uint16_t len;		/* 23 */
    uint16_t type;		/* AERO_DHDUID_EN */
    uint32_t enterprise;
    uint16_t idtype;
    struct in6_addr id;
};

struct aeroDHCPv6Opt_rapid {
    uint16_t code;		/* RAPID COMMIT */
    uint16_t len;		/* 0 */
};

struct aeroDHCPv6Opt_eto {
    uint16_t code;		/* ELAPSED TIME */
    uint16_t len;		/* 2 */
    uint16_t elapsed;		/* client sets 0 in first call */
};

struct aeroDHCPv6Opt_oro {
    uint16_t code;		/* OPTION REQUEST */
    uint16_t len;		/* 0 */
    uint16_t req[0];
};

struct aeroDHCPv6Opt_iapd {
    uint16_t code;		/* IAPD */
    uint16_t len;		/* 12 + iana-opts */
    uint32_t iaid;		/* init random; cache for later use */
    uint32_t t1;		/* server-assigned (client sets 0) */
    uint32_t t2;		/* server-assigned (client sets 0) */
    struct iapd_opts {
	uint8_t opts[0];
    } iapd_opts;
};

struct aeroDHCPv6Opt_iapref {
    uint16_t code;		/* IAPREFIX */
    uint16_t len;		/* 25 + iapref-opts */
    uint32_t preferrred;	/* server-assigned (client sets 0) */
    uint32_t valid;		/* server-assigned (client sets 0) */
    uint8_t preflen;
    struct in6_addr pref;
    struct iapref_opts {
	uint8_t opts[0];
    } iapref_opts;
};

/*
 * AERO/OMNI DHCPv6 Messages
 */
struct aeroDHCPv6Solicit {
    struct omniDHCPv6 hdr;
    struct aeroDHCPv6Opt_duid_en duid;
    struct aeroDHCPv6Opt_rapid rapid;
    struct aeroDHCPv6Opt_eto eto;
    struct aeroDHCPv6Opt_iapd iapd;
};

struct aeroDHCPv6SolicitPref {
    struct omniDHCPv6 hdr;
    struct aeroDHCPv6Opt_duid_en duid;
    struct aeroDHCPv6Opt_rapid rapid;
    struct aeroDHCPv6Opt_eto eto;
    struct aeroDHCPv6Opt_iapd iapd;
};
#pragma pack (pop)

#define AERO_DHMSG_SOLICIT	1
#define AERO_DHMSG_ADVERTISE	2
#define AERO_DHMSG_REQUEST	3
#define AERO_DHMSG_CONFIRM	4
#define AERO_DHMSG_RENEW	5
#define AERO_DHMSG_REBIND	6
#define AERO_DHMSG_REPLY	7
#define AERO_DHMSG_RELEASE	8
#define AERO_DHMSG_DECLINE	9
#define AERO_DHMSG_RECONFIGURE	10
#define AERO_DHMSG_INFO_REQ	11
#define AERO_DHMSG_RELAY_FORW	12
#define AERO_DHMSG_RELAY_REPL	13

#define AERO_DHOPT_CLIENTID	1
#define AERO_DHOPT_SERVERID	2
#define AERO_DHOPT_IANA		3
#define AERO_DHOPT_IATA		4
#define AERO_DHOPT_IAADDR	5
#define AERO_DHOPT_ORO		6
#define AERO_DHOPT_ETO		8
#define AERO_DHOPT_STATUS	13
#define AERO_DHOPT_RAPID	14
#define AERO_DHOPT_IAPD		25
#define AERO_DHOPT_IAPREF	26

#define AERO_DHDUID_LLT		1
#define AERO_DHDUID_EN		2
#define AERO_DHDUID_LL		3
#define AERO_DHDUID_UUID	4

#define AERO_DHDUID_IDTYPE	5

/* Functions that need to be made globally accessible */
int aero_run_loop_client(int epollfd);
int aero_run_loop_proxy(int epollfd);
int aero_run_loop_gateway(int epollfd);
void aero_init_ncache();
void aero_init_prl();
void aero_init_addrs(aeroNode *current);
int aero_init_sockets(aeroNode *current);
int omni_frag_init();

#endif
