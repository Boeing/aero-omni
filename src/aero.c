/*
 * aero.c     Main loop for processing all control and data plane messages
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

#define _GNU_SOURCE
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef AERO_VTNSI
#define AERO_VTNSI
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <rte_common.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <aero.h>
#include <main.h>
#ifdef AERO_VTNSI
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif

#define SERVICE_TYPE "_myserver._tcp"
#define SERVICE_PORT 12345
#define RESOLVE_TIMEOUT 10000 /* 10 seconds timeout */ 

/* socket types for epoll events */
#define AERO_SOCK_OMNI	0
#define AERO_SOCK_ETH	1
#define AERO_SOCK_IP4	2
#define AERO_SOCK_IP6	3
#define AERO_SOCK_UDP4	4
#define AERO_SOCK_UDP6	5
#define AERO_SOCK_RTNL	6

/* Neighbor cache */
struct aeroNCE *aeroNcacheByMLA[256];
struct aeroNCE *aeroNcacheByIND[256];
uint32_t nbrID = 0;

/* Potential Router List */
struct aeroPRL *aeroRcacheByMOD[256];

/* local MAC addresses */
uint8_t omni_mac[6];
uint8_t aero_mac[6];

struct aeroIfSock {
    int ifIndex;
    int sockId;
    int sockType;
} aeroIfSock[100];

int aero_rtable_init = 0;
int aero_rtable_sk = 0;

#ifdef AERO_DPDK
/* IPv6 forwarding table */
#define LPM_MAX_RULES 1024
#define LPM6_MAX_RULES 1024
#define LPM6_NUMBER_TBL8S (1 << 16)

struct rte_lpm6_config lpm6_config = {
        .max_rules = LPM6_MAX_RULES,
        .number_tbl8s = LPM6_NUMBER_TBL8S,
        .flags = 0};

struct rte_lpm6 *lpm6;
#endif

/* Use IEEE "DEC Customer use" code until formal ethertype delegated */
#define ETH_P_OMNI ETH_P_CUST

/* Use RFC3692 "experimental' code until formal ipproto delegated */
#define IPPROTO_OMNI 253

/* Use offical AERO/OMNI UDP Port Number (IANA) */
#define IPPORT_OMNI 8060

#define MAXPKT 65535

/*
 * This code has many examples of buffer manipulations in which the source
 * and destination locations overlap. It is essential that data copies for
 * overlapping buffer locations use the "memmove()" library function and
 * not the more common "memcpy()" which corrupts overlapping data copies.
 */

#ifdef AERO_VTNSI

// NSI Constants
static const uint64_t MAX_AGE_MS = 500ULL;
static const uint64_t NS_PER_MS = 1000000ULL;

typedef enum {
    AUTH_NONE = 0,
    AUTH_HMAC,
    AUTH_RSA
} auth_switch_t;

static const auth_switch_t AUTH = AUTH_RSA;

static inline size_t pad8(size_t size)
{
    size_t pad = size % 8;
    return pad ? (8 - pad) : 0;
}

// HMAC

// calculates the size of the hmac suboption (staticly 40 bytes for now)
static inline uint8_t get_hmac_length(/**uint8_t key_id_host */)
{
    const EVP_MD *md = EVP_sha256(); // use key_id in the future
    size_t digest_length = (size_t)EVP_MD_get_size(md); // len in octets

    // calculate padding
    uint8_t plen = 8 + digest_length; uint8_t ppad = (uint8_t)pad8(plen);

    if ((plen + ppad) % 8) { syslog(LOG_INFO, "HMAC padding is incorrect!"); }

    return plen + ppad;
}

static inline uint8_t add_hmac(
    uint8_t **pptr,
    const uint8_t *secret_key,
    size_t key_len,
    uint32_t key_id_host,
    struct ip6_hdr *ip6,
    uint16_t pkt_len)
{
    // local variables
    EVP_MD_CTX *ctx;
    EVP_PKEY *pkey;
    const EVP_MD *md;
    size_t digest_length;
    uint8_t plen, ppad;

    uint8_t *ptr = *pptr;

    // create context
    ctx = EVP_MD_CTX_new();
    pkey = EVP_PKEY_new_raw_private_key(
	EVP_PKEY_HMAC,
	NULL,
	secret_key,
	key_len);
    md = EVP_sha256();
    EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    digest_length = (size_t)EVP_MD_get_size(md);

    // add sub type
    *ptr++ = OMNI_SUBOPT_HMAC;

    // calculate padding
    plen = 8 + digest_length; ppad = (uint8_t)pad8(plen);

    // add sub length
    *ptr++ = ppad ? ((plen / 8 ) + 1) : (plen / 8);

    // add |d| bit and reserved field
    memset((void *)ptr, 0, 2); ptr += 2;

    // add Key ID
    uint32_t key_id_net = htonl(key_id_host);
    memcpy(ptr, &key_id_net, sizeof(key_id_net)); ptr += sizeof(key_id_net);

    // add HMAC digest
    EVP_DigestSignUpdate(ctx, (void *)ip6, pkt_len); // [ip6, key_id]
    void *tr_location = (void*)((uint8_t *)ip6) + pkt_len + digest_length;
    EVP_DigestSignUpdate(ctx, tr_location, 2);

    size_t tmp_len = digest_length;
    EVP_DigestSignFinal(ctx, ptr, &tmp_len); ptr += digest_length;
    assert(tmp_len == digest_length);

    // update pointer
    *pptr = ptr;

    // free context
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_MD_CTX_free(ctx);

    // return the total length written
    return plen + ppad;
}

// returns 1 when valid, 0 if invalid
static inline uint8_t validate_hmac(
    uint8_t *ptr,
    struct ip6_hdr *ip6,
    uint16_t pkt_len)
{
    uint8_t secret_key[] = "secret"; // TODO: Real Secret Key
    const EVP_MD *md = EVP_sha256();
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
	EVP_PKEY_HMAC,
	NULL,
	secret_key,
	sizeof(secret_key) - 1);
    EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    
    uint8_t digest_length = (uint8_t)EVP_MD_get_size(md);
    
    uint8_t hmac_digest[512];
    memcpy(hmac_digest, ((uint8_t *)ptr + 8), digest_length);
    
    EVP_DigestSignUpdate(ctx, (void *)ip6, pkt_len);
    void *tr_location = (void*)((uint8_t *)ip6) + pkt_len + digest_length;
    EVP_DigestSignUpdate(ctx, tr_location, 2);
    
    uint8_t calculated_hmac[512];
    size_t tmp_len = digest_length;
    EVP_DigestSignFinal(ctx, calculated_hmac, &tmp_len);
    assert(tmp_len == digest_length);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    
    return memcmp(calculated_hmac, hmac_digest, digest_length) == 0;
}

// RSA / SEND Implementation

static const char TEST_RSA_PRIV_PEM[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIIDlwIBADANBgkqhkiG9w0BAQEFAASCA4EwggN9AgEAAoHBAL4dxXzE10fWPeTx\n"
"no5W620QFWGTJi0yxr73PO9u+1zPAi+XO/uhJtM5hAIsKHfxvE29imeENy270HdF\n"
"MblYxI6ir/SOzob/csNF99ZQwkAAqi/TER1Y0R98TySa+38gcRWj5AdK/hy34cSI\n"
"+pWn7NYPdPcTeNsrnr7dglQsmiZlhUMcAhroGtdPbdOT6/sEBNKjMyXtChKC5sm2\n"
"t4i9tjTVQZaFx6XydENNwy7P0dcWXNjjaybm94dV1fXaGnzzLwIDAQABAoHBAIo0\n"
"Zk5PYhis3A3Ev/jFoxuDp6dpK0WMNgK5BKkiSsSrD/G8xTQlcG34z8gshba8GqGA\n"
"+k5KRTqP3/n0aTNOHoV6KuNjtStaI/lkscgwqSWR1iYyD6z/1fZHjdkUeWNvFsRD\n"
"SLd/abmmKxFqjbpgCiGMMDJbgCwsXQU68IITn4DSIPMA/w0xo9AjU5xESvk4mmyj\n"
"0Vy6dz8jeZbDjuqTEXF4csHEu2hcS0bcMemrTUsSUj9pVKoTya6rMHjCUUKbIQJh\n"
"AO+xMaxKRrnzicVRIH/J0KXi5xhtnJQXkp9CMw41Jp1Ju+cDaTjHYw5PmJm3ptyd\n"
"XmiaTiJ9km8U9+20CrnByVED7FnmCCmOvWpRbdwaA97BR0MrN9gbgf6rRROgsxJU\n"
"5wJhAMsNGKv3+P1LyvU5xPlCxdm20vrGIVwmYsF5ui1dzmiGsnlDZAeIpR5+s1Jt\n"
"nTPKF6ARhjZ5FfvydXvJurbWCC8Wydaxc9KJoYfL2akAKBoD1M3wO+MOMrqqopK/\n"
"TGpeeQJhAMnE34uo+uCNoev33uOzf3AlEWP+4U/IiCSIFXJgS6Eb8JEGzgx9y2TA\n"
"nDTJ5CzSTCbBvgRKsHnRrOLsLBsyhcUtCEik2zogblKROWmOfLOG//YK63d/sG4w\n"
"vnVHUXadAQJgUSACY3LHgCvwAtn54LzU348z7A2M9ow/mJ1RzR5VgV2PoPNT2860\n"
"aeKlMqGo1TBBECrwPINUTT0pwzNt7e7FhkrMiYKMi+mBKAhCBkuRuhMdysnYo3bg\n"
"vcO/AHJ9zWHBAmA0ntT7lVe6xQGregYfUrdb/ARvtvJbwzxiepDXecaGZrzSQfH0\n"
"RA37HzSqtqtLRJVaZHpsVIYVk0NZzFzMHmZYRCvRtC9MTZS7HK5n7wvwEYOnSNID\n"
"Rkiiun+kjs/DmTs=\n"
"-----END PRIVATE KEY-----\n";

static const char TEST_RSA_PUB_PEM[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIHfMA0GCSqGSIb3DQEBAQUAA4HNADCByQKBwQC+HcV8xNdH1j3k8Z6OVuttEBVh\n"
"kyYtMsa+9zzvbvtczwIvlzv7oSbTOYQCLCh38bxNvYpnhDctu9B3RTG5WMSOoq/0\n"
"js6G/3LDRffWUMJAAKov0xEdWNEffE8kmvt/IHEVo+QHSv4ct+HEiPqVp+zWD3T3\n"
"E3jbK56+3YJULJomZYVDHAIa6BrXT23Tk+v7BATSozMl7QoSgubJtreIvbY01UGW\n"
"hcel8nRDTcMuz9HXFlzY42sm5veHVdX12hp88y8CAwEAAQ==\n"
"-----END PUBLIC KEY-----\n";

static inline EVP_PKEY*
get_rsa_pkey(const uint8_t *pem, size_t pem_len)
{
    BIO *bio = BIO_new_mem_buf((void*)pem, (int)pem_len);

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return pkey;
}

static inline void
hash16_from_pkey(EVP_PKEY *pkey, uint8_t out[16])
{
    int derlen = i2d_PUBKEY(pkey, NULL);

    unsigned char *der = (unsigned char*)OPENSSL_malloc(derlen);

    unsigned char *p = der;
    i2d_PUBKEY(pkey, &p);

    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA1(der, derlen, sha1);
    memcpy(out, sha1, 16);
    
    OPENSSL_free(der);
}

static inline EVP_PKEY* get_pub_from_pem(const char *pem, size_t len) {
    BIO *b = BIO_new_mem_buf((void*)pem, (int)len);
    EVP_PKEY *pub = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);
    BIO_free(b);
    return pub;
}

static inline size_t get_rsa_len_pkey(EVP_PKEY *pkey)
{
    size_t sig_length = (size_t)EVP_PKEY_get_size(pkey);

    /* 20 = type + len + reserved + keyhash */
    size_t base = 20 + sig_length;

    size_t pad = pad8(base);

    return base + pad;
}

static inline uint8_t add_rsa(
    uint8_t **pptr,
    struct ip6_hdr *ip6,
    EVP_PKEY *pkey,
    uint16_t pkt_len)
{
    uint8_t *ptr = *pptr;
    
    //EVP_PKEY *pkey = get_rsa_pkey(private_key_pem, pem_len);
    const EVP_MD *md = EVP_sha256();
    size_t sig_length = (size_t)EVP_PKEY_get_size(pkey);
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
    
    uint8_t keyhash[16];
    hash16_from_pkey(pkey, keyhash);
    
    size_t pad = pad8(20 + sig_length);
    
    uint8_t sub_length = 20 + sig_length + pad;
    
    *ptr++ = OMNI_SUBOPT_AUTH;
    
    *ptr++ = (sub_length / 8); // sublength
    
    memset(ptr, 0, 2); ptr += 2; // reserved
    
    memcpy(ptr, keyhash, 16); ptr += 16;
    
    uint8_t *sig_location = ptr;
    memset(ptr, 0, sig_length); ptr += sig_length;
    
    if (pad) { memset(ptr, 0, pad); ptr += pad; }
    
    *pptr = ptr;
    
    EVP_DigestSignUpdate(ctx, (void *)ip6, pkt_len); // [ip6, SUBOPT_AUTH)
    void *tr_location = (void*)((uint8_t *)ip6) + pkt_len + sub_length;
    EVP_DigestSignUpdate(ctx, tr_location, 2);
    
    size_t tmp_len = sig_length;
    EVP_DigestSignFinal(ctx, sig_location, &tmp_len);
    assert(tmp_len == sig_length);
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return (uint8_t)(sub_length);
}

static inline uint8_t validate_rsa(
    uint8_t *ptr,
    struct ip6_hdr *ip6,
    EVP_PKEY *pub,
    uint16_t pkt_len)
{
    size_t key_siglen = (size_t)EVP_PKEY_get_size(pub);
    
    uint8_t *sig = ptr + 4 + 16;

    uint8_t saved_sig[512];
    memcpy(saved_sig, sig, key_siglen);
    memset(sig, 0, key_siglen);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub);

    EVP_DigestVerifyUpdate(ctx, (void*)ip6, pkt_len);
    void *tr_location = (void *)((uint8_t *)ip6 + pkt_len + (ptr[1] * 8));
    EVP_DigestVerifyUpdate(ctx, tr_location, 2);

    memcpy(sig, saved_sig, key_siglen);

    int result = EVP_DigestVerifyFinal(ctx, saved_sig, key_siglen);

    EVP_MD_CTX_free(ctx);

    return result == 1;
}

// Timestamp

static inline uint64_t div_rnd_u64(uint64_t num, uint64_t den)
{
    return (num + (den / 2)) / den;
}

static inline int64_t div_rnd_s64(int64_t num, int64_t den)
{
    return (num >= 0) ? (num + (den / 2)) / den : (num - (den / 2)) / den;
}

static inline void u64_to_big_endian(uint64_t in, uint8_t out[8])
{
    for (int i = 0; i < 8; i++) {
	out[i] = (uint8_t)(in >> (56 - 8 * i));
    }
}

static inline uint64_t u64_from_big_endian(const uint8_t in[8])
{
    uint64_t out = 0;
    for (int i = 0; i < 8; i++) {
	out |= (uint64_t)in[i] << (56 - 8 * i);
    }
    return out;
}

static inline void rfc3971_to_timespec(uint64_t in, struct timespec *out)
{
    uint64_t seconds = (in >> 16) & 0xFFFFFFFFFFFFULL;
    uint16_t frac = (uint16_t)(in & 0xFFFF);

    uint64_t nsec = div_rnd_u64((uint64_t)frac * NS_PER_S, 1ULL << 16);

    out->tv_sec = (time_t)seconds;
    out->tv_nsec = (long)nsec;

    if (out->tv_nsec >= NS_PER_S)
    {
	out->tv_sec += 1;
	out->tv_nsec -= NS_PER_S;
    }
}

static inline void get_timestamp(uint8_t out[8])
{
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);

    uint64_t seconds = (uint64_t)ts.tv_sec;
    uint64_t frac = div_rnd_u64((uint64_t)ts.tv_nsec * (1ULL << 16), NS_PER_S);

    if (frac == (1ULL << 16)) { seconds += 1; frac = 0; }

    uint64_t value = ((seconds & 0xFFFFFFFFFFFFULL) << 16) | frac;

    u64_to_big_endian(value, out);
}

static inline uint8_t add_timestamp_subopt(uint8_t **pptr)
{
    uint8_t *ptr = *pptr;

    struct omniTimeStamp ts = {0};
    ts.ts.subType = OMNI_SUBOPT_TIME; // subtype
    ts.ts.subLen = 2; //sublen
    get_timestamp(ts.timeStamp);

    memcpy(ptr, &ts, sizeof(ts)); ptr += sizeof(ts);

    *pptr = ptr;

    return sizeof(ts);
}

// returns 1 when valid, 0 if invalid
static inline uint8_t validate_timestamp(const uint8_t timestamp[8])
{
    struct timespec now, pkt; clock_gettime(CLOCK_REALTIME, &now);

    rfc3971_to_timespec(u64_from_big_endian(timestamp), &pkt);
    int64_t dsec = (int64_t)now.tv_sec - (int64_t)pkt.tv_sec;
    int64_t dnsec = (int64_t)now.tv_nsec - (int64_t)pkt.tv_nsec;

    if (dnsec < 0) { dsec -= 1; dnsec += NS_PER_S; }

    int64_t age_ms = dsec * MS_PER_S + div_rnd_s64(dnsec, NS_PER_MS);

    return (age_ms <= (int64_t)MAX_AGE_MS) ? 1 : 0;
}

#endif /* AERO_VTNSI */

#define BUF_SIZE 8192
/* Start - MANET route discovery */
void aero_parse_route(struct nlmsghdr *nlh, uint32_t new)
{
    struct rtmsg *rtm = NLMSG_DATA(nlh);
    struct rtattr *attr;
    int attrlen;
 
    struct in6_addr mla, gw;
#ifdef AERO_NOTDEF
    uint32_t oif;
#endif
    struct aeroNCE **headMLA, **headIND;
    struct aeroNCE *nbr, *nbr2;
    char mlabuf[100], gwbuf[100];

    /* Only monitor IPv6 routes in table 100 */
    if (rtm->rtm_table != 100)
	return;

    /* Only support host routes */
    if (rtm->rtm_dst_len != 128)
	return;

    memset (&mla, 0, sizeof(mla));
    memset (&gw, 0, sizeof(gw));
 
    attr = RTM_RTA(rtm);
    attrlen = RTM_PAYLOAD(nlh);
 
    for (; RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen)) {
	switch (attr->rta_type) {
	case RTA_DST:
	    mla = *(struct in6_addr *)RTA_DATA(attr);
	    break;
	case RTA_GATEWAY:
	    gw = *(struct in6_addr *)RTA_DATA(attr);
	    break;
#ifdef AERO_NOTDEF
	case RTA_OIF:
	    oif = *(int *)RTA_DATA(attr);
	    break;
#endif
	}
    }

    /* Only support LLA gw addrs with EUI-64 IID */
    if ((gw.s6_addr[0] != 0xfe) || ((gw.s6_addr[1] & 0xc0) != 0x80) ||
        (gw.s6_addr[11] != 0xff) || (gw.s6_addr[12] != 0xfe))
	return;

    if (!(inet_ntop(AF_INET6, (void *)&mla, mlabuf, 100)) ||
        !(inet_ntop(AF_INET6, (void *)&gw, gwbuf, 100)))
	return;

    if (new)
    syslog (LOG_INFO, "aero_parse_route: ADD dst: %s, gw: %s", mlabuf, gwbuf);
    else
    syslog (LOG_INFO, "aero_parse_route: DEL dst: %s, gw: %s", mlabuf, gwbuf);

    /* Same as receipt of NS - locate NCE by MLA */
    headMLA = &aeroNcacheByMLA[mla.s6_addr[15]];
    nbr = *headMLA;
    while (nbr && (memcmp ((void *)&nbr->ip6_mla, (void *)&mla, 16)))
	nbr = nbr->nextMLA;

    /* Delete if already in table, then replace if new*/
    if (nbr) {
	nbr2 = nbr->nextMLA;
	if (nbr->prevMLA)
	    nbr->prevMLA->nextMLA = nbr2;
	else
	    *headMLA = nbr2;

	headIND = &aeroNcacheByIND[nbr->index];
	nbr2 = nbr->nextIND;
	if (nbr->prevIND)
	    nbr->prevIND->nextIND = nbr2;
	else
	    *headIND = nbr2;
    }

    if (!new)
	return;

    /* reuse existing or malloc new */
    if (!nbr && !(nbr = (struct aeroNCE *)malloc(sizeof *nbr)))
	return;

    memset (nbr, 0, sizeof(*nbr));

    /* Copy MAC address from gw interface ID (flip u/l bit) */
    nbr->eth_addr[0] = gw.s6_addr[8] ^ 0x02;
    nbr->eth_addr[1] = gw.s6_addr[9];
    nbr->eth_addr[2] = gw.s6_addr[10];
    nbr->eth_addr[3] = gw.s6_addr[13];
    nbr->eth_addr[4] = gw.s6_addr[14];
    nbr->eth_addr[5] = gw.s6_addr[15];

    nbr->prevMLA = (struct aeroNCE *)NULL;
    nbr->nextMLA = nbr2 = *headMLA;
    if (nbr2) nbr2->prevMLA = nbr;
    *headMLA = nbr;

    headIND = &aeroNcacheByIND[nbrID & 0xff];
    nbr->prevIND = (struct aeroNCE *)NULL;
    nbr->nextIND = nbr2 = *headIND;
    if (nbr2) nbr2->prevIND = nbr;
    *headIND = nbr;

    memcpy (&nbr->ip6_nbr, &mla, 16);
    memcpy (&nbr->ip6_gua, &mla, 16);
    memcpy (&nbr->ip6_mla, &mla, 16);
    nbr->ident = (uint32_t)rand();
    nbr->index = nbrID++;
    nbr->mfs = 1280;
    nbr->manet = 1;
}
 
void aero_dump_routes(int sock)
{
    struct {
	struct nlmsghdr nlh;
	struct rtmsg rtm;
    } req;
 
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.rtm.rtm_family = AF_UNSPEC;
#ifdef AERO_NOTDEF
    req.rtm.rtm_table = RT_TABLE_MAIN;
    syslog (LOG_INFO, "aero_dump_routes for table %d", req.rtm.rtm_table);
#else
    req.rtm.rtm_table = 100;
#endif
 
    if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
	perror("send");
	exit(1);
    }
 
    char buf[BUF_SIZE];
    int len;
 
    while ((len = recv(sock, buf, sizeof(buf), 0)) > 0) {
	struct nlmsghdr *nlh;
	for (nlh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nlh, len);
	     nlh = NLMSG_NEXT(nlh, len)) {
 
	    if (nlh->nlmsg_type == NLMSG_DONE)
		return;
 
	    if (nlh->nlmsg_type == NLMSG_ERROR) {
		fprintf(stderr, "Netlink error\n");
		return;
	    }
 
	    aero_parse_route(nlh, 1);
	}
    }
}
 
void aero_monitor_routes(int sock)
{
    char buf[BUF_SIZE];
    int len;
 
    while ((len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
	struct nlmsghdr *nlh;
	for (nlh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nlh, len);
	     nlh = NLMSG_NEXT(nlh, len)) {
 
	    switch (nlh->nlmsg_type) {
	    case RTM_NEWROUTE:
		aero_parse_route(nlh, 1);
		break;
	    case RTM_DELROUTE:
		aero_parse_route(nlh, 0);
		break;
	    }
	}
    }
}
/* End - MANET route discovery */

uint16_t in_chksum(const void *buf, const void *saddr, const void *daddr,
		     uint16_t plen, uint8_t proto)
{
    uint32_t csum, left, csum_pseudo;
    uint16_t len = ntohs(plen);
    const uint16_t *data;

    csum = 0;

    data = saddr; left = sizeof(struct in6_addr);
    while (left > 0) {
	csum += *data++;
	left -= 2;
    }

    data = daddr; left = sizeof(struct in6_addr);
    while (left > 0) {
	csum += *data++;
	left -= 2;
    }

    csum_pseudo = htonl((uint32_t)len);
    data = (uint16_t *)&csum_pseudo;
    csum += *data++; csum += *data;

    csum_pseudo = htonl(proto);
    data = (uint16_t *)&csum_pseudo;
    csum += *data++; csum += *data;

    data = buf; left = len;
    while (left > 1) {
	csum += *data++;
	left -= 2;
    }
    if (left) {
	csum += *(uint8_t *)data;
    }

    while (csum & 0xffff0000)
	csum = (csum >> 16) + (csum & 0xffff);

    return (uint16_t)(~csum);
}

uint16_t om_chksum(const void *buf, uint16_t plen)
{
    uint32_t csum, left;
    uint16_t len = plen;
    const uint16_t *data;

    csum = 0;

    data = buf; left = len;
    while (left > 1) {
	csum += *data++;
	left -= 2;
    }
    if (left) {
	csum += *(uint8_t *)data;
    }

    while (csum & 0xffff0000)
	csum = (csum >> 16) + (csum & 0xffff);

    return (uint16_t)(~csum);
}

/* Helper: compute checksum for ICMPv6 over IPv6 pseudo-header + icmpv6 */
static uint16_t checksum_calc(const void *buf, size_t len)
{
    const uint16_t *data = buf;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len) {
        sum += (*(const uint8_t *)data) << 8;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t icmpv6_checksum(struct in6_addr *src, struct in6_addr *dst,
                                const void *icmp6, uint32_t icmp_len)
{
    /* pseudo-header: src(16) dst(16) plen(4) zero(3) nxt(1) */
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t plen;
        uint8_t zeros[3];
        uint8_t nxt;
    } ph;

    memset(&ph, 0, sizeof(ph));
    ph.src = *src;
    ph.dst = *dst;
    ph.plen = htonl(icmp_len);
    ph.nxt = IPPROTO_ICMPV6;

    /* accumulate pseudo-header + icmpv6 */
    size_t total_len = sizeof(ph) + icmp_len;
    uint8_t *buf = malloc(total_len);
    if (!buf) return 0;
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), icmp6, icmp_len);
    uint16_t cs = checksum_calc(buf, total_len);
    free(buf);
    return cs;
}

void aero_init_ncache()
{
    int i;

    for (i = 0; i < 256; i++) {
	aeroNcacheByMLA[i] = (struct aeroNCE *)0;
	aeroNcacheByIND[i] = (struct aeroNCE *)0;
    }
}

void aero_init_prl()
{
    int i;

    for (i = 0; i < 256; i++) {
	aeroRcacheByMOD[i] = (struct aeroPRL *)0;
    }
}

void aero_init_addrs(aeroNode *current)
{
    aeroNodeInterface *interface = current->data;
    struct aeroPRL *prl, *nxt, **head;
    uint32_t rtr;

    inet_pton(AF_INET6, "ff05::2", (void *)&omni_arm);
    inet_pton(AF_INET6, "ff05:1:3", (void *)&omni_ads);
    inet_pton(AF_INET6, "ff02::1:2", (void *)&omni_adras);
    inet_pton(AF_INET6, "ff02:0:0:0:0:1:ff00:0", (void *)&omni_snm);
    inet_pton(AF_INET6, "2002:0:0:0:0:0:0:0", (void *)&omni_any);

    /*
     * XXX - Currently only reads first PRL entry at startup time; need
     * to read all at startup time; refresh list when JSON changes.
     */
    memset(&omni_rv4, 0, sizeof(omni_rv4));
    omni_rv4.sin_family = AF_INET;
    omni_rv4.sin_port = htons(IPPORT_OMNI);
    if (!(inet_aton(interface->prlv4[0], &omni_rv4.sin_addr))) {
	syslog(LOG_ERR, "bad PRL IPv4");
	return;
    }

    memset(&omni_rv6, 0, sizeof(omni_rv6));
    omni_rv6.sin6_family = AF_INET6;
    omni_rv6.sin6_port = htons(IPPORT_OMNI);
    if (inet_pton(AF_INET6, interface->prlv6[0], &omni_rv6.sin6_addr) != 1) {
	syslog(LOG_ERR, "bad PRL IPv6");
	return;
    }

    rtr = (uint32_t)omni_rv4.sin_addr.s_addr;
    head = &aeroRcacheByMOD[(uint32_t)rtr % 256];
    nxt = *head;
    while (nxt && ((uint32_t)nxt->rtr.sin_addr.s_addr != rtr))
	nxt = nxt->nextMOD;

    if (!nxt) {
	if (!(prl = (struct aeroPRL *)malloc(sizeof *prl))) {
	    syslog(LOG_ERR, "PRL malloc failed");
	    return;
	}

	memset (prl, 0, sizeof(*prl));
	prl->rtr = omni_rv4;
	prl->mla = omni_rv6;
	prl->nextMOD = *head;
	*head = prl;
    }
}

int aero_init_sockets(aeroNode *current)
{
    aeroNodeInterface *interface;
    struct sockaddr_ll sll;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct epoll_event ev;
    struct ifreq ifr;
    int epollfd, sockfd;
    int i = 0, index = 0;
    int on = 1;

    /* set up for epoll servicing */
    if ((epollfd = epoll_create1(0)) == -1) {
	syslog(LOG_ERR, "sock(0.1): epoll_create1() failed");
	return (-1);
    }

    for (; i < 100; i++) {
	aeroIfSock[i].ifIndex = 0;
	aeroIfSock[i].sockId = 0;
	aeroIfSock[i].sockType = 0;
    }

    /* OMNI interface read/write */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        syslog(LOG_ERR, "sock(0.2): sockfd invalid: %s", strerror(errno));
        return -1;
    }

    /* OMNI interface local hwaddr */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "omni0");
    if (!(ioctl(sockfd, SIOCGIFHWADDR, &ifr))) {
	memcpy(omni_mac, ifr.ifr_addr.sa_data, ETH_ALEN);
    } else {
	syslog(LOG_ERR, "failed to fetch OMNI hwaddr");
	return (-1);
    }

    /*
     * AERO interface local hwaddr. Flip u/l bit to differentiate nbrs
     * from aero interface. Pkts sent to this mac will be received due
     * to promiscuous mode.
     */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "aero0");
    if (!(ioctl(sockfd, SIOCGIFHWADDR, &ifr))) {
	memcpy(aero_mac, ifr.ifr_addr.sa_data, ETH_ALEN);
	aero_mac[0] = aero_mac[0] ^ 0x2; /* do not change this */
    } else {
	syslog(LOG_ERR, "failed to fetch AERO hwaddr");
	return (-1);
    }

    memset (&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("aero0");

    /* bind to aero0 interface */
    if (bind (sockfd, (struct sockaddr *)&sll, sizeof (sll))) {
	syslog(LOG_ERR, "sock(0.3): sockfd bind failed: %s", strerror(errno));
	return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = index;
    aeroIfSock[index].sockId = sockfd;
    aeroIfSock[index].sockType = AERO_SOCK_OMNI;
    aeroIfSock[index++].ifIndex = sll.sll_ifindex;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
	syslog(LOG_ERR, "sock(0.4): epoll_ctl fail: %s", strerror(errno));
	return -1;
    }

    /*
     * Netlink socket for receiving routing updates; interface state
     * change updates
     */
    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0)
    {
	syslog(LOG_ERR, "sock(0.5): invalid fd: %s", strerror(errno));
	return -1;
    }

    struct sockaddr_nl nlAddr = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE
    };

    if (bind(sockfd, (struct sockaddr *)&nlAddr, sizeof(nlAddr)) < 0) {
	syslog(LOG_ERR, "sock(0.5.5): sockfd bind failed: %s", strerror(errno));
        return -1;
    }

    aero_rtable_sk = sockfd;

    ev.events = EPOLLIN;
    ev.data.fd = index;
    aeroIfSock[index].sockId = sockfd;
    aeroIfSock[index].sockType = AERO_SOCK_RTNL;
    aeroIfSock[index++].ifIndex = 0;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
	syslog(LOG_ERR, "sock(0.6): epoll_ctl fail: %s", strerror(errno));
	return -1;
    }

    while (current) {
	interface = current->data;

	if (!strcmp(interface->ifGroup, "manet")) {

	    /* raw MAC-layer encapsulation (ETH_P_OMNI) */
	    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_OMNI));
	    if (sockfd < 0) {
		syslog(LOG_ERR, "sock(1): invalid fd: %s", strerror(errno));
		return -1;
	    }

	    memset (&sll, 0, sizeof(sll));
	    sll.sll_family = AF_PACKET;
	    sll.sll_ifindex = if_nametoindex(interface->ifName);

	    /* bind socket to interface */
	    if (bind (sockfd, (struct sockaddr *)&sll, sizeof (sll))) {
		syslog(LOG_ERR, "sock(2), bind failed: %s", strerror(errno));
		return -1;
	    }

	    ev.events = EPOLLIN;
	    ev.data.fd = index;
	    aeroIfSock[index].sockId = sockfd;
	    aeroIfSock[index].sockType = AERO_SOCK_ETH;
	    aeroIfSock[index++].ifIndex = sll.sll_ifindex;
	    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
		syslog(LOG_ERR, "sock(3): epoll_ctl fail: %s", strerror(errno));
		return -1;
	    }

#ifdef AERO_NOTYET
	    goto nextif;
#endif
	}

	/* raw IPv4 encapsulation (IPPROTO_OMNI) */
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_OMNI);
	if (sockfd < 0)
	{
	    syslog(LOG_ERR, "sock(4): invalid fd: %s", strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifName,
		       strlen(interface->ifName))) {
	    syslog(LOG_ERR, "sock(5), bind failed: %s", strerror(errno));
	    return -1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = index;
	aeroIfSock[index].sockId = sockfd;
	aeroIfSock[index].sockType = AERO_SOCK_IP4;
	aeroIfSock[index++].ifIndex = if_nametoindex(interface->ifName);
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
	    syslog(LOG_ERR, "sock(6): epoll_ctl fail: %s", strerror(errno));
	    return -1;
	}

	/* raw IPv6 encapsulation (IPPROTO_OMNI) */
	sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_OMNI);
	if (sockfd < 0)
	{
	    syslog(LOG_ERR, "sock(7): invalid fd: %s", strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifName,
		       strlen(interface->ifName))) {
	    syslog(LOG_ERR, "sock(8), bind failed: %s", strerror(errno));
	    return -1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = index;
	aeroIfSock[index].sockId = sockfd;
	aeroIfSock[index].sockType = AERO_SOCK_IP6;
	aeroIfSock[index++].ifIndex = if_nametoindex(interface->ifName);
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
	    syslog(LOG_ERR, "sock(9): epoll_ctl fail: %s", strerror(errno));
	    return -1;
	}

	/* UDP/IPv4 socket */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
	    syslog(LOG_ERR, "sock(10): invalid fd: %s", strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	{
	    syslog(LOG_ERR, "sock(11): SO_REUSEADDR invalid: %s",
	           strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifName,
		       strlen(interface->ifName))) {
	    syslog(LOG_ERR, "sock(12), bind failed: %s", strerror(errno));
	    return -1;
	}

#ifdef AERO_NOTYET
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
	    syslog(LOG_ERR, "sock(xx): IP_HDRINCL invalid: %s",
	           strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0)
	{
	    syslog(LOG_ERR, "sock(xx): IP_PKTINFO invalid: %s",
	           strerror(errno));
	    return -1;
	}
#endif

	sin.sin_family = AF_INET;
	sin.sin_port = htons(IPPORT_OMNI);
	sin.sin_addr.s_addr = INADDR_ANY;
	if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
	    syslog(LOG_ERR, "sock(13): invalid fd: %s",
	           strerror(errno));
	    return -1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = index;
	aeroIfSock[index].sockId = sockfd;
	aeroIfSock[index].sockType = AERO_SOCK_UDP4;
	aeroIfSock[index++].ifIndex = if_nametoindex(interface->ifName);
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
	    syslog(LOG_ERR, "sock(14): epoll_ctl fail: %s", strerror(errno));
	    return -1;
	}

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
	    syslog(LOG_ERR, "sock(15): invalid fd: %s", strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	{
	    syslog(LOG_ERR, "socket(16): SO_REUSEADDR invalid: %s",
	           strerror(errno));
	    return -1;
	}

#ifdef AERO_NOTYET
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) < 0)
	{
	    syslog(LOG_ERR, "sock(xx): IPV6_HDRINCL invalid: %s",
	           strerror(errno));
	    return -1;
	}
#endif

	if (setsockopt(sockfd, IPPROTO_IPV6, IP_PKTINFO, &on, sizeof(on)) < 0)
	{
	    syslog(LOG_ERR, "sock(17): IP_PKTINFO invalid: %s",
	           strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
	               &on, sizeof(on)) < 0)
	{
	    syslog(LOG_ERR, "sock(18): IPV6_RECVPKTINFO invalid: %s",
	           strerror(errno));
	    return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifName,
		       strlen(interface->ifName))) {
	    syslog(LOG_ERR, "sock(19), bind failed: %s", strerror(errno));
	    return -1;
	}

#ifdef AERO_NOTYET
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) < 0)
	{
	    syslog(LOG_ERR, "sock(xx): IPV6_V6ONLY invalid: %s",
	           strerror(errno));
	    return -1;
	}
#endif

	sin6.sin6_family = AF_INET6;
	sin6.sin6_flowinfo = 0;
	sin6.sin6_port = htons(IPPORT_OMNI);
	sin6.sin6_addr = in6addr_any;
	if (bind(sockfd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0)
	{
	    syslog(LOG_ERR, "sock(20): invalid fd: %s", strerror(errno));
	    return -1;
	}

	ev.events = EPOLLIN;
	ev.data.fd = index;
	aeroIfSock[index].sockId = sockfd;
	aeroIfSock[index].sockType = AERO_SOCK_UDP6;
	aeroIfSock[index++].ifIndex = if_nametoindex(interface->ifName);
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
	    syslog(LOG_ERR, "sock(21): epoll_ctl fail: %s", strerror(errno));
	    return -1;
	}

	/* goto next interface */
#ifdef AERO_NOTYET
nextif:
#endif
	current = current->next;
    }

    return epollfd;
}

/*
 * Return next header and address of upper layer protocol (ULP).
 * This code regards IPsec AH/ESP as ULPs and does not attempt
 * to parse extensions beyond. Returns 0 for fragments and next
 * header value for non-fragments.
 */
uint8_t aero_ip6_nexthdr(struct ip6_hdr *ip6, uint8_t **ulp)
{
    struct ip6_ext *ip6e;
    int elen, plen;
    uint8_t nxt;

    if (ip6 == NULL) {
	*ulp = NULL;
	return (0);
    }

    nxt = ip6->ip6_nxt;
    elen = 0;
    ip6e = (struct ip6_ext *)(ip6 + 1);
    plen = ntohs(ip6->ip6_plen);

    while (plen > 0) {
	switch (nxt) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
	    nxt = ip6e->ip6e_nxt;
	    elen = (ip6e->ip6e_len * 8);
	    ip6e = (struct ip6_ext *)((char *)ip6e + elen);
	    plen -= elen;
	    break;
	    
	case IPPROTO_FRAGMENT:
	    *ulp = ((uint8_t *)ip6e + 8);
	    return (0);

	default:
	    *ulp = (uint8_t *)ip6e;
    	    return (nxt);
	}
    }
    *ulp = (uint8_t *)ip6e;
    return (nxt);
}

/* Set MLA Node Identifier */
void aero_set_mla(struct omniSubHdr *om, uint16_t *olen)
{
    struct omniNodeID *nid = (struct omniNodeID *)om;

    om->subType = OMNI_SUBOPT_NODEID;
    om->subLen = 3;
    nid->padLen = 4;
    nid->idType = OMNI_NIDTYPE_MLA;
    nid->nid_mla = omni_mla;
    *olen = om->subLen * 8;
}

/* Get MLA Node Identifier */
int aero_get_mla(struct omniSubHdr *om, uint16_t olen, struct in6_addr *mla)
{
    while (olen >= (om->subLen * 8)) {
	switch (om->subType) {
	case OMNI_SUBOPT_NODEID:
	    struct omniNodeID *nid = (struct omniNodeID *)om;
	    if (nid->idType == OMNI_NIDTYPE_MLA) {
		memcpy (mla, &nid->nid_mla, sizeof(*mla));
		return 1;
	    }
	default:
	    olen -= (om->subLen * 8);
	    om = (struct omniSubHdr *)((uint8_t *)om + (om->subLen * 8));
	    break;
	}
    }
    return 0;
}

/* Fill out Client Interface Attributes */
void aero_cli_ifattr(struct omniSubHdr *om, uint16_t *olen)
{
    struct omniIfAttr *ifa = (struct omniIfAttr *)(om);
    om->subType = OMNI_SUBOPT_IFATTR; om->subLen = 7;

    /* XXX - check bit ordering */
    ifa->srt = 0; ifa->fmt = (OMNI_FMT_F|OMNI_FMT_M|OMNI_FMT_UNSPEC);
    ifa->lhs_mla = omni_mla;

    /* XXX - set these to proper values later */
    ifa->ifIndex = htonl(0);
    ifa->ifType = htonl(0);
    ifa->ifProvider = htonl(0);
    ifa->ifMetric = htonl(0);
    ifa->ifGroup = htonl(0);

    *olen = om->subLen * 8;
}

void aero_dhcpv6_clipref(struct omniSubHdr *om,  uint16_t len)
{
    struct aeroDHCPv6SolicitPref *dh = (struct aeroDHCPv6SolicitPref *)om;
    uint8_t pad = (len % 8) ? (8 - (len % 8)) : 0;

    om->subType = OMNI_SUBOPT_DHCPv6;
    om->subLen = pad ? ((len / 8) + 1) : (len / 8);

    dh->hdr.padLen = pad;
    dh->hdr.msgType = AERO_DHMSG_SOLICIT;
    dh->hdr.transID[0] = 0x32;
    dh->hdr.transID[1] = 0x1c;
    dh->hdr.transID[2] = 0xba;

    dh->duid.code = htons(AERO_DHOPT_CLIENTID);
    dh->duid.len = htons(24);
    dh->duid.type = htons(AERO_DHDUID_EN);
    dh->duid.enterprise = htonl(45282);
    dh->duid.idtype = htons(AERO_DHDUID_IDTYPE);
    memcpy(&dh->duid.id, &omni_mla, 16);

    dh->rapid.code = htons(AERO_DHOPT_RAPID);
    dh->rapid.len = 0;

    dh->eto.code = htons(AERO_DHOPT_ETO);
    dh->eto.len = htons(2);
    dh->eto.elapsed = 0;

    dh->iapd.code = htons(AERO_DHOPT_IAPD);
    dh->iapd.len = htons(12);
    dh->iapd.iaid = 0xffffffff;
    dh->iapd.t1 = 0;
    dh->iapd.t2 = 0;
}

/* Client Parse DHCPv6 Reply locally (DHCPv6 Client) */
void aero_dhcpv6_clirep(struct omniDHCPv6 *dhc,  uint16_t len)
{
    struct aeroDHCPv6Opt *opt;
    struct aeroDHCPv6Opt_iapd *iapd;
    struct aeroDHCPv6Opt_iapref *iapref;
    char addrbuf[100], cmdbuf[200];

    if (dhc->msgType != AERO_DHMSG_REPLY)
	return;

    opt = (struct aeroDHCPv6Opt *)dhc->opts;
    len -= sizeof(*dhc);
    len -= dhc->padLen;

    while (len >= sizeof(*opt)) {
	switch(ntohs(opt->option_code)) {
	case AERO_DHOPT_IAPD:
	    iapd = (struct aeroDHCPv6Opt_iapd *)opt;
	    if (iapd->len < 37)
		break;

	    iapref = (struct aeroDHCPv6Opt_iapref *)&iapd->iapd_opts;
	    if ((ntohs(iapref->code) == AERO_DHOPT_IAPREF) &&
		(iapref->preflen == 64) && (ntohs(iapref->len) >= 25)) {
		if (inet_ntop(AF_INET6, (void *)&iapref->pref, addrbuf, 100)) {
		    sprintf (cmdbuf,"ip -6 addr replace %s1/128 dev omni0",
			     addrbuf);
		    if (system (cmdbuf))
			syslog(LOG_INFO, "DHCPv6 addr failed: %s", cmdbuf);

		    if (iot_ifname != NULL) {
			sprintf (cmdbuf, "ip -6 addr replace %s1/%d dev %s",
				 addrbuf, iapref->preflen, iot_ifname);
			if (system (cmdbuf))
			    syslog(LOG_INFO, "DHCPv6 pref failed: %s", cmdbuf);
		    }
		}
	    }
	    break;
	default:
	    break;
	}
	len -= (ntohs(opt->option_len) + 4);
	opt = (struct aeroDHCPv6Opt *)((uint8_t *)opt +
				       (ntohs(opt->option_len) + 4));
    }
}

/* Proxy Parse DHCPv6 Reply locally */
void aero_dhcpv6_srvrep(struct aeroDHCPv6Msg *dhc,  uint16_t len,
			struct aeroNCE *nbr)
{
    struct aeroDHCPv6Opt *opt;
    struct aeroDHCPv6Opt_iapd *iapd;
    struct aeroDHCPv6Opt_iapref *iapref;

    if (dhc->msgType != AERO_DHMSG_REPLY)
	return;

    opt = (struct aeroDHCPv6Opt *)dhc->opts;
    len -= sizeof(*dhc);

    while (len >= sizeof(*opt)) {
	switch(ntohs(opt->option_code)) {
	case AERO_DHOPT_IAPD:
	    iapd = (struct aeroDHCPv6Opt_iapd *)opt;
	    if (iapd->len < 37)
		break;

	    iapref = (struct aeroDHCPv6Opt_iapref *)&iapd->iapd_opts;
	    if ((ntohs(iapref->code) == AERO_DHOPT_IAPREF) &&
		(ntohs(iapref->len) >= 25)) {

		if ((rte_lpm6_is_rule_present(lpm6,
		    (const struct rte_ipv6_addr *)&iapref->pref,
		    iapref->preflen, &nbr->index)))
		    break;

		if ((rte_lpm6_add(lpm6,
		    (const struct rte_ipv6_addr *)&iapref->pref,
		    iapref->preflen, nbr->index)))
		    break;

		if ((rte_lpm6_is_rule_present(lpm6,
		    (const struct rte_ipv6_addr *)&nbr->ip6_mla,
		    128, &nbr->index)))
		    break;

		if ((rte_lpm6_add(lpm6,
		    (const struct rte_ipv6_addr *)&nbr->ip6_mla,
		    128, nbr->index)))
		    break;
	    }
	    break;
	default:
	    break;
	}
	len -= (ntohs(opt->option_len) + 4);
	opt = (struct aeroDHCPv6Opt *)((uint8_t *)opt +
				       (ntohs(opt->option_len) + 4));
    }
}

/*
 * Handle OMNI interface IPv6 ND messages.
 */
int aero_omni_nd (struct rte_mbuf *m, struct ether_header *eh,
		  struct ip6_hdr *ip6, struct icmp6_hdr *icmp6,
		  struct sockaddr_in *lldst, struct in6_addr *omdst,
		  struct aeroNCE **n)
{

    struct nd_neighbor_solicit *ns = NULL;
    struct nd_neighbor_advert *na = NULL;
    struct nd_router_solicit *rs = NULL;
    struct nd_router_advert *ra = NULL;
    struct aeroNCE *nbr = NULL;
    struct omniTrail *tr;
    struct omniSubHdr *om;
    uint16_t olen, slen;
    uint8_t *base;
    uint8_t *ndopt;
    uint16_t optlen, trim, plen;

    *n = nbr;

    switch (icmp6->icmp6_type) {
    case ND_ROUTER_SOLICIT:
	if (nodetype != AERO_NODETYPE_CLIENT) return 0;
	rs = (struct nd_router_solicit *)icmp6;
	ndopt = (uint8_t *)(rs + 1);
	optlen = ntohs(ip6->ip6_plen) - sizeof (*rs);
	break;
    case ND_ROUTER_ADVERT:
	if (nodetype != AERO_NODETYPE_PROXY) return 0;
	ra = (struct nd_router_advert *)icmp6;
	ndopt = (uint8_t *)(ra + 1);
	optlen = ntohs(ip6->ip6_plen) - sizeof (*ra);
	break;
    case ND_NEIGHBOR_SOLICIT:
	ns = (struct nd_neighbor_solicit *)icmp6;
	ndopt = (uint8_t *)(ns + 1);
	optlen = ntohs(ip6->ip6_plen) - sizeof (*ns);
	break;
    case ND_NEIGHBOR_ADVERT:
	na = (struct nd_neighbor_advert *)icmp6;
	ndopt = (uint8_t *)(na + 1);
	optlen = ntohs(ip6->ip6_plen) - sizeof (*na);
	break;
    case ND_REDIRECT:
	return 0;
    }

    if (ns || na || rs) {

	/* change LLA src to MLA */
	if IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)
	    memcpy (&ip6->ip6_src, &omni_mla, 16);

	/* if unicast, check whether nbr already established */
	if (!(eh->ether_dhost[0] & 0x01)) {

	    nbr = aeroNcacheByMLA[ip6->ip6_dst.s6_addr[15]];
	    /* nbr = aeroNcacheByMLA[omdst->s6_addr[15]]; */
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&ip6->ip6_dst, 16)))
		nbr = nbr->nextMLA;

	    if (nbr) {
		if (ns || na)
		    memcpy (omdst, &ip6->ip6_dst, sizeof(*omdst));
		else
		    memcpy (omdst, &nbr->ip6_mla, sizeof(*omdst));
		memcpy (lldst, &nbr->lldst, sizeof(*lldst));
	    }
	}

	/* Multicast or non-nbr -> send to target or default router */
	/* dynamic discovery of Proxy/Server IPv4 needed */
	if ((eh->ether_dhost[0] & 0x01) || !nbr) {

	    if (ns && IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		memcpy (omdst, &ns->nd_ns_target, sizeof(*omdst));
		nbr = aeroNcacheByMLA[omdst->s6_addr[15]];
		while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&omdst, 16)))
		    nbr = nbr->nextMLA;
	    } else
		memcpy (omdst, &omni_arm, sizeof(*omdst));
	    memcpy (lldst, &omni_rv4, sizeof(*lldst));
	}

	/* If ns target is MANET nbr, return immediate NA */
	if (ns && nbr && nbr->manet) {
	    uint8_t *llao;
	    const uint8_t flags_byte = 0x80 | 0x40 | 0x20;
    	    uint32_t flags_field = (uint32_t)flags_byte << 24;

	    /* only respond to ns */
	    if (!ns) return 0;

	    /* reverse addresses */
	    ip6->ip6_dst = ip6->ip6_src;
	    ip6->ip6_src = *omdst;

	    /* reset type */
	    icmp6->icmp6_type = ND_NEIGHBOR_ADVERT;

	    na = (struct nd_neighbor_advert *)icmp6;
	    na->nd_na_flags_reserved = htonl(flags_field >> 0);

	    llao = (void *)(na + 1);
	    llao[0] = ND_OPT_TARGET_LINKADDR;
	    llao[1] = 1;
	    memcpy(&llao[2], aero_mac, 6);

	    /* XXX - calculate checksum and return to OMNI */
	    icmp6->icmp6_cksum = 0;
	    uint16_t cs = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst,
				(void *)na, ntohs(ip6->ip6_plen));
	    icmp6->icmp6_cksum = cs;

	    memcpy (eh->ether_shost, aero_mac, ETH_ALEN);
	    memcpy (eh->ether_dhost, omni_mac, ETH_ALEN);
	    eh->ether_type = htons(ETHERTYPE_IPV6);

	    /* Send to OMNI interface */
	    /* this needs a better way to determine b interface */
	    struct sockaddr_ll sll;
	    struct aeroIfSock *b;
	    int mslen, i = 0;
	    while ((b = &aeroIfSock[i++]) &&
		(b->sockType != AERO_SOCK_OMNI));

	    if (!b)
		return 0;

	    memset (&sll, 0, sizeof(sll));
	    sll.sll_ifindex = b->ifIndex;
	    sll.sll_halen = ETH_ALEN;
	    memcpy (sll.sll_addr, omni_mac, ETH_ALEN);
	    mslen = sizeof(*eh) + sizeof(*ip6) + ntohs(ip6->ip6_plen);

	    sendto (b->sockId, (void *)eh, mslen, 0,
		(struct sockaddr *)&sll, sizeof(sll));
	    return 0; /* done with this ND message */
	}

	/* Trim S/TLLAO */
	while (optlen) {
	    trim = ndopt[1] * 8;

	    switch (ndopt[0]) {
	    case ND_OPT_TARGET_LINKADDR:
	    case ND_OPT_SOURCE_LINKADDR:

		if ((optlen -= trim)) {
		    memmove(ndopt, (ndopt + trim), optlen);
		    optlen = 0; /* trim complete */
		}

		plen = ntohs(ip6->ip6_plen);
		ip6->ip6_plen = htons(plen - trim);
		rte_pktmbuf_pkt_len(m) -= trim;
		break;
	    default:
		optlen -= trim;
		ndopt += trim;
		break;
	    }
	}

	base = ((uint8_t *)(ip6 + 1) + ntohs(ip6->ip6_plen));
	om = (struct omniSubHdr *)base;
	olen = 0;

	if (ns || na) {
	    aero_cli_ifattr(om, &slen);
	    om = (struct omniSubHdr *)((uint8_t *)om + slen);
	    olen += slen;
	}

	if (rs) {
	    aero_dhcpv6_clipref((struct omniSubHdr *)om,
	                        sizeof(struct aeroDHCPv6SolicitPref));
	    olen += (om->subLen * 8);
	    om = (struct omniSubHdr *)((uint8_t *)om + (om->subLen * 8));
	}

#ifdef AERO_VTNSI

	// Start of Auth Block

	// Calculate Authentication Offset
	uint8_t authOffset;

	// assumes no remainder
	uint16_t authOffsetBytes = ((uint8_t *)om - (uint8_t *)base);

	if (authOffsetBytes % 8)
	{
	    syslog(LOG_INFO, "OM is not on an 8 octet bound!");
	}

	authOffset = authOffsetBytes / 8;

	// Add Timestamp Suboption
	olen += add_timestamp_subopt((uint8_t **)&om);

	// Add Authentication
	if (AUTH == AUTH_HMAC) {
	    uint8_t hmacLenBytes = get_hmac_length();
	    tr = (struct omniTrail *)((uint8_t *)om + hmacLenBytes);
	    if ((olen + hmacLenBytes) % 8)
	    {
		syslog(LOG_INFO, "olen not on a 8 octet bound");
	    }
	    tr->omniLen = (olen + hmacLenBytes) / 8;
	    tr->authOffset = authOffset;
	    uint8_t secret_key[] = "secret";
	    olen += add_hmac(
		(uint8_t **)&om,
		secret_key, sizeof(secret_key) - 1,
		1,
		ip6,
		(uint8_t *)om - (uint8_t *)ip6 + 8);
	} else if (AUTH == AUTH_RSA) {
	    EVP_PKEY *pkey = get_rsa_pkey(
		(const uint8_t*)TEST_RSA_PRIV_PEM,
		strlen(TEST_RSA_PRIV_PEM));
	    size_t rsaLenBytes = get_rsa_len_pkey(pkey);
	    tr = (struct omniTrail *)((uint8_t *)om + rsaLenBytes);
	    if ((olen + rsaLenBytes) % 8)
	    {
		syslog(LOG_INFO, "olen not on a 8 octet bound");
	    }
	    tr->omniLen = ((olen + rsaLenBytes) / 8);
	    tr->authOffset = authOffset;
	    olen += add_rsa(
		(uint8_t **)&om, ip6, pkey,
		(uint8_t *)om - (uint8_t *)ip6);
	} else {
	    syslog(LOG_INFO, "No Authentication Chosen");
	    tr = (struct omniTrail *)om;
	    tr->omniLen = (olen / 8);
	    tr->authOffset = 0xff;
	}
#else /* AERO_VTNSI */
	tr = (struct omniTrail *)om;
	tr->omniLen = (olen / 8);
	tr->authOffset = 0xff;
#endif /* AERO_VTNSI */

	rte_pktmbuf_pkt_len(m) += olen;

#ifdef AERO_NOTYET
	tr->omniChk = om_chksum(base, (olen + sizeof (*tr)));
#else
	tr->omniChk = 0;
#endif
	rte_pktmbuf_pkt_len(m) += sizeof (*tr);
	*n = nbr;
	return 1;
    }

    if (ra) {

	/* Trim S/TLLAO */
	while (optlen) {
	    trim = ndopt[1] * 8;

	    switch (ndopt[0]) {
	    case ND_OPT_TARGET_LINKADDR:
	    case ND_OPT_SOURCE_LINKADDR:

		if ((optlen -= trim)) {
		    memcpy(ndopt, (ndopt + trim), optlen);
		    optlen = 0; /* trim complete */
		}

		plen = ntohs(ip6->ip6_plen);
		ip6->ip6_plen = htons(plen - trim);
		rte_pktmbuf_pkt_len(m) -= trim;
		break;
	    default:
		optlen -= trim;
		ndopt += trim;
		break;
	    }
	}

	base = ((uint8_t *)(ip6 + 1) + ntohs(ip6->ip6_plen));
	/* RA will be signed in aero_proxy_maint() */
	if (!(eh->ether_dhost[0] & 0x01)) {

	    /* unicast RA - locate NCE by MLA */
	    nbr = aeroNcacheByMLA[ip6->ip6_dst.s6_addr[15]];
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&ip6->ip6_dst, 16)))
		nbr = nbr->nextMLA;

	    if ((*n = nbr) == NULL)
		return 0;

	    /* change LLA src to MLA */
	    if IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)
		memcpy (&ip6->ip6_src, &omni_mla, 16);

	    memcpy (omdst, &nbr->ip6_mla, sizeof(*omdst));
	    memcpy (lldst, &nbr->lldst, sizeof(*lldst));
	    return 1;
	}

	/* don't currently handle multicast RAs */
	return 0;
    }

    return 0;
}

/*
 * Handle ND messages received from link layer on Client.
 */
int aero_link_nd_client (struct rte_mbuf *m, struct ip6_hdr *om6,
		      struct ip6_hdr *ip6, struct icmp6_hdr *icmp6,
		      struct sockaddr_in *llsrc, struct aeroNCE **n,
		      struct omniSubHdr **om, uint16_t *olen)
{
    struct aeroNCE *nbr = NULL;
    struct aeroNCE *nbr2;
    struct omniTrail *tr;
    uint16_t tlen, xlen;
    uint16_t plen;
    uint8_t *llao, *last;

    *n = nbr;

    switch (icmp6->icmp6_type) {
    case ND_ROUTER_ADVERT:
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT:
	break;
    case ND_ROUTER_SOLICIT:
    case ND_REDIRECT:
    default:
	return 0;
    }

    tlen = rte_pktmbuf_pkt_len(m);
    last = (uint8_t *)om6 + tlen;

    if (tlen < sizeof(*tr))
	return 0;

    tlen -= sizeof(*tr);

    tr = (struct omniTrail *)((uint8_t *)om6 + tlen);
    if (tlen < (*olen = (tr->omniLen * 8)))
	return 0;

    xlen = *olen;
    tlen -= xlen;

    *om = (struct omniSubHdr *)((uint8_t *)om6 + tlen);
#ifdef AERO_NOTYET
    if (om_chksum(*om, (xlen + sizeof (*t1)))) {
	syslog(LOG_INFO, "aero_link_nd_client: bad cksum (type: %d, len: %d)",
			icmp6->icmp6_type, xlen);
	return 0;
    }
#endif

#ifdef AERO_VTNSI

    // Authentication

    // Find the start of the Auth Block
    uint8_t authOffset = tr->authOffset;
    uint8_t *base = ((uint8_t *)(ip6 + 1) + ntohs(ip6->ip6_plen));
    struct omniSubHdr *am = (struct omniSubHdr *)(base + (authOffset * 8));
    
    // Loop though authentication helpers
    while (am->subType != OMNI_SUBOPT_HMAC && am->subType != OMNI_SUBOPT_AUTH)
    {
	switch (am->subType)
	{
	    case OMNI_SUBOPT_TIME:
	        if (!validate_timestamp(((uint8_t *)am) + 8))
		    syslog(LOG_INFO, "Timestamp Invalid");
#ifdef AERO_NOTDEF
		else
		    syslog(LOG_INFO, "Timestamp Valid");
#endif
		break;
	    case OMNI_SUBOPT_NONCE:
		break;
	    default:
		syslog(LOG_INFO, "OMNI SUBOPT doesn't match 1");
		return 0; // should prevent an infinite loop
		break; // not needed
	}

	am = (struct omniSubHdr *)((uint8_t *)am + (am->subLen * 8));
    }

    if (am->subType == OMNI_SUBOPT_HMAC) {
	uint16_t pkt_len = (uint8_t *)am - (uint8_t *)ip6 + 8;
	if (validate_hmac((uint8_t *)am, ip6, pkt_len) == 0) {
	    syslog(LOG_INFO, "IPv6ND Rx - HMAC FAILURE");
	    //return 0;
        }
#ifdef AERO_NOTDEF
	else {
	    syslog(LOG_INFO, "IPv6ND Rx - HMAC SUCCESS");
	}
#endif
    } else if (am->subType == OMNI_SUBOPT_AUTH) {
	uint16_t pkt_len = (uint8_t *)am - (uint8_t *)ip6;
	EVP_PKEY *pub = get_pub_from_pem(
	    TEST_RSA_PUB_PEM,
	    strlen(TEST_RSA_PUB_PEM));
	if (validate_rsa((uint8_t *)am, ip6, pub, pkt_len) == 0) {
	    syslog(LOG_INFO, "IPv6ND Rx - RSA FAILURE");
	    // return 0;
	}
#ifdef AERO_NOTDEF
	else {
	    syslog(LOG_INFO, "IPv6ND Rx - RSA SUCCESS");
	}
#endif
    }

#endif /* AERO_VTNSI */

    switch (icmp6->icmp6_type) {
    case ND_ROUTER_ADVERT:

	/* RA sent to my unicast */
	if (!(memcmp ((void *)&om6->ip6_dst, (void *)&omni_mla, 16))) {
	    struct aeroNCE **headMLA;

	    /* unicast RA - locate NCE by MLA address */
	    headMLA = &aeroNcacheByMLA[om6->ip6_src.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&om6->ip6_src, 16)))
		nbr = nbr->nextMLA;

	    if (!nbr) {

		if (!(nbr = (struct aeroNCE *)malloc(sizeof *nbr)))
		    return 0;

		memset (nbr, 0, sizeof(*nbr));

		memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
		nbr->prevMLA = (struct aeroNCE *)NULL;
		nbr->nextMLA = nbr2 = *headMLA;
		if (nbr2) nbr2->prevMLA = nbr;
		*headMLA = nbr;

		/* these will both be the rtr's MLA from now on */
		memcpy (&nbr->ip6_nbr, &ip6->ip6_src, 16);
		memcpy (&nbr->ip6_mla, &om6->ip6_src, 16);
		nbr->ident = (uint32_t)rand();
		nbr->index = nbrID++;
		nbr->mfs = 1280;
	    }

	    /* Make room, then insert SLLAO and include MAC (RFC4861) */
	    plen = ntohs(ip6->ip6_plen);
	    llao = (uint8_t *)(ip6 + 1) + plen;
	    memmove ((llao + 8), llao, last - llao);
	    llao[0] = ND_OPT_SOURCE_LINKADDR; llao[1] = 1;
	    memcpy(&llao[2], aero_mac, ETH_ALEN);
	    plen += 8; ip6->ip6_plen = htons(plen);
	    *om = (struct omniSubHdr *)(llao + 8);
	    rte_pktmbuf_pkt_len(m) += 8;

	    /* XXX - calculate checksum and return to OMNI */
	    icmp6->icmp6_cksum = 0;
	    uint16_t cs = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst,
				(void *)icmp6, ntohs(ip6->ip6_plen));
	    icmp6->icmp6_cksum = cs;

	    /* Record most-recent llsrc */
	    memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));

	    *n = nbr;
	    return 1;
	}

	break;
    case ND_NEIGHBOR_SOLICIT:

	/* NS sent to my unicast */
	if (!(memcmp ((void *)&om6->ip6_dst, (void *)&omni_mla, 16))) {
	    struct aeroNCE **headMLA;
	    struct in6_addr mla = ip6->ip6_src;

	    /* NS - locate NCE by MLA address */
	    headMLA = &aeroNcacheByMLA[mla.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla, (void *)&mla, 16)))
		nbr = nbr->nextMLA;

	    if (!nbr) {
		struct aeroNCE **headIND;

		if (!(nbr = (struct aeroNCE *)malloc(sizeof *nbr)))
		    return 0;

		memset (nbr, 0, sizeof(*nbr));

		memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
		nbr->prevMLA = (struct aeroNCE *)NULL;
		nbr->nextMLA = nbr2 = *headMLA;
		if (nbr2) nbr2->prevMLA = nbr;
		*headMLA = nbr;

		headIND = &aeroNcacheByIND[nbrID & 0xff];
		nbr->prevIND = (struct aeroNCE *)NULL;
		nbr->nextIND = nbr2 = *headIND;
		if (nbr2) nbr2->prevIND = nbr;
		*headIND = nbr;

		memcpy (&nbr->ip6_nbr, &ip6->ip6_src, 16);
		memcpy (&nbr->ip6_gua, &om6->ip6_src, 16);
		memcpy (&nbr->ip6_mla, &mla, 16);
		nbr->ident = (uint32_t)rand();
		nbr->index = nbrID++;
		nbr->mfs = 1280;
	    }

	    /* Make room, then insert SLLAO and include MAC (RFC4861) */
	    plen = ntohs(ip6->ip6_plen);
	    llao = (uint8_t *)(ip6 + 1) + plen;
	    memmove ((llao + 8), llao, last - llao);
	    llao[0] = ND_OPT_SOURCE_LINKADDR; llao[1] = 1;
	    memcpy(&llao[2], aero_mac, ETH_ALEN);
	    plen += 8; ip6->ip6_plen = htons(plen);
	    *om = (struct omniSubHdr *)(llao + 8);
	    rte_pktmbuf_pkt_len(m) += 8;

	    /* XXX - calculate checksum and return to OMNI */
	    icmp6->icmp6_cksum = 0;
	    uint16_t cs = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst,
				(void *)icmp6, ntohs(ip6->ip6_plen));
	    icmp6->icmp6_cksum = cs;

	    if (!(rte_lpm6_is_rule_present(lpm6,
		    (const struct rte_ipv6_addr *)&nbr->ip6_gua,
		    128, &nbr->index))) {

		if ((rte_lpm6_add(lpm6,
		    (const struct rte_ipv6_addr *)&nbr->ip6_gua,
		    128, nbr->index))) {
		    syslog(LOG_INFO, "Client NS: route add failed");
		    return 0;
		}
	     }

	    /* Record most-recent llsrc */
	    memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));

	    *n = nbr;
	    return 1;
	}
	break;

    case ND_NEIGHBOR_ADVERT:
	/* NA sent to my unicast */
	if (!(memcmp ((void *)&om6->ip6_dst, (void *)&omni_mla, 16))) {
	    struct aeroNCE **headMLA;
	    struct in6_addr mla = ip6->ip6_src;

	    /* NA - locate NCE by MLA address */
	    headMLA = &aeroNcacheByMLA[mla.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla, (void *)&mla, 16)))
		nbr = nbr->nextMLA;

	    if (!nbr) {
		struct aeroNCE **headIND;

		if (!(nbr = (struct aeroNCE *)malloc(sizeof *nbr)))
		    return 0;

		memset (nbr, 0, sizeof(*nbr));

		memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
		nbr->prevMLA = (struct aeroNCE *)NULL;
		nbr->nextMLA = nbr2 = *headMLA;
		if (nbr2) nbr2->prevMLA = nbr;
		*headMLA = nbr;

		headIND = &aeroNcacheByIND[nbrID & 0xff];
		nbr->prevIND = (struct aeroNCE *)NULL;
		nbr->nextIND = nbr2 = *headIND;
		if (nbr2) nbr2->prevIND = nbr;
		*headIND = nbr;

		memcpy (&nbr->ip6_nbr, &ip6->ip6_src, 16);
		memcpy (&nbr->ip6_gua, &om6->ip6_src, 16);
		memcpy (&nbr->ip6_mla, &mla, 16);
		nbr->ident = (uint32_t)rand();
		nbr->index = nbrID++;
		nbr->mfs = 1280;
	    }

	    /* Make room, then insert TLLAO and include MAC (RFC4861) */
	    plen = ntohs(ip6->ip6_plen);
	    llao = (uint8_t *)(ip6 + 1) + plen;
	    memmove ((llao + 8), llao, last - llao);
	    llao[0] = ND_OPT_TARGET_LINKADDR; llao[1] = 1;
	    memcpy(&llao[2], aero_mac, ETH_ALEN);
	    plen += 8; ip6->ip6_plen = htons(plen);
	    *om = (struct omniSubHdr *)(llao + 8);
	    rte_pktmbuf_pkt_len(m) += 8;

	    /* XXX - calculate checksum and return to OMNI */
	    icmp6->icmp6_cksum = 0;
	    uint16_t cs = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst,
				(void *)icmp6, ntohs(ip6->ip6_plen));
	    icmp6->icmp6_cksum = cs;

	    if (!(rte_lpm6_is_rule_present(lpm6,
		    (const struct rte_ipv6_addr *)&nbr->ip6_gua,
		    128, &nbr->index))) {

		if ((rte_lpm6_add(lpm6,
		    (const struct rte_ipv6_addr *)&nbr->ip6_gua,
		    128, nbr->index))) {
		    syslog(LOG_INFO, "Client NA: route add failed");
		    return 0;
		}
	    }

	    /* Record most-recent llsrc */
	    memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));

	    *n = nbr;
	    return 1;
	}
    }

    return 0;
}

/*
 * Handle ND messages received from link layer on Proxy.
 */
int aero_link_nd_proxy (struct rte_mbuf *m, struct ip6_hdr *om6,
			struct ip6_hdr *ip6, struct icmp6_hdr *icmp6,
			struct sockaddr_in *llsrc, struct aeroNCE **n,
			struct omniSubHdr **om, uint16_t *olen)
{
    struct aeroNCE *nbr = NULL;
    struct aeroNCE *nbr2;
    struct omniTrail *tr;
    uint16_t tlen, xlen;
    uint16_t plen;
    uint8_t *llao, *last;

    *n = nbr;

    switch (icmp6->icmp6_type) {
    case ND_ROUTER_SOLICIT:
    case ND_NEIGHBOR_SOLICIT:
    case ND_NEIGHBOR_ADVERT:
	break;
    case ND_ROUTER_ADVERT:
    case ND_REDIRECT:
	return 0;
    }

    if ((tlen = rte_pktmbuf_pkt_len(m)) < sizeof(*tr))
	return 0;

    last = (uint8_t *)om6 + tlen;
    tlen -= sizeof(*tr);

    tr = (struct omniTrail *)((uint8_t *)om6 + tlen);
    if (tlen < (*olen = (tr->omniLen * 8)))
	return 0;

    xlen = *olen;
    tlen -= xlen;

    *om = (struct omniSubHdr *)((uint8_t *)om6 + tlen);

#ifdef AERO_NOTYET
    xm = *om;
    if (om_chksum(xm, (xlen + sizeof (*t1)))) {
	syslog(LOG_INFO, "aero_link_nd_proxy: bad cksum (type: %d, len: %d)",
			icmp6->icmp6_type, xlen);
	return 0;
    }
#endif

#ifdef AERO_VTNSI

    // Authentication

    // Find the start of the Auth Block
    uint8_t authOffset = tr->authOffset;
    uint8_t *base = ((uint8_t *)(ip6 + 1) + ntohs(ip6->ip6_plen));
    struct omniSubHdr *am = (struct omniSubHdr *)(base + (authOffset * 8));
    
    // Loop though authentication helpers
    while (am->subType != OMNI_SUBOPT_HMAC && am->subType != OMNI_SUBOPT_AUTH)
    {
	switch (am->subType)
	{
	    case OMNI_SUBOPT_TIME:
	        if (!validate_timestamp(((uint8_t *)am) + 8))
		    syslog(LOG_INFO, "Timestamp Invalid");
#ifdef AERO_NOTDEF
		else
		    syslog(LOG_INFO, "Timestamp Valid");
#endif
		break;
	    case OMNI_SUBOPT_NONCE:
		break;
	    default:
		syslog(LOG_INFO, "OMNI SUBOPT doesn't match 2");
		return 0; // should prevent an infinite loop
		break; // not needed
	}

	am = (struct omniSubHdr *)((uint8_t *)am + (am->subLen * 8));
    }

    if (am->subType == OMNI_SUBOPT_HMAC) {
	uint16_t pkt_len = (uint8_t *)am - (uint8_t *)ip6 + 8;
	if (validate_hmac((uint8_t *)am, ip6, pkt_len) == 0) {
	    syslog(LOG_INFO, "IPv6ND Rx - HMAC FAILURE");
	    //return 0;
        }
#ifdef AERO_NOTDEF
	else {
	    syslog(LOG_INFO, "IPv6ND Rx - HMAC SUCCESS");
	}
#endif
    } else if (am->subType == OMNI_SUBOPT_AUTH) {
	uint16_t pkt_len = (uint8_t *)am - (uint8_t *)ip6;
	EVP_PKEY *pub = get_pub_from_pem(
	    TEST_RSA_PUB_PEM,
	    strlen(TEST_RSA_PUB_PEM));
	if (validate_rsa((uint8_t *)am, ip6, pub, pkt_len) == 0) {
	    syslog(LOG_INFO, "IPv6ND Rx - RSA FAILURE");
	    // return 0;
	}
#ifdef AERO_NOTDEF
	else {
	    syslog(LOG_INFO, "IPv6ND Rx - RSA SUCCESS");
	}
#endif
    }

#endif /* AERO_VTNSI */

    switch (icmp6->icmp6_type) {
    case ND_ROUTER_SOLICIT:

	/* RS sent to my unicast or all-routers multicast */
	if (!(memcmp ((void *)&om6->ip6_dst, (void *)&omni_mla, 16)) ||
	    !(memcmp ((void *)&om6->ip6_dst, (void *)&omni_arm, 16))) {
	    struct aeroNCE **headMLA, **headIND;

	    /* RS - locate NCE by MLA address */
	    headMLA = &aeroNcacheByMLA[om6->ip6_src.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&om6->ip6_src, 16)))
		nbr = nbr->nextMLA;

	    if (!nbr) {

		if (!(nbr = (struct aeroNCE *)malloc(sizeof *nbr)))
		    return 0;

		memset (nbr, 0, sizeof(*nbr));

		nbr->prevMLA = (struct aeroNCE *)NULL;
		nbr->nextMLA = nbr2 = *headMLA;
		if (nbr2) nbr2->prevMLA = nbr;
		*headMLA = nbr;

		headIND = &aeroNcacheByIND[nbrID & 0xff];
		nbr->prevIND = (struct aeroNCE *)NULL;
		nbr->nextIND = nbr2 = *headIND;
		if (nbr2) nbr2->prevIND = nbr;
		*headIND = nbr;

		memcpy (&nbr->ip6_nbr, &ip6->ip6_src, 16);
		memcpy (&nbr->ip6_mla, &om6->ip6_src, 16);
		nbr->ident = (uint32_t)rand();
		nbr->index = nbrID++;
		nbr->mfs = 1280;
	    }

	    /* Make room, then insert SLLAO and include MAC (RFC4861) */
	    plen = ntohs(ip6->ip6_plen);
	    llao = (uint8_t *)(ip6 + 1) + plen;
	    memmove ((llao + 8), llao, last - llao);
	    llao[0] = ND_OPT_SOURCE_LINKADDR; llao[1] = 1;
	    memcpy(&llao[2], aero_mac, ETH_ALEN);
	    plen += 8; ip6->ip6_plen = htons(plen);
	    *om = (struct omniSubHdr *)(llao + 8);
	    rte_pktmbuf_pkt_len(m) += 8;

	    /* calculate checksum and return to OMNI */
	    icmp6->icmp6_cksum = 0;
	    uint16_t cs = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst,
				(void *)icmp6, ntohs(ip6->ip6_plen));
	    icmp6->icmp6_cksum = cs;

	    memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
	    memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));
	    nbr->isClient = 1;
	    *n = nbr;
	    return 1;
	}

	break;
    case ND_NEIGHBOR_SOLICIT:

	/* NS sent to proxy unicast - handle locally */
	if (!(memcmp ((void *)&ip6->ip6_dst, (void *)&omni_mla, 16))) {
	    struct aeroNCE **headMLA;
	    uint8_t *llao;

	    /* NS - locate NCE by source MLA address */
	    /* NCE must have been established by prior RS/RA */
	    headMLA = &aeroNcacheByMLA[om6->ip6_src.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&om6->ip6_src, 16)))
		nbr = nbr->nextMLA;

	    if (!nbr)
		return 0;

	    /* Make room, then insert SLLAO and include MAC (RFC4861) */
	    plen = ntohs(ip6->ip6_plen);
	    llao = (uint8_t *)(ip6 + 1) + plen;
	    memmove ((llao + 8), llao, last - llao);
	    llao[0] = ND_OPT_SOURCE_LINKADDR; llao[1] = 1;
	    memcpy(&llao[2], aero_mac, ETH_ALEN);
	    plen += 8; ip6->ip6_plen = htons(plen);
	    *om = (struct omniSubHdr *)(llao + 8);
	    rte_pktmbuf_pkt_len(m) += 8;

	    /* XXX - calculate checksum and return to OMNI */
	    icmp6->icmp6_cksum = 0;
	    uint16_t cs = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst,
				(void *)icmp6, ntohs(ip6->ip6_plen));
	    icmp6->icmp6_cksum = cs;

	    /* Record most-recent llsrc */
	    memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
	    memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));

	    *n = nbr;
	    return 1;
	} else {

	    /* NS sent to target address - forward */
	    struct aeroNCE **headMLA;
	    uint32_t index;

	    /*
	     * NS may be sourced or destined to a local neighbor Client or a
	     * remote Client of a different Proxy. At least one of the source
	     * or destination must be a local neighbor.
	     */

	    /* NS - locate source NCE by MLA address */
	    headMLA = &aeroNcacheByMLA[om6->ip6_src.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&om6->ip6_src, 16)))
		nbr = nbr->nextMLA;

	    if (nbr) {

		/* Record most-recent llsrc */
		memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
		memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));
	    }

	    /* NS - locate target NCE by NS target address */
	    struct nd_neighbor_solicit *ns =
		(struct nd_neighbor_solicit *)icmp6;
	    if ((rte_lpm6_lookup(lpm6,
		(const struct rte_ipv6_addr *)&ns->nd_ns_target,
		&index) != 0))
		return 0;

	    /* locate target NCE by routing table index */
	    nbr2 = aeroNcacheByIND[index & 0xff];
	    while (nbr2 && (nbr2->index != index))
		nbr2 = nbr2->nextIND;

	    /* if no route to target, drop */
	    if (!nbr2)
		return 0;

	    if (nbr2->isClient)

		/* rewrite destination address */
		om6->ip6_dst = nbr2->ip6_mla;

	    *n = nbr2;
	    return 2;
	}
	break;
    case ND_NEIGHBOR_ADVERT:

	/* NA sent to proxy unicast - handle locally */
	if (!(memcmp ((void *)&ip6->ip6_dst, (void *)&omni_mla, 16))) {
	    struct aeroNCE **headMLA;
	    uint8_t *llao;

	    /* NA - locate NCE by source MLA address */
	    /* NCE must have been established by prior RS/RA */
	    headMLA = &aeroNcacheByMLA[om6->ip6_src.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&om6->ip6_src, 16)))
		nbr = nbr->nextMLA;

	    if (!nbr)
		return 0;

	    /* Make room, then insert TLLAO and include MAC (RFC4861) */
	    plen = ntohs(ip6->ip6_plen);
	    llao = (uint8_t *)(ip6 + 1) + plen;
	    memmove ((llao + 8), llao, last - llao);
	    llao[0] = ND_OPT_TARGET_LINKADDR; llao[1] = 1;
	    memcpy(&llao[2], aero_mac, ETH_ALEN);
	    plen += 8; ip6->ip6_plen = htons(plen);
	    *om = (struct omniSubHdr *)(llao + 8);
	    rte_pktmbuf_pkt_len(m) += 8;

	    /* XXX - calculate checksum and return to OMNI */
	    icmp6->icmp6_cksum = 0;
	    uint16_t cs = icmpv6_checksum(&ip6->ip6_src, &ip6->ip6_dst,
				(void *)icmp6, ntohs(ip6->ip6_plen));
	    icmp6->icmp6_cksum = cs;

	    /* Record most-recent llsrc */
	    memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
	    memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));

	    *n = nbr;
	    return 1;
	} else {

	    /* NA sent to destination address - forward */
	    struct aeroNCE **headMLA;
	    uint32_t index;

	    /*
	     * NA may be sourced or destined to a local neighbor Client or a
	     * remote Client of a different Proxy. At least one of the source
	     * or destination must be a local neighbor.
	     */

	    /* NN - locate source NCE by MLA address */
	    headMLA = &aeroNcacheByMLA[om6->ip6_src.s6_addr[15]];
	    nbr = *headMLA;
	    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&om6->ip6_src, 16)))
		nbr = nbr->nextMLA;

	    if (nbr) {

		/* Record most-recent llsrc */
		memcpy(nbr->eth_addr, aero_mac, ETH_ALEN);
		memcpy (&nbr->lldst, llsrc, sizeof(*llsrc));
	    }

	    /* NA - locate NCE by NA destination address */
	    if ((rte_lpm6_lookup(lpm6,
		(const struct rte_ipv6_addr *)&ip6->ip6_dst,
		&index) != 0))
		return 0;

	    /* locate NCE by routing table index */
	    nbr2 = aeroNcacheByIND[index & 0xff];
	    while (nbr2 && (nbr2->index != index))
		nbr2 = nbr2->nextIND;

	    /* if no route to target, drop */
	    if (!nbr2)
		return 0;

	    /* If NA dst is a local Client, rewrite dst */
	    if (nbr2->isClient)

		/* rewrite destination address */
		om6->ip6_dst = nbr2->ip6_mla;

	    *n = nbr2;
	    return 2;
	}
	break;
    }

    *n = nbr;
    return 0;
}

/*
 * Main AERO processing loops for Client, Proxy, Gateway, or Host.
 * Process all control and data plane messages in the following fashion
 * according to neighbor cache and/or forwarding table state (both IP
 * forwarding and AFIB forwarding):
 *
 * 1) Read from omni; write to underlay (source)
 * 2) Read from underlay; write to omni (destination)
 * 3) Read from underlay; write to underlay (intermediate)
 */
void aero_client_maint(int signum)
{
    struct aeroPRL *prl;
    struct timeval now;
    int i;

    /* dump (then monitor) MANET routing table when it becomes available */
    if (!aero_rtable_init) {
	if (!(system ("ip -6 ro sh table 100"))) {
	    aero_dump_routes(aero_rtable_sk);
	    aero_rtable_init = 1;
	}
    }

    gettimeofday (&now, NULL);
    srand((uint32_t)now.tv_usec);
    for (i = 0; i < 256; i++) {
	for (prl = aeroRcacheByMOD[i]; prl; prl = prl->nextMOD) {
	    if (prl->rs.m) {

		if ((prl->rs.sent.tv_sec + 30) > now.tv_sec)
		    continue;

		/* send pending RS */
		prl->rs.sent = now;
		sendto (prl->rs.sid, (void *)prl->rs.om6,
			rte_pktmbuf_pkt_len(prl->rs.m), 0,
			(struct sockaddr *)&prl->rtr, sizeof(prl->rtr));
	    }
	}
    }
}

int aero_run_loop_client(int epollfd)
{
    struct epoll_event events[10];
    struct aeroIfSock *a, *b;
    struct sockaddr_in llsrc, lldst;
    socklen_t slen = sizeof(llsrc);
    struct itimerval new_timer;
    struct itimerval old_timer;
    struct sockaddr_ll sll;
    struct ether_header *eh;
    struct aeroNCE *nbr;
    struct ip6_hdr *ip6, *om6;
    struct in6_addr omdst;
    struct iphdr *ip4;
    struct rte_mbuf *m, *mo, *m_table[64];
    struct mmsghdr mmsg[24];
    struct iovec mvec[24][8];
    uint8_t *pkt, *ulp;
    int n, nfds, i, j, len, ipv6nd, ipv6ra, ipv6rs;
    uint32_t id, mfs, nfrags;
    struct ip6_frag *fh;
    uint16_t mslen, olen, ehlen;
    struct omniSubHdr *om;
    struct sigaction sa = {
	.sa_handler = aero_client_maint,
	.sa_flags = SA_RESTART | SA_NOCLDSTOP,
    };

#ifdef AERO_DPDK
    lpm6 = rte_lpm6_create("IP_AERO_LPM_0", 0, &lpm6_config);
    if (lpm6 == NULL) {
	syslog(LOG_ERR, "Cannot create DPDK LPM table");
	return 0;
    }
#endif

    new_timer.it_value.tv_sec = 0;
    new_timer.it_value.tv_usec = 200 * 1000;
    new_timer.it_interval.tv_sec = 0;
    new_timer.it_interval.tv_usec = 200 * 1000; 
 
    setitimer(ITIMER_REAL, &new_timer, &old_timer);
    signal(SIGALRM, aero_client_maint); 
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
	syslog(LOG_ERR, "AERO Client sigaction failure");
	return 0;
    }

    for (;;) {

	nfds = epoll_wait(epollfd, events, 10, -1);
	if (nfds < 0) {
	    if (errno == EINTR)
		continue;

	    syslog(LOG_ERR, "epoll_wait returns error %d", errno);
	    return 0;
	}

	for (n = 0; n < nfds; ++n) {

	    nbr = NULL;

            if (!(m = rte_pktmbuf_alloc(mp))) {
		syslog (LOG_INFO, "aero_client: out of mbufs");
		goto c_nextm;
	    }

            pkt = rte_pktmbuf_mtod(m, uint8_t *);
	    a = &aeroIfSock[events[n].data.fd];

	    switch (a->sockType) {
	    case AERO_SOCK_OMNI:

		/* aerod side of OMNI interface in promiscuous mode */
		if ((len = recv(a->sockId, pkt, MAXPKT, 0)) <= 0) {
		    syslog (LOG_INFO, "aero_client: OMNI socket read fail");
		    goto c_next;
		}

		rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m) = len;
		eh = (struct ether_header *)pkt;

		switch (ntohs(eh->ether_type)) {
		case ETHERTYPE_IP:
		    ip4 = (struct iphdr *)(pkt + sizeof(*eh));
		    if (ip4->version != 4) {
		        syslog(LOG_INFO, "aero_client: bad ip4 %d",
				rte_pktmbuf_pkt_len(m));
		    }

		    /* handle ordinary IPv4 here */
		    goto c_next;
		    break;

		case ETHERTYPE_IPV6:
		    ip6 = (struct ip6_hdr *)(pkt + sizeof(*eh));
		    if ((ip6->ip6_vfc >> 4) != 6) {
		    	syslog(LOG_INFO, "aero_client: bad ip6 %d",
				rte_pktmbuf_pkt_len(m));
			goto c_next;
		    }

		    /* Initialize lldst, omdst (both may change) */
		    memcpy (&lldst, &omni_rv4, sizeof(lldst));
		    memcpy (&omdst, &ip6->ip6_dst, sizeof(omdst));
		    /* omdst.s6_addr32[2] = omdst.s6_addr32[3] = 0; SRA */

		    ipv6nd = ipv6rs = 0;

		    if (aero_ip6_nexthdr(ip6, &ulp) == IPPROTO_ICMPV6) {
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)ulp;

			/* Handle IPv6ND here */
			if ((icmp6->icmp6_type >= ND_ROUTER_SOLICIT) &&
			    (icmp6->icmp6_type <= ND_REDIRECT)) {

			    ipv6nd = 1;

			    if (!(aero_omni_nd (m, eh, ip6, icmp6,
						&lldst, &omdst, &nbr))) {
				goto c_next;
			    }

			    if (icmp6->icmp6_type == ND_ROUTER_SOLICIT)
				ipv6rs = 1;
			}
		    }

		    /* for unicast IPv6, locate NCE by MAC address */
		    if (!ipv6nd) {

			/* non-ND multicast - drop for now */
			if (eh->ether_dhost[0] & 0x01) {
			    syslog(LOG_INFO, "aero_client: non-nd multi %d",
					rte_pktmbuf_pkt_len(m));
			    goto c_next;
			}

			if (!nbr) {
			    nbr = aeroNcacheByMLA[ip6->ip6_dst.s6_addr[15]];
			    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&ip6->ip6_dst, 16)))
				nbr = nbr->nextMLA;
			}

			if (nbr)
			    memcpy (&lldst, &nbr->lldst, sizeof(lldst));
		    }

		    /* OMNI encapsulation - replace eh with ipv6 */
		    /* (adjusts rte_pktmbuf_pkt_len) */
		    om6 = (struct ip6_hdr *)rte_pktmbuf_prepend(m,
			(uint16_t)(sizeof (*om6) - sizeof (*eh)));

		    if (!om6) {
			syslog(LOG_INFO, "aero_client: om6 prepend failed");
			goto c_next;
		    }

		    /* Copy IPv6 header, set dst, src */
		    memcpy ((void *)om6, (void *)ip6, sizeof (*ip6));
		    om6->ip6_plen = htons(rte_pktmbuf_pkt_len(m)-sizeof(*om6));
		    om6->ip6_dst = omdst; om6->ip6_src = omni_mla;
		    om6->ip6_nxt = IPPROTO_IPV6;

		    /*
		     * Set DSCP to '111111' for IPv6 ND messages
		     * Reset DSCP '111111' to '110111' for others
		     */
		    if (ipv6nd) {
			om6->ip6_flow |= htonl(0x0ff00000);
		    } else {
			if ((ntohl(om6->ip6_flow) & 0x0ff00000) == 0x0ff00000)
			    om6->ip6_flow &= htonl(0xfdffffff);
		    }

		    /* Send out with UDP/IPv4 encapsulation */
		    /* XXX - need multilink decision for b interface */
		    i = 0;
		    while ((b = &aeroIfSock[i++]) &&
			   (b->sockType != AERO_SOCK_UDP4));

		    if (!b) {
			syslog(LOG_INFO, "aero_client: socket not found");
			goto c_next;
		    }

		    /*
		     * XXX - need to use raw socket with IP_HDRINCL in
		     * subsequent send*() syscalls so that the DSCP and
		     * ECN can be set from the OMNI IPv6 header into the
		     * L2 IP encapsulation header.
		     */
		    if (ipv6nd) {
		    	sendto (b->sockId, (void *)om6, rte_pktmbuf_pkt_len(m),
				0, (struct sockaddr *)&lldst, sizeof(lldst));

			/* cache RS for future iterations */
			if (ipv6rs) {
			    struct aeroPRL *prl = aeroRcacheByMOD[
				((uint32_t)lldst.sin_addr.s_addr % 256)];

			     while (prl && (prl->rtr.sin_addr.s_addr !=
				            lldst.sin_addr.s_addr))
				prl = prl->nextMOD;

			    if (prl) {
				if (prl->rs.m)
				    rte_pktmbuf_free(prl->rs.m);
				prl->rs.m = m;
				prl->rs.om6 = om6;
				gettimeofday (&prl->rs.sent, NULL);
				prl->rs.sid = b->sockId;
				goto c_nextm;
			     }
			}
			goto c_next;
		    }

		    /* data plane packet */
		    /* leave room for likely L2 encapsulations */
		    if (nbr) {
			mfs = nbr->mfs - sizeof (struct ip6_hdr) -
			      sizeof(struct udphdr);
			id = nbr->ident++;
		    } else {
			/* leave room for likely L2 encapsulations */
			mfs = 1280 - sizeof (struct ip6_hdr) -
			      sizeof(struct udphdr);
			id = (uint32_t)rand();
		    }

		    /* Create atomic fragment? */
		    if (rte_pktmbuf_pkt_len(m) <= mfs) {
			uint16_t plen;
    			uint8_t *mptr;

			nfrags = 1;
			ehlen = sizeof (*fh);
			if ((mptr = (uint8_t *)rte_pktmbuf_prepend(m, ehlen))
			    == NULL) {
			    syslog(LOG_INFO, "aero_client: exthdr failed");
			    goto c_next;
			}

			memcpy(mptr, (void *)om6, sizeof(*om6));
			om6 = (struct ip6_hdr *)mptr;
			fh = (struct ip6_frag *)(om6 + 1);
			fh->ip6f_nxt = om6->ip6_nxt;
			fh->ip6f_reserved = 0;
			fh->ip6f_offlg = 0;
			plen = ntohs(om6->ip6_plen);
			om6->ip6_plen = htons(plen + ehlen);
			om6->ip6_nxt = IPPROTO_FRAGMENT;
		    } else {

			/* Framgent packet */
			if ((nfrags = rte_ipv6_fragment_packet(m, &m_table[0],
					64, mfs, mp, mp)) < 0) {
			    syslog(LOG_INFO, "aero_client: fragmentation fail");
			    goto c_next;
			}
		    }

		    /* link up fragment(s) for transmission */
		    memset(mmsg, 0, sizeof(mmsg));
		    for (i = 0; i < nfrags; i++) {
			struct rte_mbuf *z = (nfrags == 1) ? m : m_table[i];

			om6 = rte_pktmbuf_mtod(z, struct ip6_hdr *);
			fh = (struct ip6_frag *)(om6 + 1);
			fh->ip6f_ident = id;

#ifdef AERO_NOTYET
			if (nbr) {
			  struct omniSRH *srh;
			  uint16_t plen;
			  uint8_t *mptr;

			  /* add omniSRH to first mbuf of each fragment */
			  ehlen = sizeof (*srh) + sizeof (omdst);
			  if ((mptr = (uint8_t *)rte_pktmbuf_prepend(z, ehlen))
			      == NULL) {
			      syslog(LOG_INFO, "aero_client: exthdr failed");
			      goto c_next;
			  }

			  memcpy(mptr, (void *)om6, sizeof(*om6));
			  om6 = (struct ip6_hdr *)mptr;
			  srh = (struct omniSRH *)(om6 + 1);
			  srh->rh.ip6r_nxt = om6->ip6_nxt;
			  srh->rh.ip6r_len = 4;
			  srh->rh.ip6r_type = OMNI_SRH_TYPE;
			  srh->rh.ip6r_segleft = 2;
			  srh->sid[0] = nbr->ip6_nbr;
			  srh->sid[1] = nbr->ip6_mla;
			  plen = ntohs(om6->ip6_plen);
			  om6->ip6_plen = htons(plen + ehlen);
			  om6->ip6_nxt = IPPROTO_ROUTING;
			}
#endif /* AERO_NOTYET */

			for (j = 0; (z && (j < 8)); j++) {
			  mvec[i][j].iov_base = rte_pktmbuf_mtod(z, uint8_t *);
			  mvec[i][j].iov_len = rte_pktmbuf_data_len(z);
			  z = z->next;
			}

			if (z) {
			    for (j = 0; (nfrags > 1 && nfrags > j); j++)
				rte_pktmbuf_free(m_table[j]);

			    syslog(LOG_INFO, "aero_client: too many mbuf");
			    goto c_next;
			}

			mmsg[i].msg_hdr.msg_name = (void *)&lldst;
			mmsg[i].msg_hdr.msg_namelen = sizeof(lldst);
			mmsg[i].msg_hdr.msg_iov = mvec[i];
			mmsg[i].msg_hdr.msg_iovlen = j;
		    }

		    sendmmsg (b->sockId, mmsg, nfrags, 0);

		    for (j = 0; (nfrags > 1 && nfrags > j); j++)
			rte_pktmbuf_free(m_table[j]);

		    /* will free m */
		    goto c_next;
		    break;

		case ETHERTYPE_ARP:
		    /* handle ARP here */
		    goto c_next;
		    break;

		default:
		    /* ETHERTYPE not recognized */
		    goto c_next;
		    break;
		}

		break;

	    case AERO_SOCK_UDP4:
	    case AERO_SOCK_UDP6:
	    case AERO_SOCK_IP4:
	    case AERO_SOCK_IP6:
	    case AERO_SOCK_ETH:

		/*
		 * XXX - need to use raw socket with IP_HDRINCL here
		 * so that the DSCP and ECN can be set from the L2 IP
		 * into the OMNI IPv6 header.
		 */
		if ((len = recvfrom(a->sockId, pkt, MAXPKT, 0,
			   (struct sockaddr *)&llsrc, &slen)) <= 0)
		    goto c_next;

		rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m) = len;

		om6 = (struct ip6_hdr *)pkt;

		if ((om6->ip6_vfc >> 4) != 6) {
		    syslog(LOG_INFO, "aero_client: recfrom %d vers %d",
			   rte_pktmbuf_pkt_len(m), (om6->ip6_vfc >> 4));
		    goto c_next;
		}

		switch (aero_ip6_nexthdr(om6, &ulp)) {
		case 0:
		    /* Fragment Header present */
		    fh = (struct ip6_frag *)(ulp - sizeof(*fh));

		    if (fh->ip6f_offlg == 0) {
			/* atomic fragment - remove frag hdr */
			uint8_t *src = (uint8_t *)om6;
			uint8_t *dst = src + sizeof (*fh);
			uint32_t tr = ((uint8_t *)fh - src);
			uint16_t ptmp = ntohs(om6->ip6_plen);
			uint8_t ntmp = fh->ip6f_nxt;
			memmove (dst, src, tr);

			rte_pktmbuf_adj(m, sizeof(*fh));
			om6 = rte_pktmbuf_mtod(m, struct ip6_hdr *);
			om6->ip6_plen = htons(ptmp - sizeof(*fh));
			om6->ip6_nxt = ntmp;
		    } else {
			/* fragmented packet - frag hdr removed later */
			m->l3_len = (uint32_t)((void *)ulp - (void *)om6);
			m->l2_len = 0;
			mo = rte_ipv6_frag_reassemble_packet(frag_tbl,
			    death_row, m, rte_rdtsc(),
			    (struct rte_ipv6_hdr *)om6,
			    (struct ipv6_extension_fragment *)fh);

			if (!mo)
			    goto c_nextm;

			/* first fragment must be large enough */
			if (rte_pktmbuf_data_len(mo) < 1024)
			    goto c_nextm;

			/*
			 * XXX - TODO - accommodate chain of mbufs instead of
			 * linearizing. Need to declare "struct iovec" and
			 * "struct msghdr" then link up chain of mbufs and
			 * prepare for transmission using "sendmsg" instead
			 * of "sendto".
			 */
			if (rte_pktmbuf_linearize(mo))
			    goto c_nextm;

			m = mo;
		    }

		    om6 = rte_pktmbuf_mtod(m, struct ip6_hdr *);
		    if (aero_ip6_nexthdr(om6, &ulp) != IPPROTO_IPV6)
			goto c_next; /* else, fall through */

		case IPPROTO_IPV6:
		    ip6 = (struct ip6_hdr *)ulp;
		    break;
		default:
		    goto c_next;
		}

		if ((ip6->ip6_vfc >> 4) != 6) {
		    syslog(LOG_INFO, "aero_client: bad ip6 %d",
			   rte_pktmbuf_pkt_len(m));
		    goto c_next;
		}

		ipv6nd = ipv6ra = 0;
		if (((ntohl(om6->ip6_flow) & 0x0ff00000) == 0x0ff00000) &&
		    (aero_ip6_nexthdr(ip6, &ulp) == IPPROTO_ICMPV6)) {
		    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)ulp;

		    /* Handle IPv6ND here */
		    if ((icmp6->icmp6_type >= ND_ROUTER_SOLICIT) &&
			(icmp6->icmp6_type <= ND_REDIRECT)) {

			if (!(aero_link_nd_client (m, om6, ip6, icmp6, &llsrc,
						   &nbr, &om, &olen)))
			    goto c_next;

			/* RA requires post-processing */
			if (icmp6->icmp6_type == ND_ROUTER_ADVERT)
			    ipv6ra = 1;

			ipv6nd = 1;
		    }
		}

		if (!ipv6nd) {
		    uint32_t index;

		    if ((rte_lpm6_lookup(lpm6,
			(const struct rte_ipv6_addr *)&om6->ip6_src,
			 &index)) == 0) {
			nbr = aeroNcacheByIND[index & 0xff];
			while (nbr && (nbr->index != index))
			    nbr = nbr->nextIND;
		    }

		    if (!nbr)
			goto c_next;
		}

		/* OMNI decapsulation - replace ipv6 header with ether */
		eh = (struct ether_header *)((void *)ip6 - sizeof(*eh));
		rte_pktmbuf_pkt_len(m) -= sizeof (*om6);
		rte_pktmbuf_pkt_len(m) += sizeof (*eh);

		memcpy (eh->ether_shost, aero_mac, ETH_ALEN);
		memcpy (eh->ether_dhost, omni_mac, ETH_ALEN);
		eh->ether_type = htons(ETHERTYPE_IPV6);

		/* Send to OMNI interface */
		/* this needs a better way to determine b interface */
		i = 0;
		while ((b = &aeroIfSock[i++]) &&
		       (b->sockType != AERO_SOCK_OMNI));

		if (!b)
		    goto c_next;

		memset (&sll, 0, sizeof(sll));
		sll.sll_ifindex = b->ifIndex;
		sll.sll_halen = ETH_ALEN;
		memcpy (sll.sll_addr, omni_mac, ETH_ALEN);

		mslen = sizeof(*eh) + sizeof(*ip6) + ntohs(ip6->ip6_plen);

		sendto (b->sockId, (void *)eh, mslen, 0,
			(struct sockaddr *)&sll, sizeof(sll));

		/* Post-process RA OMNI option; send DHCPv6 messages */
		/* Ethernet; IPv6 header can mostly be reused */
		if (ipv6ra) {
		    struct udphdr *uh = (struct udphdr *)(ip6 + 1);

		    ip6->ip6_nxt = IPPROTO_UDP;
		    uh->source = htons(DHCPV6_SERVER_PORT);
		    uh->dest = htons(DHCPV6_CLIENT_PORT);

		    while (olen > 0) {

			if ((olen == 1) || ((om->subLen * 8) > olen))
			    goto c_next;

			switch (om->subType) {
			case OMNI_SUBOPT_DHCPv6:
#ifdef AERO_NOTYET
			    /*
			     * 01162025 - Currently, there is no DHCPv6
			     * client process listening on the OMNI
			     * interface, although there may be one in the
			     * future. Process DHCPv6 results locally in
			     * aero_dhcpv6_clirep() unless or until a
			     * DHCPv6 Client process is added.
			     */
			    ip6->ip6_plen = htons(sizeof(*uh) + om->subLen);
			    uh->len = ip6->ip6_plen;
			    uh->check = 0;

			    rte_pktmbuf_pkt_len(m) = sizeof(*eh) +
				  sizeof(*ip6) + sizeof(*uh) + om->subLen;

			    /* reset nxt before destructive memcpy */
			    nxt += om->subLen * 8;

			    memcpy((void *)(uh + 1), (void *)(om + 1),
					((om->subLen * 8) - 2));

	    		    uh->check = in_chksum(uh, &ip6->ip6_src,
						&ip6->ip6_dst, ip6->ip6_plen,
						IPPROTO_UDP);

			    sendto (b->sockId, (void *)eh,
					rte_pktmbuf_pkt_len(m), 0,
					(struct sockaddr *)&sll, sizeof(sll));
#else /* AERO_NOTYET */
			    aero_dhcpv6_clirep((struct omniDHCPv6 *)om,
						(om->subLen * 8));

			    olen -= (om->subLen * 8);
			    om = (struct omniSubHdr *)((uint8_t *)om +
							(om->subLen * 8));
#endif /* AERO_NOTYET */
			    break;
			default:
			    olen -= (om->subLen * 8);
			    om = (struct omniSubHdr *)((uint8_t *)om +
							(om->subLen * 8));
			    break;
			}
		    }
		}
		goto c_next;
		break;

	    case AERO_SOCK_RTNL:
		aero_monitor_routes(a->sockId);
		break;
	    }
c_next:
	rte_pktmbuf_free(m);
c_nextm:
	}
    }

    return 0;
}

void aero_proxy_maint(int signum)
{
    struct aeroNCE *nbr;
    struct timeval now;
    int i;

    gettimeofday (&now, NULL);
    srand((uint32_t)now.tv_usec);
    for (i = 0; i < 256; i++) {
	for (nbr = aeroNcacheByMLA[i]; nbr; nbr = nbr->nextMLA) {
	    if (nbr->ra.m) {
		struct omniSubHdr *om;
		struct omniDHCPv6 *dhc;
		struct omniTrail *tr;
		uint16_t dlen, pad, olen = 0;

		if (nbr->ra.rcv.tv_sec == now.tv_sec) {
		    if ((nbr->ra.rcv.tv_usec + 100000) > now.tv_usec)
			continue;
		} else {
		    if ((nbr->ra.rcv.tv_sec == (now.tv_sec - 1)) &&
			(nbr->ra.rcv.tv_usec > 900000) &&
			(now.tv_usec < 100000))
			continue;
		}

		om = (struct omniSubHdr *)nbr->ra.base;

		if (nbr->ra.dh1.m) {
		    dlen = nbr->ra.dh1.l;
		    pad = (dlen % 8) ? (8 - (dlen % 8)) : 0;
		    om->subLen = pad ? ((dlen / 8) + 1) : (dlen / 8);
		    om->subType = OMNI_SUBOPT_DHCPv6;
		    dhc = (struct omniDHCPv6 *)om;
		    dhc->padLen = pad;
		    memcpy ((void *)&dhc->msgType, nbr->ra.dh1.base, dlen);
		    olen += om->subLen * 8;
		    om = (struct omniSubHdr *)((uint8_t *)om + (om->subLen*8));
		    rte_pktmbuf_free(nbr->ra.dh1.m);
		    nbr->ra.dh1.m = NULL;
		}

#ifdef AERO_VTNSI

		// Start of Auth Block
		struct ip6_hdr *ip6 = nbr->ra.ip6;

		// Calculate Authentication Offset
		uint8_t authOffset;

		// assumes no remainder
		uint8_t *base = ((uint8_t *)(ip6 + 1) + ntohs(ip6->ip6_plen));
		uint16_t authOffsetBytes = ((uint8_t *)om - (uint8_t *)base);

		if (authOffsetBytes % 8)
		{
		    syslog(LOG_INFO, "OM is not on an 8 octet bound!");
		}

		authOffset = authOffsetBytes / 8;

		// Add Timestamp Suboption
		olen += add_timestamp_subopt((uint8_t **)&om);

		// Add Authentication
		if (AUTH == AUTH_HMAC) {
		    uint8_t hmacLenBytes = get_hmac_length();
		    tr = (struct omniTrail *)((uint8_t *)om + hmacLenBytes);
  		    if ((olen + hmacLenBytes) % 8)
		    {
			syslog(LOG_INFO, "olen not on a 8 octet bound");
		    }
		    tr->omniLen = ((olen + hmacLenBytes) / 8);
		    tr->authOffset = authOffset;
		    uint8_t secret_key[] = "secret";
		    olen += add_hmac(
			(uint8_t **)&om,
			secret_key, sizeof(secret_key) - 1,
			1, ip6,
			(uint8_t *)om - (uint8_t *)ip6 + 8);
		} else if (AUTH == AUTH_RSA) {
		    EVP_PKEY *pkey = get_rsa_pkey(
			(const uint8_t*)TEST_RSA_PRIV_PEM,
			strlen(TEST_RSA_PRIV_PEM));
		    size_t rsaLenBytes = get_rsa_len_pkey(pkey);
		    tr = (struct omniTrail *)((uint8_t *)om + rsaLenBytes);
		    if ((olen + rsaLenBytes) % 8)
		    {
			syslog(LOG_INFO, "olen not on a 8 octet bound");
		    }
		    tr->omniLen = ((olen + rsaLenBytes) / 8);
		    tr->authOffset = authOffset;
		    olen += add_rsa(
			(uint8_t **)&om, ip6, pkey,
			(uint8_t *)om - (uint8_t *)ip6);
		} else {
		    syslog(LOG_INFO, "No Authentication Chosen");
		    tr = (struct omniTrail *)om;
		    tr->omniLen = (olen / 8);
		    tr->authOffset = authOffset;
		}
#else /* AERO_VTNSI */
		tr = (struct omniTrail *)om;
		tr->omniLen = (olen / 8);
		tr->authOffset = 0xff;
#endif
#ifdef AERO_NOTYET
		tr->omniChk = om_chksum(nbr->ra.base, olen);
#else
		tr->omniChk = 0;
#endif
		olen += sizeof(*tr);
		rte_pktmbuf_pkt_len(nbr->ra.m) += olen;
		nbr->ra.om6->ip6_plen =
		  htons(rte_pktmbuf_pkt_len(nbr->ra.m) - sizeof(*nbr->ra.om6));

		/* send pending RA */
#ifdef AERO_NOTYET
/*
 * XXX - need to use raw socket with IP_HDRINCL here
 * so that the DSCP and ECN can be set from the OMNI
 * IPv6 header into the L2 IP encapsulation header.
 */
#endif
		sendto (nbr->ra.sid, (void *)nbr->ra.om6,
			rte_pktmbuf_pkt_len(nbr->ra.m), 0,
			(struct sockaddr *)&nbr->lldst, sizeof(nbr->lldst));

		/* release RA mbuf */
		rte_pktmbuf_free(nbr->ra.m);
		nbr->ra.m = NULL;
	    }
	}
    }
}

int aero_run_loop_proxy(int epollfd)
{
    struct epoll_event events[10];
    struct aeroIfSock *a, *b;
    struct sockaddr_in llsrc, lldst;
    socklen_t slen = sizeof(llsrc);
    struct itimerval new_timer;
    struct itimerval old_timer;
    struct in6_addr omdst;
    struct sockaddr_ll sll;
    struct ether_header *eh;
    struct aeroNCE *nbr, *nbr2;
    struct ip6_hdr *ip6, *om6;
    struct iphdr *ip4;
    struct rte_mbuf *m;
#ifdef AERO_NOTYET
    struct omniSRH *srh;
#endif
    uint8_t *pkt, *ulp;
    uint8_t proto;
    int n, nfds, i, len, ipv6nd, ipv6nd_ra;
    uint32_t index;
    struct sigaction sa = {
	.sa_handler = aero_proxy_maint,
	.sa_flags = SA_RESTART | SA_NOCLDSTOP,
    };

    new_timer.it_value.tv_sec = 0;
    new_timer.it_value.tv_usec = 200 * 1000;
    new_timer.it_interval.tv_sec = 0;
    new_timer.it_interval.tv_usec = 200 * 1000; 
 
    setitimer(ITIMER_REAL, &new_timer, &old_timer);
    signal(SIGALRM, aero_proxy_maint); 
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
	syslog(LOG_ERR, "AERO Proxy/Server sigaction failure");
	return 0;
    }

    lpm6 = rte_lpm6_create("IP_AERO_LPM_0", 0, &lpm6_config);
    if (lpm6 == NULL) {
	syslog(LOG_ERR, "Cannot create DPDK LPM table");
	return 0;
    }

    for (;;) {

	nfds = epoll_wait(epollfd, events, 10, -1);
	if (nfds < 0) {
	    if (errno == EINTR)
		continue;

	    syslog(LOG_ERR, "epoll_wait returns error %d", errno);
	    return 0;
	}

	for (n = 0; n < nfds; ++n) {

	    nbr = NULL;

            if (!(m = rte_pktmbuf_alloc(mp))) {
		syslog (LOG_INFO, "aero_proxy: out of mbufs");
		goto p_nextm;
	    }

            pkt = rte_pktmbuf_mtod(m, uint8_t *);
	    a = &aeroIfSock[events[n].data.fd];

	    switch (a->sockType) {
	    case AERO_SOCK_OMNI:

		/* aerod side of OMNI interface in promiscuous mode */
		if ((len = recv(a->sockId, pkt, MAXPKT, 0)) <= 0) {
		    syslog (LOG_INFO, "aero_proxy: recv failed");
		    goto p_next;
		}

		rte_pktmbuf_pkt_len(m) = len;
		eh = (struct ether_header *)pkt;

		switch (ntohs(eh->ether_type)) {
		case ETHERTYPE_IP:
		    ip4 = (struct iphdr *)(pkt + sizeof(*eh));
		    if (ip4->version != 4) {
			syslog(LOG_INFO, "aero_proxy: bad ip4 %d",
				rte_pktmbuf_pkt_len(m));
		    }

		    /* handle ordinary IPv4 here */
		    goto p_next;
		    break;

		case ETHERTYPE_IPV6:
		    ip6 = (struct ip6_hdr *)(pkt + sizeof(*eh));
		    if ((ip6->ip6_vfc >> 4) != 6) {
			syslog(LOG_INFO, "aero_proxy: bad ip6 %d",
				rte_pktmbuf_pkt_len(m));
			goto p_next;
		    }

		    ipv6nd = ipv6nd_ra = 0;

		    if ((proto = aero_ip6_nexthdr(ip6, &ulp)) ==
			 IPPROTO_ICMPV6) {
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)ulp;

			/* Handle IPv6ND here */
			if ((icmp6->icmp6_type >= ND_ROUTER_SOLICIT) &&
			    (icmp6->icmp6_type <= ND_REDIRECT)) {
			    if (!(aero_omni_nd (m, eh, ip6, icmp6,
						&lldst, &omdst, &nbr))) {
				goto p_next;
			    }
			    ipv6nd = 1;
			    if (icmp6->icmp6_type == ND_ROUTER_ADVERT)
				ipv6nd_ra = 1;
			}
		    }

		    /* for unicast IPv6, locate NCE by MAC address */
		    if (!ipv6nd) {

			/* non-ND multicast -> drop */
			if (eh->ether_dhost[0] & 0x01) {
		    	    syslog (LOG_INFO, "aero_proxy: non-nd multi");
			    goto p_next;
			}

			if (!nbr) {
			    nbr = aeroNcacheByMLA[ip6->ip6_dst.s6_addr[15]];
			    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				   (void *)&ip6->ip6_dst, 16)))
				nbr = nbr->nextMLA;
			}

			if (!nbr)
			    goto p_next;

			if (proto == IPPROTO_UDP) {
			    struct udphdr *uh = (struct udphdr *)ulp;

			    /* Handle DHCPv6 here */
			    if ((uh->source == htons(DHCPV6_SERVER_PORT)) &&
			        (uh->dest == htons(DHCPV6_CLIENT_PORT))) {
				uint32_t ulen =  (ntohs(uh->len) - sizeof(*uh));
				struct aeroDHCPv6Msg *dhc =
					(struct aeroDHCPv6Msg *)(uh + 1);

				/* Update pending DHCPv6 for this nbr */
				if (nbr->ra.dh1.m)
				    rte_pktmbuf_free(nbr->ra.dh1.m);

				nbr->ra.dh1.m = m;
				nbr->ra.dh1.l = ulen;
				nbr->ra.dh1.base = (void *)dhc;

				/* Update IPv6 routing table */
				aero_dhcpv6_srvrep(dhc, len, nbr);
				goto p_nextm;
			    }
			}

			memcpy (&omdst, &nbr->ip6_mla, sizeof(omdst));
                        memcpy (&lldst, &nbr->lldst, sizeof(lldst));
		    }

		    /* OMNI encapsulation - replace ether header with ipv6 */
		    om6 = (struct ip6_hdr *)rte_pktmbuf_prepend(m,
			(uint16_t)(sizeof (*om6) - sizeof (*eh)));

		    if (!om6) {
		    	syslog (LOG_INFO, "aero_proxy: bad om6");
			goto p_next;
		    }

		    /* Copy IPv6 header, set dst; src */
		    memcpy ((void *)om6, (void *)ip6, sizeof *ip6);
		    om6->ip6_plen = htons(ntohs(ip6->ip6_plen) + sizeof(*ip6));
		    om6->ip6_dst = omdst; om6->ip6_src = omni_mla;
		    om6->ip6_nxt = IPPROTO_IPV6;

		    /*
		     * Set DSCP to '111111' for IPv6 ND messages
		     * Reset DSCP '111111' to '110111' for others
		     */
		    if (ipv6nd) {
			om6->ip6_flow |= htonl(0x0ff00000);
		    } else {
			if ((ntohl(om6->ip6_flow) & 0x0ff00000) == 0x0ff00000)
			    om6->ip6_flow &= htonl(0xfdffffff);
		    }

		    /* Send out with UDP/IPv4 encapsulation */
		    /* this needs a better way to determine b interface */
		    i = 0;
		    while ((b = &aeroIfSock[i++]) &&
			   (b->sockType != AERO_SOCK_UDP4));

		    if (!b) {
		    	syslog (LOG_INFO, "aero_proxy: socket not found");
			goto p_next;
		    }

		    /*
		     * schedule RA for transmission after short delay
		     * to await DHCPv6 results
		     */
		    if (ipv6nd_ra && nbr) {

			/* flush stale RA (rare) */
			if (nbr->ra.m)
			    rte_pktmbuf_free(nbr->ra.m);

			/* queue new RA */
			nbr->ra.m = m;
			gettimeofday(&nbr->ra.rcv, NULL);
			nbr->ra.om6 = om6;
			nbr->ra.ip6 = ip6;
			nbr->ra.base =
				(void *)(ip6 + 1) + ntohs(ip6->ip6_plen);
			nbr->ra.sid = b->sockId;
			goto p_nextm;
		    }

		    /*
		     * XXX - need to use raw socket with IP_HDRINCL here
		     * so that the DSCP and ECN can be set from the OMNI
		     * IPv6 header into the L2 IP encapsulation header.
		     */
		    sendto (b->sockId, (void *)om6, rte_pktmbuf_pkt_len(m), 0,
			    (struct sockaddr *)&lldst, sizeof(lldst));
		    goto p_next;
		    break;

		case ETHERTYPE_ARP:
		    /* handle ARP here */
		    goto p_next;
		    break;

		default:
		    /* ETHERTYPE not recognized */
		    goto p_next;
		    break;
		}

		break;

	    case AERO_SOCK_UDP4:
	    case AERO_SOCK_UDP6:

		/*
		 * XXX - need to use raw socket with IP_HDRINCL here
		 * so that the DSCP and ECN can be set from the L2 IP
		 * into the OMNI IPv6 header.
		 */
		if ((len = recvfrom(a->sockId, pkt, MAXPKT, 0,
			  (struct sockaddr *)&llsrc, &slen)) <= 0)
		    goto p_next;

		rte_pktmbuf_pkt_len(m) = len;

		om6 = (struct ip6_hdr *)pkt;
		if ((om6->ip6_vfc >> 4) != 6) {
		    syslog(LOG_INFO, "aero_proxy: bad om6 %d", len);
		    goto p_next;
		}

		switch (aero_ip6_nexthdr(om6, &ulp)) {
		case IPPROTO_IPV6:
		    ip6 = (struct ip6_hdr *)ulp;
		    if ((ip6->ip6_vfc >> 4) != 6) {
			syslog(LOG_INFO, "aero_proxy: bad ip6 %d", len);
			goto p_next;
		    }
		    break;
		case 0: /* fragment */
		    ip6 = NULL;
		    break;
		default:
		    goto p_next;
		}

		if (((ntohl(om6->ip6_flow) & 0x0ff00000) == 0x0ff00000) &&
		    ip6 && (aero_ip6_nexthdr(ip6, &ulp) == IPPROTO_ICMPV6)) {
		    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)ulp;

		    /* Handle IPv6ND here */
		    if ((icmp6->icmp6_type >= ND_ROUTER_SOLICIT) &&
			(icmp6->icmp6_type <= ND_REDIRECT)) {
			struct omniSubHdr *om, *nxt;
			uint16_t ndlen, olen;
			int ret = aero_link_nd_proxy (m, om6, ip6, icmp6,
					&llsrc, &nbr, &om, &olen);

			if (ret == 0) {
		    	    syslog (LOG_INFO, "aero_proxy: bad link nd");
			    goto p_next;
			}

			if (ret == 2) {

			    /* Send message out same interface */
			    sendto (a->sockId, (void *)om6,
				rte_pktmbuf_pkt_len(m), 0,
				(struct sockaddr *)&nbr->lldst,
				sizeof(nbr->lldst));
			    goto p_next;
			}

			/* OMNI decaps - replace ipv6 hdr with eh */
			eh = (struct ether_header *)((void *)ip6 - sizeof(*eh));
			rte_pktmbuf_pkt_len(m) -= sizeof (*om6);
			rte_pktmbuf_pkt_len(m) += sizeof (*eh);

			memcpy (eh->ether_shost, aero_mac, ETH_ALEN);
			memcpy (eh->ether_dhost, omni_mac, ETH_ALEN);
			eh->ether_type = htons(ETHERTYPE_IPV6);

			/* Send to OMNI interface */
			i = 0;
			while ((b = &aeroIfSock[i++]) &&
			       (b->sockType != AERO_SOCK_OMNI));

			if (!b) {
		    	    syslog (LOG_INFO, "aero_proxy: omni sock");
			    goto p_next;
			}

			memset (&sll, 0, sizeof(sll));
			sll.sll_ifindex = b->ifIndex;
			sll.sll_halen = ETH_ALEN;
			memcpy (sll.sll_addr, omni_mac, ETH_ALEN);

			/* OMNI option not included */
			ndlen = sizeof(*eh) + sizeof(*ip6) +
				ntohs(ip6->ip6_plen);

			sendto (b->sockId, (void *)eh, ndlen, 0,
				(struct sockaddr *)&sll, sizeof(sll));

			/* Post-process RS OMNI option; send DHCPv6 messages */
			/* Ethernet; IPv6 header can mostly be reused */
			if (icmp6->icmp6_type == ND_ROUTER_SOLICIT) {
			    struct udphdr *uh = (struct udphdr *)(ip6 + 1);

			    memcpy(&ip6->ip6_dst, (void *)&omni_adras, 16);
			    ip6->ip6_nxt = IPPROTO_UDP;
			    uh->source = htons(DHCPV6_CLIENT_PORT);
			    uh->dest = htons(DHCPV6_SERVER_PORT);

			    while (olen > 0) {

				if ((olen == 1) || (olen < (om->subLen * 8)))
				    goto p_next;

				/* set nxt before destructive memcpy below */
				nxt = (struct omniSubHdr *)((uint8_t *)om +
							(om->subLen * 8));

				olen -= (om->subLen * 8);

				switch (om->subType) {
				case OMNI_SUBOPT_DHCPv6:
				    struct omniDHCPv6 *dhc =
					(struct omniDHCPv6 *)om;
				    int dlen = (om->subLen * 8);

				    /* subtract hdr octets plus padding */
				    dlen -= (sizeof(*om) + 2 + dhc->padLen);
				    ip6->ip6_plen = htons(sizeof(*uh) + dlen);
				    uh->len = ip6->ip6_plen;
				    uh->check = 0;

				    rte_pktmbuf_pkt_len(m) = sizeof(*eh) +
				      sizeof(*ip6) + sizeof(*uh) + dlen;

				    memmove((void *)(uh + 1),
					(void *)&dhc->msgType, dlen);

	    			    uh->check = in_chksum(uh, &ip6->ip6_src,
						&ip6->ip6_dst, ip6->ip6_plen,
						IPPROTO_UDP);

#ifdef AERO_NOTYET
/*
 * XXX - need to use raw socket with IP_HDRINCL here
 * so that the DSCP and ECN can be set from the OMNI
 * IPv6 header into the L2 IP encapsulation header.
 */
#endif
				    sendto (b->sockId, (void *)eh,
					rte_pktmbuf_pkt_len(m), 0,
					(struct sockaddr *)&sll, sizeof(sll));
				    break;
				default:
				    break;
				}
				om = nxt;
			    }
			}
			goto p_next;
			break;
		    }
		}

		/* data plane packet; forward */
		if (!nbr) {
		    nbr = aeroNcacheByMLA[om6->ip6_src.s6_addr[15]];
		    while (nbr && (memcmp ((void *)&nbr->ip6_mla,
				     (void *)&om6->ip6_src, 16)))
			nbr = nbr->nextMLA;
		}

#ifdef AERO_NOTYET
		if (!nbr || (om6->ip6_nxt != IPPROTO_ROUTING))
		    goto p_next;

		srh = (struct omniSRH *)(om6 + 1);
		if ((srh->rh.ip6r_type != OMNI_SRH_TYPE) ||
		    (srh->rh.ip6r_len & 0x01))
		    goto p_next;

		nsegs = srh->rh.ip6r_len / 2;
		sleft = srh->rh.ip6r_segleft--;
		if ((nsegs < sleft) || (sleft == 0))
		    goto p_next;

		omdst = om6->ip6_dst;
		om6->ip6_dst = srh->sid[--sleft];
		srh->sid[sleft] = omdst;
#endif /* AERO_NOTYET */

		if ((rte_lpm6_lookup(lpm6,
		    (const struct rte_ipv6_addr *)&om6->ip6_dst,
		    &index)) == 0) {
		    nbr2 = aeroNcacheByIND[index & 0xff];
		    while (nbr2 && (nbr2->index != index))
			nbr2 = nbr2->nextIND;

		    /* if no nbr2 or loopback, drop */
		    if (!nbr2 || (nbr == nbr2))
			goto p_next;

		    /* Send message out same interface */
		    om6->ip6_dst = nbr2->ip6_mla;
		    om6->ip6_src = nbr->ip6_mla;
		    sendto (a->sockId, (void *)om6, rte_pktmbuf_pkt_len(m), 0,
			(struct sockaddr *)&nbr2->lldst, sizeof(nbr2->lldst));
		}
		goto p_next;
		break;

	    case AERO_SOCK_ETH:
	    case AERO_SOCK_IP4:
	    case AERO_SOCK_IP6:
	    case AERO_SOCK_RTNL:
		goto p_next;
		break;
	    }
p_next:
	rte_pktmbuf_free(m);
p_nextm:
	}
    }
    return 0;
}

int aero_run_loop_gateway(int epollfd)
{
    return 0;
}
