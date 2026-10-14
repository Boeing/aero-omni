/*
 * main.c       main
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#ifdef AERO_DPDK
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#endif
#include "unistd.h"
#include "sys/inotify.h"
#include "sys/time.h"
#define _GNU_SOURCE
#include <getopt.h>

#include "jansson.h"
#include "aero_config_utils.h"

#define MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#include "aero.h"

#ifdef AERO_DPDK
struct rte_mempool *mp;
struct rte_ip_frag_tbl *frag_tbl;
struct rte_ip_frag_death_row aero_dr;
struct rte_ip_frag_death_row *death_row = &aero_dr;
uint64_t frag_cycles;
struct rte_mbuf *mtest;
char *dpdk_argv[] = { "/usr/local/sbin/aerod", "--syslog", "--log-level=info" };
int dpdk_argc = 3;
#endif

#ifdef AERO_JSON
json_t *readConfig;
json_t *re_readConfig;
json_t *readInterface;
struct aero_interface *nodeLink;
#endif

static char *config_file = "/etc/network/aerod.json";
static int verbose = 0;
static int daemonize = 0;
static char *pid_file = NULL;
static int volatile go_down = 0;
static pid_t child = 0;
int nodetype = AERO_NODETYPE_NONE;
struct in6_addr omni_null = IN6ADDR_ANY_INIT;
struct in6_addr omni_mla = IN6ADDR_ANY_INIT;
struct in6_addr omni_gua = IN6ADDR_ANY_INIT;
struct in6_addr omni_arm;
struct in6_addr omni_ads;
struct in6_addr omni_adras;
struct in6_addr omni_snm;
struct in6_addr omni_any;
struct sockaddr_in omni_rv4;
struct sockaddr_in6 omni_rv6;
char *iot_ifname = NULL;
int omni_fd;
int json_fd;
int udp4_fd;
int udp6_fd;
int ip4_fd;
int ip6_fd;
int eth_fd;
int rtnl_fd;

static int syslog_facility = LOG_DAEMON;

static void show_help()
{
	fprintf(stderr, "Usage: aerod [OPTIONS] [ROUTER]...\n");
	fprintf(stderr, "       -T --nodetype   AERO/OMNI nodetype\n");
	fprintf(stderr, "          Host/Client/Proxy/Server/Gateway\n");
	fprintf(stderr, "       -C --config     configuration file name\n");
	fprintf(stderr, "                       default: %s\n", config_file);
	fprintf(stderr, "       -a --address    Multilink Local Address\n");
	fprintf(stderr, "       -d --daemon     fork into background\n");
	fprintf(stderr, "       -i --iot        Internet of Things ifname\n");
	fprintf(stderr, "       -p --pid        store pid of daemon in file\n");
	fprintf(stderr, "       -v --verbose    increase verbosity\n");
	fprintf(stderr, "       -q --quiet      decrease verbosity\n");
	fprintf(stderr, "       -h --help       display this message\n");
	fprintf(stderr, "          --version    display version\n");

	exit(1);
}

static void show_version()
{

	fprintf(stderr, "Copyright (c) 2024 The Boeing Company\n");
	fprintf(stderr, "\nThis is free software; You may redistribute copies of this software\n");
	fprintf(stderr, "under the terms of the GNU General Public License.\n");
	fprintf(stderr, "For more information about these matters, see the file named COPYING.\n");

	exit(0);
}

static void parse_options(int argc, char **argv)
{
	int c;
	const char *short_options = "hvqdV:i:p:a:T:C:";
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"verbose", 0, NULL, 'v'},
		{"quiet", 0, NULL, 'q'},
		{"daemon", 0, NULL, 'd'},
		{"version", 0, NULL, 'V'},
		{"iot", 1, NULL, 'i'},
		{"pid", 1, NULL, 'p'},
		{"address", 1, NULL, 'a'},
		{"nodetype", 1, NULL, 'T'},
		{"config", 1, NULL, 'C'},
		{NULL, 0, NULL, 0}};
	int long_index = 0;

	while (1)
	{
		c = getopt_long(argc, argv, short_options, long_options,
						&long_index);
		if (c == -1)
			break;

		switch (c)
		{
		case 'd': /* --daemonize */
			daemonize = 1;
			break;

		case 'p': /* --pid */
			pid_file = strdup(optarg);
			break;

		case 'v': /* --verbose */
			verbose++;
			break;

		case 'q': /* --quiet */
			verbose--;
			break;

		case 'V': /* --version */
			show_version();
			break;

		case 'T': /* --nodetype */
			if (strcmp(optarg, "Client") == 0)
			{
				nodetype = AERO_NODETYPE_CLIENT;
				break;
			}

			if ((strcmp(optarg, "Proxy") == 0) ||
				(strcmp(optarg, "Server") == 0) ||
				(strcmp(optarg, "P/S") == 0) ||
				(strcmp(optarg, "Proxy/Server") == 0))
			{
				nodetype = AERO_NODETYPE_PROXY;
				break;
			}

			if (strcmp(optarg, "Gateway") == 0)
			{
				nodetype = AERO_NODETYPE_GATEWAY;
				break;
			}

			syslog(LOG_ERR, "invalid type -- %s", optarg);
			show_help();
			break;

		case 'C': /* --config */
			config_file = strdup(optarg);
			break;

		case 'i': /* --iot */
			iot_ifname = strdup(optarg);
			break;

		case 'a': /* --address */
			if (inet_pton(AF_INET6, optarg, &omni_mla) != 1) {
			    syslog(LOG_ERR, "invalid address -- %s", optarg);
                            show_help();
			}
			break;

		default:
			syslog(LOG_ERR, "not implemented option -- %s",
				   argv[optind - 1]);
		case 'h':
		case '?':
			show_help();
			break;
		}
	}
}

/**
 * Creates OMNI interface. 
 **/
static int create_omni_interface(aeroNode *current)
{
	aeroNodeInterface *interface = current->data;
	char addrbuf[100], cmdbuf[200];

	/* Command line options override config file */
	if (!memcmp((void *)&omni_mla, (void *)&omni_null, 16))
	    omni_mla = interface->omniAddress;

	/*
	 * aerod reads/writes via aero0
	 * OS reads/writes via omni0
	 */
	if (system ("ip link add aero0 type veth peer name omni0"))
	    return 0;

	if (system ("ethtool --offload aero0 rx off tx off"))
	    return 0;
		
	if (system ("ethtool --offload omni0 rx off tx off"))
	    return 0;

	if (system ("sysctl -w net.ipv6.conf.aero0.router_solicitations=0") < 0)
	    return 0;

	if (nodetype != AERO_NODETYPE_CLIENT) {
	    if (system ("sysctl -w net.ipv6.conf.omni0.router_solicitations=0") < 0)
		return 0;

	    if (system ("sysctl -w net.ipv6.conf.omni0.forwarding=1") < 0)
		return 0;
	}

	if (system ("sysctl -w net.ipv6.conf.omni0.dad_transmits=0") < 0)
	    return 0;

	if (system ("sysctl -w net.ipv6.conf.omni0.enhanced_dad=0") < 0)
	    return 0;

	if (!inet_ntop(AF_INET6, (void *)&omni_mla, addrbuf, 100))
	    return 0;

	sprintf(cmdbuf, "ip -6 addr add %s dev omni0", addrbuf);
	if (system (cmdbuf))
	    return 0;

	if (system ("ip link set dev aero0 promisc on"))
	    return 0;

	if (system ("ip link set dev aero0 mtu 2048"))
	    return 0;

	if (system ("ip link set dev aero0 up"))
	    return 0;

	if (system ("ip link set dev omni0 mtu 2048"))
	    return 0;

	if (system ("ip link set dev omni0 up"))
	    return 0;

	if (system ("ip -6 ro add 2001:30::/28 dev omni0") < 0)
	    return 0;

	if (system ("ip -6 ro add 2001:db8::/32 dev omni0") < 0)
	    return 0;

	return 1;
}

/**
 * Sets OMNI interface DOWN and delete it.
 **/
static void delete_omni_interface()
{
	if ((system ("ip link set dev aero0 down")) ||
	    (system ("ip link set dev omni0 down")))
		return;

	if (system ("ip link del dev aero0"))
		return;

	if (system ("ip link del dev omni0"))
		return;
}

static void write_pid_file()
{
	struct flock fl;
	char s[32];
	int pf;

	pf = open(pid_file, O_WRONLY | O_CREAT, 0644);
	if (pf < 0)
	{
		syslog(LOG_ERR, "Cannot create pid file, terminating: %s",
			   strerror(errno));
		exit(1);
	}

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(pf, F_SETLK, &fl) < 0)
	{
		syslog(LOG_ERR, "Cannot lock pid file, terminating: %s",
			   strerror(errno));
		exit(1);
	}

	if (ftruncate(pf, 0) < 0)
	{
		syslog(LOG_ERR, "Cannot truncate pid file, terminating: %s",
			   strerror(errno));
		exit(1);
	}

	snprintf(s, sizeof(s), "%d\n", (int)getpid());
	if (write(pf, s, strlen(s)) < strlen(s))
		syslog(LOG_ERR, "write: %s", strerror(errno));
	if (fsync(pf) < 0)
		syslog(LOG_ERR, "fsync: %s", strerror(errno));
}

/**
 * SIGINT, SIGTERM
 *
 * kill child and go down
 **/
static void sigint_handler(int sig)
{
	signal(sig, SIG_DFL);
	if (verbose >= 0)
		syslog(LOG_NOTICE, "signal %d received, going down.", sig);
	if (child)
		kill(child, SIGHUP);
	go_down = 1;
}

/**
 * SIGHUP
 *
 * kill child to continue in main loop
 **/
static void sighup_handler(int sig)
{
	if (verbose >= 0)
		syslog(LOG_NOTICE, "SIGHUP received.");
	if (child)
		kill(child, SIGHUP);
}

static void setup_signals()
{
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGHUP, sighup_handler);
}

#ifdef AERO_CONFIGMON
static void monitorConfigFile()
{
	int file_descriptor;
	int watch_descriptor;
	int retval;
	struct timeval tv;

	while (true)
	{
		file_descriptor = inotify_init();
		watch_descriptor = inotify_add_watch(file_descriptor, config_file, IN_MODIFY);
		if (watch_descriptor < 0)
		{
		    syslog(LOG_INFO, "inotify cannot be used");
		}
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(file_descriptor, &rfds);
		tv.tv_sec = 500;
		tv.tv_usec = 0;
		retval = select(file_descriptor + 1, &rfds, NULL, NULL, &tv);
		if (retval == -1)
			perror("select()");
		else if (retval)
		{
			syslog(LOG_INFO, "Config file modified");
			reloadConfigFile();
		}
	}
}
#endif

int main(int argc, char **argv)
{
#ifdef AERO_JSON
	json_t *jsonConf;
	aeroParamList *paramList;
	json_t *interfaceArray;
	aeroNode *current;
#endif /* AERO_JSON */

	int epollfd = 0;

	openlog(NULL, LOG_PID | LOG_PERROR, syslog_facility);

	/* initialize omni_mla to "unspecified" */
	if (inet_pton(AF_INET6, "::", &omni_mla) != 1) {
	    syslog(LOG_ERR, "inet_pton: %s", strerror(errno));
	    exit(1);
	}

	parse_options(argc, argv);

	if (daemonize == 1)
	{
		pid_t pid = fork();

		if (pid < 0)
		{
			syslog(LOG_ERR, "fork: %s", strerror(errno));
			exit(1);
		}
		if (pid > 0)
		{
			/* Parent */
			if (verbose >= 1)
				syslog(LOG_INFO, "Running aerod as pid %d",
					   (int)pid);
			exit(0);
		}

		/* Child */
		setsid();
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	if (pid_file != NULL)
		write_pid_file();

	setup_signals();

	/* Load the config file, parse it, and print the contents
	 * -------------------------------------------------------
	 * This block of code is responsible for loading the config file,
	 * parsing it, and printing the contents.
	 *
	 * The code uses the `loadConfigFile()` function to load the config
	 * file, `createParamList()` to create a parameter list,
	 * `json_object_get()` to get the array of interfaces, and
	 * `parseJSON()` to parse the JSON.
	 *
	 * The code then iterates through each interface and prints
	 * its contents using the `printInterface()` function.
	 *
	 * Finally, the code destroys the parameter list and frees the JSON
	 * object.
	 */
	if (!(jsonConf = loadConfigFile(config_file))) {
		syslog(LOG_INFO, "AEROD: JSON missing or corrupt");
		delete_omni_interface();
		exit (0);
	}
	struct aero_interface *nodeLink = malloc(sizeof(struct aero_interface));
	if (nodeLink == NULL) {
	    syslog(LOG_ERR, "Failed to allocate memory for nodeLink");
	    exit(EXIT_FAILURE);
	}
	if (loadInterfaceTrafficSelectors(config_file, nodetype, nodeLink) == NULL) {
	    syslog(LOG_ERR, "Failed to load interface traffic selectors");
	    free(nodeLink);
	    delete_omni_interface(); 
	    exit(EXIT_FAILURE);
	}
	if ((paramList = createParamList()) &&
	    (interfaceArray = json_object_get(jsonConf, "interface"))) {
		parseJSON(interfaceArray, paramList, jsonConf);
	} else {
		syslog(LOG_INFO, "AEROD: JSON interfaces corrupt");
		free(nodeLink);
		delete_omni_interface();
		exit (0);
	}

	current = paramList->head;
	while (current != NULL)
	{
		aeroNodeInterface *interface = current->data;
		if (verbose >= 1)
			printInterface(interface);
		current = current->next;
	}

#ifdef AERO_JSON_NOTDEF
	destroyParamList(paramList);
	json_decref(jsonConf);
#endif
	aero_init_ncache();
	aero_init_prl();

	aero_init_addrs(paramList->head);

	if (!(create_omni_interface(paramList->head))) {
		syslog(LOG_INFO, "AEROD: OMNI interface NOT created");
		exit (0);
	}

	if ((epollfd = aero_init_sockets(paramList->head)) < 0) {
		syslog(LOG_INFO, "AEROD: sockets NOT created");
		delete_omni_interface();
		exit (0);
	}

#ifdef AERO_DPDK
	if ((rte_eal_init(dpdk_argc, dpdk_argv)) < 0) {
		syslog(LOG_INFO, "AERO_DPDK: cannot init EAL");
		exit(0);
	}

	if ((mp = rte_pktmbuf_pool_create("aero", 8192, 32, 0,
		    RTE_MBUF_DEFAULT_BUF_SIZE, 0))) {

		if (!(mtest = rte_pktmbuf_alloc(mp))) {
			syslog(LOG_INFO, "AERO_DPDK: cannot allocate mbuf");
			exit(0);
		}
		syslog(LOG_INFO, "AERO_DPDK: mbuf pool created");
		rte_pktmbuf_free(mtest);
	} else {
		syslog(LOG_ERR, "AERO_DPDK: mbuf pool NOT created");
		rte_eal_cleanup();
		exit(0);
	}

	/*
	 * XXX - need to understand how to set frag_cycles below in a
	 * sensible way w/o timing out valid entries in ip_frag_find().
	 */
#ifdef AERO_NOTYET
	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1)/(MS_PER_S * MS_PER_S);
#else
	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1);
#endif
	if ((frag_tbl = rte_ip_frag_table_create(0x1000, 16, 0x1000,
                        frag_cycles, SOCKET_ID_ANY))) {
		syslog(LOG_INFO, "AERO_DPDK: frag table created");
	} else {
        	syslog(LOG_ERR, "AERO_DPDK: aero_init_frag_tbl failed");
		rte_eal_cleanup();
		exit(0);
	}

#endif

	bool exit_loop = false;
	while (!go_down && !exit_loop)
	{
	switch (nodetype)
	{
	case AERO_NODETYPE_CLIENT:
		if (!(aero_run_loop_client(epollfd)))
			break;
	case AERO_NODETYPE_PROXY:
		if (!(aero_run_loop_proxy(epollfd)))
			break;
		break;
	case AERO_NODETYPE_GATEWAY:
		if (!(aero_run_loop_gateway(epollfd)))
			break;
	default:
		syslog(LOG_INFO, "Default");
	}

	    int file_descriptor = inotify_init();
        if (file_descriptor < 0)
        {
            syslog(LOG_ERR, "inotify_init failed: %s", strerror(errno));
            exit_loop = true;
        }

        int watch_descriptor = inotify_add_watch(file_descriptor, config_file, IN_MODIFY);
        if (watch_descriptor < 0)
        {
            syslog(LOG_ERR, "inotify_add_watch failed: %s", strerror(errno));
            close(file_descriptor);
            exit_loop = true;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(file_descriptor, &rfds);
        struct timeval tv;
        tv.tv_sec = 5; // Timeout for select
        tv.tv_usec = 0;

        int retval = select(file_descriptor + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1)
        {
            perror("select()");
        }
        else if (retval)
        {
            reloadConfigFile();
        }

        close(file_descriptor);
	}
	delete_omni_interface();
#ifdef AERO_DPDK
	rte_eal_cleanup();
#endif

	if (pid_file)
	{
		if (unlink(pid_file) < 0)
			syslog(LOG_WARNING, "cannot unlink pid file: %s",
				   strerror(errno));
	}
	closelog();

	return 0;
}
