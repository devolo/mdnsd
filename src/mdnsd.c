/*
 * Copyright (c) 2003  Jeremie Miller <jer@jabber.org>
 * Copyright (c) 2016-2022  Joachim Wiberg <troglobit@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the copyright holders nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <getopt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "mcsock.h"
#include "mdnsd.h"

#define SYS_INTERVAL 10		/* System inteface poll interval */

volatile sig_atomic_t running = 1;
volatile sig_atomic_t reload = 0;
char *prognm      = PACKAGE_NAME;
char *hostnm      = NULL;
char *ifname      = NULL;
char *path        = NULL;
int   background  = 1;
int   logging     = 1;
int   ttl         = 255;


void mdnsd_conflict(char *name, int type, void *arg)
{
	struct iface *iface = (struct iface *)arg;

	WARN("%s: conflicting name detected %s for type %d, reloading config ...", iface->ifname, name, type);
	if (!reload) {
		iface->hostid++;
		reload = 1;
	}
}

static void record_received(const struct resource *r, void *data)
{
	char ipinput[INET6_ADDRSTRLEN];

	switch(r->type) {
	case QTYPE_A:
		inet_ntop(AF_INET, &(r->known.a.ip), ipinput, INET_ADDRSTRLEN);
		DBG("Got %s: A %s->%s", r->name, r->known.a.name, ipinput);
		break;

	case QTYPE_AAAA:
		inet_ntop(AF_INET6, &(r->known.aaaa.ip6), ipinput, INET6_ADDRSTRLEN);
		DBG("Got %s: AAAA %s->%s", r->name, r->known.aaaa.name, ipinput);
		break;

	case QTYPE_NS:
		DBG("Got %s: NS %s", r->name, r->known.ns.name);
		break;

	case QTYPE_CNAME:
		DBG("Got %s: CNAME %s", r->name, r->known.cname.name);
		break;

	case QTYPE_PTR:
		DBG("Got %s: PTR %s", r->name, r->known.ptr.name);
		break;

	case QTYPE_TXT:
		DBG("Got %s: TXT %s", r->name, r->rdata);
		break;

	case QTYPE_SRV:
		DBG("Got %s: SRV %d %d %d %s", r->name, r->known.srv.priority,
		    r->known.srv.weight, r->known.srv.port, r->known.srv.name);
		break;

	default:
		DBG("Got %s: unknown", r->name);

	}
}

static void free_iface(struct iface *iface)
{
	mdnsd_shutdown(iface->mdns);
	mdnsd_free(iface->mdns);
	if (iface->sd4 >= 0)
		close(iface->sd4);

	mdnsd_shutdown(iface->mdns6);
	mdnsd_free(iface->mdns6);
	if (iface->sd6 >= 0)
		close(iface->sd6);
}


/* Create a multicast socket and bind it to the given interface. */
static int multicast_socket(struct iface *iface, int domain, unsigned char ttl)
{
	struct ifnfo ifa = { 0 };
	memcpy(ifa.ifname, iface->ifname, sizeof(ifa.ifname));
	ifa.ifindex = iface->ifindex;

	if (domain == AF_INET6) {
		return mdns_ipv6_socket(&ifa, ttl);
	}

	ifa.inaddr = iface->inaddr;
	return mdns_ipv4_socket(&ifa, ttl);
}


static void setup_iface(struct iface *iface)
{
	if (!iface->changed)
		return;

	if (iface->unused) {
		free_iface(iface);
		return;
	}

	/* Set up IPv4 domain if it is active on the interface */
	if (! is_zeronet(&iface->inaddr)) {
		if (!iface->mdns) {
			iface->mdns = mdnsd_new(QCLASS_IN, 1000);
			if (!iface->mdns) {
				ERR("Failed creating IPv4 mDNS context for interface %s: %s", iface->ifname, strerror(errno));
				exit(1);
			}

			mdnsd_set_address(iface->mdns, iface->inaddr);
			mdnsd_set_ipv6_address(iface->mdns, iface->in6addr);
			conf_init(iface, iface->mdns, path, hostnm);
			mdnsd_register_receive_callback(iface->mdns, record_received, NULL);
		}

		if (iface->sd4 < 0) {
			iface->sd4 = multicast_socket(iface, AF_INET, (unsigned char)ttl);
			if (iface->sd4 < 0) {
				ERR("Failed creating IPv4 socket: %s", strerror(errno));
				exit(1);
			}
		}
	}


	/* Set up IPv6 domain if it is active on the interface */
	if (! IN6_IS_ADDR_UNSPECIFIED(&iface->in6addr)) {
		if (!iface->mdns6) {
			iface->mdns6 = mdnsd_new(QCLASS_IN, 1000);
			if (!iface->mdns6) {
				ERR("Failed creating IPv6 mDNS context for interface %s: %s", iface->ifname, strerror(errno));
				exit(1);
			}

			mdnsd_set_address(iface->mdns6, iface->inaddr);
			mdnsd_set_ipv6_address(iface->mdns6, iface->in6addr);
			conf_init(iface, iface->mdns6, path, hostnm);
			mdnsd_register_receive_callback(iface->mdns6, record_received, NULL);
		}

		if (iface->sd6 < 0) {
			iface->sd6 = multicast_socket(iface, AF_INET6, (unsigned char)ttl);
			if (iface->sd6 < 0) {
				ERR("Failed creating socket: %s", strerror(errno));
				exit(1);
			}
		}
	}

	if (iface->mdns) {
		mdnsd_set_address(iface->mdns, iface->inaddr);
		mdnsd_set_ipv6_address(iface->mdns, iface->in6addr);
	}
	if (iface->mdns6) {
		mdnsd_set_address(iface->mdns6, iface->inaddr);
		mdnsd_set_ipv6_address(iface->mdns6, iface->in6addr);
	}
	iface->changed = 0;
}

static int sys_timeout(int *timeout)
{
	static struct timespec before;
	struct timespec now;

	if (*timeout == 0) {
		clock_gettime(CLOCK_MONOTONIC, &before);
		*timeout = SYS_INTERVAL;
	} else {
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (before.tv_sec + SYS_INTERVAL <= now.tv_sec) {
			before = now;
			return 1;
		}
	}

	return 0;
}

static void sys_init(void)
{
	struct iface *iface;

	/* Initialize or check if IP address changed, needed to update A records */
	iface_init(ifname);

	for (iface = iface_iterator(1); iface; iface = iface_iterator(0))
		setup_iface(iface);
}

static void done(int signo)
{
	running = 0;
}

static void reconf(int signo)
{
	reload = 1;
}

static void sig_init(void)
{
	signal(SIGINT, done);
	signal(SIGHUP, reconf);
	signal(SIGQUIT, done);
	signal(SIGTERM, done);
}


static int usage(int code)
{
	printf("Usage: %s [-hnsv] [-i IFACE] [-l LEVEL] [-t TTL] [PATH]\n"
	       "\n"
	       "Options:\n"
	       "    -h        This help text\n"
	       "    -i IFACE  Interface to announce services on, and get address from\n"
	       "    -l LEVEL  Set log level: none, err, notice (default), info, debug\n"
	       "    -n        Run in foreground, do not detach from controlling terminal\n"
	       "    -s        Use syslog even if running in foreground\n"
	       "    -t TTL    Set TTL of mDNS packets, default: 1 (link-local only)\n"
	       "    -v        Show program version\n"
	       "\n"
	       "Arguments:\n"
	       "    PATH      Path to mDNS-SD .service files, default: /etc/mdns.d\n"
	       "\n"
	       "Bug report address: %-40s\n", prognm, PACKAGE_BUGREPORT);

	return code;
}

static char *progname(char *arg0)
{
       char *nm;

       nm = strrchr(arg0, '/');
       if (nm)
	       nm++;
       else
	       nm = arg0;

       return nm;
}

int main(int argc, char *argv[])
{
	struct timeval tv = { 0 };
	struct iface *iface;
	fd_set fds;
	int timeout = 0;
	int c, rc, rc6;

	prognm = progname(argv[0]);
	while ((c = getopt(argc, argv, "H:hi:l:nst:v?")) != EOF) {
		switch (c) {
		case 'H':
			hostnm = optarg;
			break;

		case 'h':
		case '?':
			return usage(0);

		case 'i':
			ifname = optarg;
			break;

		case 'l':
			if (-1 == mdnsd_log_level(optarg))
				return usage(1);
			break;

		case 'n':
			background = 0;
			logging--;
			break;

		case 's':
			logging++;
			break;

		case 't':
			/* XXX: Use strtonum() instead */
			ttl = atoi(optarg);
			if (ttl < 1 || ttl > 255)
				return usage(1);
			break;

		case 'v':
			puts(PACKAGE_VERSION);
			return 0;

		default:
			break;
		}
	}

	if (optind < argc)
		path = argv[optind];
	else
		path = "/etc/mdns.d";

	if (logging > 0)
		mdnsd_log_open(prognm);

	if (background) {
		DBG("Daemonizing ...");
		if (-1 == daemon(0, 0)) {
			ERR("Failed daemonizing: %s", strerror(errno));
			return 1;
		}
	}

	NOTE("%s starting.", PACKAGE_STRING);
	sig_init();
	sys_init();
	pidfile(PACKAGE_NAME);

	while (running) {
		int nfds = 0;

		FD_ZERO(&fds);
		for (iface = iface_iterator(1); iface; iface = iface_iterator(0)) {
			if ((iface->sd4 < 0 && iface->sd6 < 0) || iface->unused)
				continue;

			if (iface->sd4 >= 0) {
				FD_SET(iface->sd4, &fds);
				if (iface->sd4 > nfds)
					nfds = iface->sd4;
			}
			if (iface->sd6 >= 0) {
				FD_SET(iface->sd6, &fds);
				if (iface->sd6 > nfds)
					nfds = iface->sd6;
			}
		}

		if (nfds > 0)
			nfds++;

		DBG("Going to sleep for %d sec ...", (int)tv.tv_sec);
		rc = select(nfds, &fds, NULL, NULL, &tv);
		if ((rc < 0 && EINTR == errno) || reload) {
			if (!running)
				break;
			if (reload) {
				sys_init();
				for (iface = iface_iterator(1); iface; iface = iface_iterator(0)) {
					if (iface->mdns) {
						records_clear(iface->mdns);
						conf_init(iface, iface->mdns, path, hostnm);
					}
					if (iface->mdns6) {
						records_clear(iface->mdns6);
						conf_init(iface, iface->mdns6, path, hostnm);
					}
				}
				pidfile(PACKAGE_NAME);
				reload = 0;
			}

			continue;
		}

		if (sys_timeout(&timeout))
		    sys_init();

		tv.tv_sec = timeout;
		for (iface = iface_iterator(1); iface; iface = iface_iterator(0)) {
			struct timeval next;

			if (iface->unused)
				continue;

			rc = rc6 = 0;
			if (iface->mdns && iface->sd4 >= 0) {
				DBG("Checking interface %s for IPv4 activity ...", iface->ifname);

				rc = mdnsd_step(iface->mdns, iface->sd4, FD_ISSET(iface->sd4, &fds), true, &next);
				if (!rc) {
					if (tv.tv_sec > next.tv_sec)
						tv = next;
				}

				if (rc == 1)
					ERR("Failed reading from IPv4 socket %d: %s", errno, strerror(errno));
				if (rc == 2)
					ERR("Failed writing to IPv4 socket: %s", strerror(errno));
			}

			if (iface->mdns6 && iface->sd6 >= 0) {
				DBG("Checking interface %s for IPv6 activity ...", iface->ifname);

				rc6 = mdnsd_step(iface->mdns6, iface->sd6, FD_ISSET(iface->sd6, &fds), true, &next);
				if (!rc6) {
					if (tv.tv_sec > next.tv_sec)
						tv = next;
				}

				if (rc6 == 1)
					ERR("Failed reading from IPv6 socket %d: %s", errno, strerror(errno));
				if (rc6 == 2)
					ERR("Failed writing to IPv6 socket: %s", strerror(errno));
			}


			if (!rc || !rc6)  /* Continue as long as one socket can successfully send/receive */
				continue;

			free_iface(iface);
		}
	}

	NOTE("%s exiting.", PACKAGE_STRING);
	for (iface = iface_iterator(1); iface; iface = iface_iterator(0))
		free_iface(iface);
	iface_exit();

	return 0;
}
