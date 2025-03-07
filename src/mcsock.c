/*
 * Copyright (c) 2022  Florian Zschocke
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

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "libmdnsd/mdnsd.h"
#include "mcsock.h"



static struct in_addr get_addr(const char *ifname)
{
	struct ifaddrs *ifaddr, *ifa;
	struct in_addr addr;
	addr.s_addr = htonl(INADDR_ANY);

	if (getifaddrs(&ifaddr) < 0) {
		WARN("Failed getting interfaces: %s", strerror(errno));
		return addr;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET &&
			strcmp(ifname, ifa->ifa_name) == 0) {
			addr = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			break;
		}
	}

	freeifaddrs(ifaddr);
	return addr;
}


static int mc_socket(struct ifnfo *iface, unsigned char ttl)
{
#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
	struct ip_mreqn imr ={ 0 };
#else
	struct ip_mreq imr = { 0 };
	imr.imr_interface.s_addr = htonl(INADDR_ANY);
#endif

	const int on = 1;
	const int off = 0;

	struct sockaddr_in sin;
	socklen_t len;
	int unicast_ttl = 255;
	int bufsiz;
	int sd;


	sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sd < 0) {
		ERR("Failed creating UDP socket: %s", strerror(errno));
		return -1;
	}

#ifdef SO_REUSEPORT
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)))
		WARN("Failed setting SO_REUSEPORT: %s", strerror(errno));
#endif
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		WARN("Failed setting SO_REUSEADDR: %s", strerror(errno));

	/* Double the size of the receive buffer (getsockopt() returns the double) */
	len = sizeof(bufsiz);
	if (!getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &bufsiz, &len)) {
		if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &bufsiz, sizeof(bufsiz)))
			INFO("Failed doubling the size of the receive buffer: %s", strerror(errno));
	}

	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on)))
		WARN("Failed enabling IP_MULTICAST_LOOP on %s: %s", iface->ifname, strerror(errno));

	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_ALL, &off, sizeof(off)))
		WARN("Failed disabling IP_MULTICAST_ALL on %s: %s", iface->ifname, strerror(errno));

	/*
	 * All traffic on mDNS is link-local only, so the default
	 * TTL is set to 1.  Some users may however want to route mDNS.
	 */
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)))
		WARN("Failed setting IP_MULTICAST_TTL to %d: %s", ttl, strerror(errno));

	/* mDNS also supports unicast, so we need a relevant TTL there too */
	if (setsockopt(sd, IPPROTO_IP, IP_TTL, &unicast_ttl, sizeof(unicast_ttl)))
		WARN("Failed setting IP_TTL to %d: %s", unicast_ttl, strerror(errno));


	if (iface) {
		if (iface->ifindex != 0 && iface->inaddr.s_addr == 0) {
			iface->inaddr = get_addr(iface->ifname);
		}
		/* Set interface for outbound multicast */
#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
		imr.imr_ifindex   = iface->ifindex;
		if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &imr, sizeof(imr)))
			WARN("Failed setting IP_MULTICAST_IF to %d: %s", iface->ifindex, strerror(errno));
#else
		imr.imr_interface = iface->inaddr;
		if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &(iface->inaddr), sizeof(struct in_addr)))
			WARN("Failed setting IP_MULTICAST_IF to %s: %s", inet_ntoa(iface->inaddr), strerror(errno));
#endif

		/* Filter inbound traffic from anyone (ANY) to port 5353 on ifname */
		if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &iface->ifname, strlen(iface->ifname)))
			INFO("Failed setting SO_BINDTODEVICE on %s: %s", iface->ifname, strerror(errno));
	}

	/*
	 * Join mDNS link-local group on the given interface, that way
	 * we can receive multicast without a proper net route (default
	 * route or a 224.0.0.0/24 net route).
	 */
	imr.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr)))
		WARN("Failed joining mDNS group 224.0.0.251: %s", strerror(errno));


	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(5353);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin))) {
		close(sd);
		ERR("Failed binding socket to *:5353: %s", strerror(errno));
		return -1;
	}
	INFO("Bound to *:5353 on iface %s", iface->ifname);


	return sd;
}


int mdns_socket(struct ifnfo *iface, unsigned char ttl)
{
	/* Default to TTL of 1 for mDNS as it is link-local */
	if (ttl == 0)
		ttl = 1;

	return mc_socket(iface, ttl);
}
