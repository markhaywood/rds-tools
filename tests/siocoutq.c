/*
 * rds unit tests
 *
 * Test reachability of a remote RDS node by sending a packet to port 0.
 *
 * Copyright (c) 2023 Oracle and/or its affiliates. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <net/rds.h>

#define die(fmt...) do {		\
	fprintf(stderr, fmt);		\
	exit(1);			\
} while (0)

#define die_errno(fmt, args...) do {				\
	fprintf(stderr, fmt ", errno: %d (%s)\n", ##args , errno,\
		strerror(errno));				\
	exit(1);						\
} while (0)

/*
 * Used to represent both IPv4 and IPv6 sockaddr.
 */
union sockaddr_ip {
	struct sockaddr_in	addr4;
	struct sockaddr_in6	addr6;
};

static unsigned long	opt_count;
static union sockaddr_ip	opt_srcaddr;
static union sockaddr_ip	opt_dstaddr;
static unsigned long	opt_tos = 0;
static bool use_siocoutq = false;

/* For reasons of simplicity, RDS ping does not use a packet
 * payload that is being echoed, the way ICMP does.
 * Instead, we open a number of sockets on different ports, and
 * match packet sequence numbers with ports.
 */
static unsigned long nsockets = 8;
static unsigned long nsockets_min = 1;
static unsigned long nsockets_max = 32;

struct socket {
	int fd;
	unsigned int sent_id;
	struct timeval sent_ts;
	unsigned int nreplies;
};

/* returns a - b in usecs */
static inline long usec_sub(const struct timeval *a, const struct timeval *b)
{
	return (long)(((long)(a->tv_sec - b->tv_sec) * 1000000UL) +
		      a->tv_usec - b->tv_usec);
}

static int send_on_one_socket(int fd, struct sockaddr *dst,
			      int msglen, int per_sock)
{
	int ret = 0, idx;

	for (idx = 0; idx < per_sock; idx++) {
		if (sendto(fd, NULL, 0, 0, dst, msglen)) {
			ret = errno;
			break;
		}
	}
	return ret;
}

static int spin_on_one_socket(int fd)
{
	int sp_cnt = 0;
	int pend;

	do {
		if (ioctl(fd, TIOCOUTQ, &pend)) {
			sp_cnt = -errno;
			break;
		}
		sp_cnt++;
	} while(pend && sp_cnt < 100000);

	return sp_cnt;
}

static int send_on_n_sockets_seq(struct socket *nsocks, struct sockaddr *dst,
				 int n_socks, int per_sock, int msglen)
{
	int idx, ret = 0;
	int spin_count;

	for (idx = 0; idx < n_socks; idx++) {
		ret = send_on_one_socket(nsocks[idx].fd, dst,
					 msglen, per_sock);
		if (ret)
			break;
		if (use_siocoutq) {
			spin_count = spin_on_one_socket(nsocks[idx].fd);
			printf("Spun for %d counts on socket %d\n", spin_count, idx);
		}
	}

	return ret;
}

static int rds_socket(union sockaddr_ip *src, union sockaddr_ip *dst)
{
	socklen_t alen;
	int fd;

	fd = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (fd < 0)
		die_errno("unable to create RDS socket");

	/* Guess the local source addr if not given. */
	if (src->addr4.sin_family == AF_UNSPEC) {
		int ufd;
		in_port_t *dst_port;

		ufd = socket(dst->addr4.sin_family, SOCK_DGRAM, 0);
		if (ufd < 0)
			die_errno("unable to create UDP socket");

		switch (dst->addr4.sin_family) {
		case AF_INET:
			dst_port = &dst->addr4.sin_port;
			*dst_port = htons(1);
			alen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			dst_port = &dst->addr6.sin6_port;
			*dst_port = htons(1);
			alen = sizeof(struct sockaddr_in6);
			break;
		default:
			die_errno("unknown destination address family");
			break;
		}

		if (connect(ufd, (struct sockaddr *)dst, alen) < 0) {
			char name[INET6_ADDRSTRLEN];
			socklen_t name_len = sizeof(name);

			if (dst->addr4.sin_family == AF_INET) {
				(void) inet_ntop(AF_INET, &dst->addr4.sin_addr,
						 name, name_len);
			} else {
				(void) inet_ntop(AF_INET6,
						 &dst->addr6.sin6_addr, name,
						 name_len);
			}
			die_errno("unable to connect to %s", name);
		}

		/* Remember to reset the destination port. */
		*dst_port = 0;

		if (getsockname(ufd, (struct sockaddr *)src, &alen) < 0)
			die_errno("getsockname failed");

		close(ufd);
	}

	switch (src->addr4.sin_family) {
	case AF_INET:
		src->addr4.sin_port = 0;
		alen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		src->addr6.sin6_port = 0;
		alen = sizeof(struct sockaddr_in6);
		break;
	default:
		die("unknown source address family");
		break;
	}

	if (bind(fd, (struct sockaddr *)src, alen) != 0)
		die_errno("bind() failed");

	if (opt_tos && ioctl(fd, SIOCRDSSETTOS, &opt_tos)) 
		die_errno("ERROR: failed to set TOS\n");

	return fd;
}

static int run_test(void)
{
	struct timeval	start, end;
	struct socket	socket[nsockets];
	socklen_t	dst_len;
	float		tdiff;
	int		i;

	for (i = 0; i < nsockets; ++i) {
		int fd;

		fd = rds_socket(&opt_srcaddr, &opt_dstaddr);
		socket[i].fd = fd;
	}

	/* Family check is already done earlier - just set length. */
	if (opt_dstaddr.addr4.sin_family == AF_INET)
		dst_len = sizeof(struct sockaddr_in);
	else
		dst_len = sizeof(struct sockaddr_in6);

	gettimeofday(&start, NULL);
	send_on_n_sockets_seq(socket, (struct sockaddr *)&opt_dstaddr,
			      nsockets, opt_count, dst_len);
	gettimeofday(&end, NULL);
	tdiff = usec_sub(&end, &start) / 1000;
	printf("%d sockets took %f msec to send and spin for %d packets\n",
	       (int)nsockets, tdiff, (int)(opt_count * nsockets));
	/* Program exit code: signal success if we received any response. */
	return 0;
}

static void usage(const char *complaint)
{
        fprintf(stderr, "siocoutq version %s\n", RDS_VERSION);

	fprintf(stderr,
		"%s\nUsage: siocoutq [options] dst_addr\n"
		"Options:\n"
		" -c count      limit packet count\n"
		" -n number     number of RDS sockets used\n"
		" -I interface  source IP address\n"
		" -Q tos	type of service\n"
		" -s 		Use SIOCOUTQ\n",
		complaint);
	exit(1);
}

static int parse_long(const char *ptr, unsigned long *ret)
{
	unsigned long long val;
	char *endptr;

	val = strtoull(ptr, &endptr, 0);
	switch (*endptr) {
	case 'k': case 'K':
		val <<= 10;
		endptr++;
		break;

	case 'm': case 'M':
		val <<= 20;
		endptr++;
		break;

	case 'g': case 'G':
		val <<= 30;
		endptr++;
		break;
	}

	if (*endptr)
		return 0;

	*ret = val;
	return 1;
}

/*
 * We just return the address here without checking if the returned address
 * matches the correct family.  The caller should do the check instead.
 */
static int parse_addr(const char *ptr, union sockaddr_ip *ret)
{
	struct addrinfo *ainfo, hints = {.ai_flags = AI_NUMERICHOST,};

	/* passing hints to avoid netlink syscall as possible */
	if (getaddrinfo(ptr, NULL, &hints, &ainfo) != 0) {
		if (getaddrinfo(ptr, NULL, NULL, &ainfo) != 0)
			return 0;
	}

	/* Just use the first one returned. */
	switch (ainfo->ai_family) {
	case AF_INET:
	case AF_INET6:
		(void) memcpy(ret, ainfo->ai_addr, ainfo->ai_addrlen);
		break;
	default:
		die("getaddrinfo() returns unsupported family: %d\n",
		    ainfo->ai_family);
		break;
	}
	freeaddrinfo(ainfo);
	return 1;
}

int main(int argc, char **argv)
{
	int c;
	bool src_set = false;
	bool num_sock_set = false;

	while ((c = getopt(argc, argv, "c:n:I:Q:s")) != -1) {
		switch (c) {
		case 'c':
			if (!parse_long(optarg, &opt_count))
				die("Bad packet count <%s>\n", optarg);
			break;

		case 'n':
			if (!parse_long(optarg, &nsockets) ||
			    nsockets < nsockets_min || nsockets > nsockets_max)
				die("Invalid number of sockets <%s>\n",
				    optarg);
			num_sock_set = true;
			break;

		case 'I':
			if (!parse_addr(optarg, &opt_srcaddr))
				die("Unknown source address <%s>\n", optarg);
			src_set = true;
			break;

		case 'Q':
			if (!parse_long(optarg, &opt_tos))
				die("Bad tos <%s>\n", optarg);
			break;
		case 's':
			use_siocoutq = true;
			break;
		default:
			usage("Unknown option");
		}
	}

	if (optind + 1 != argc)
		usage("Missing destination address");
	if (!parse_addr(argv[optind], &opt_dstaddr))
		die("Cannot parse destination address <%s>\n", argv[optind]);

	if (src_set && opt_dstaddr.addr4.sin_family !=
	    opt_srcaddr.addr4.sin_family)
		die("Source and destination address family are not the same\n");

	if (!num_sock_set && opt_count && opt_count < nsockets)
		nsockets = opt_count;

	return run_test();
}
