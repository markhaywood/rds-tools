/*
 * Copyright (c) 2008, 2018 Oracle and/or its affiliates. All rights reserved.
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
 *
 */

#ifndef _LINUX_RDS_H
#define _LINUX_RDS_H

/* This is a copy of include/uapi/linux/rds.h from the UEK kernel source.
 * Note that the u8 and u64 types are changed to the C standard uint8_t and
 * uint64_t respectively.
 */

#include <linux/types.h>
#include <limits.h>
#include <linux/net.h>
#include <time.h>
/* XXX <net/sock.h> was included as part of NETFILTER support (commit f13bbf62)
 * but <net/sock.h> is not exported to uapi, although <linux/rds.h> is
 * (in theory). Is <net/sock.h> needed for user-apps that use netfilter?
 */
#ifdef __KERNEL__
#include <net/sock.h>
#endif

/* These sparse annotated types shouldn't be in any user
 * visible header file. We should clean this up rather
 * than kludging around them. */
#ifndef __KERNEL__
#define __be16	u_int16_t
#define __be32	u_int32_t
#define __be64	u_int64_t
#endif

#define RDS_IB_ABI_VERSION		0x301

#define	SOL_RDS				276
/*
 * setsockopt/getsockopt for SOL_RDS
 */
#define RDS_CANCEL_SENT_TO		1
#define RDS_GET_MR			2
#define RDS_FREE_MR			3
/* deprecated: RDS_BARRIER 4 */
#define RDS_RECVERR			5
#define RDS_CONG_MONITOR		6
#define RDS_GET_MR_FOR_DEST		7
#define RDS_CONN_RESET                  8
#define SO_RDS_TRANSPORT		9
/* Socket option to tap receive path latency
 *	SO_RDS: SO_RDS_MSG_RXPATH_LATENCY
 *	Format used struct rds_rx_trace_so
 */
#define SO_RDS_MSG_RXPATH_LATENCY	10
#define RDS6_CONN_RESET			11

/* supported values for SO_RDS_TRANSPORT */
#define	RDS_TRANS_IB	0
#define	RDS_TRANS_TCP	2
#define	RDS_TRANS_COUNT	3
#define	RDS_TRANS_NONE	(~0)

/*
 * ioctl commands for SOL_RDS
*/
#define SIOCRDSSETTOS                   (SIOCPROTOPRIVATE)
#define SIOCRDSGETTOS                   (SIOCPROTOPRIVATE + 1)
#define SIOCRDSENABLENETFILTER          (SIOCPROTOPRIVATE + 2)

#define IPPROTO_OKA (142)

typedef u_int8_t         rds_tos_t;

/* RDS message Receive Path Latency points */
enum rds_message_rxpath_latency {
	RDS_MSG_RX_HDR_TO_DGRAM_START = 0,
	RDS_MSG_RX_DGRAM_REASSEMBLE,
	RDS_MSG_RX_DGRAM_DELIVERED,
	RDS_MSG_RX_DGRAM_TRACE_MAX
};

struct rds_rx_trace_so {
	uint8_t rx_traces;
	uint8_t rx_trace_pos[RDS_MSG_RX_DGRAM_TRACE_MAX];
};

struct rds_cmsg_rx_trace {
	uint8_t rx_traces;
	uint8_t rx_trace_pos[RDS_MSG_RX_DGRAM_TRACE_MAX];
	uint64_t rx_trace[RDS_MSG_RX_DGRAM_TRACE_MAX];
};

/*
 * Control message types for SOL_RDS.
 *
 * CMSG_RDMA_ARGS (sendmsg)
 *	Request a RDMA transfer to/from the specified
 *	memory ranges.
 *	The cmsg_data is a struct rds_rdma_args.
 * RDS_CMSG_RDMA_DEST (recvmsg, sendmsg)
 *	Kernel informs application about intended
 *	source/destination of a RDMA transfer
 * RDS_CMSG_RDMA_MAP (sendmsg)
 *	Application asks kernel to map the given
 *	memory range into a IB MR, and send the
 *	R_Key along in an RDS extension header.
 *	The cmsg_data is a struct rds_get_mr_args,
 *	the same as for the GET_MR setsockopt.
 * RDS_CMSG_RDMA_SEND_STATUS (recvmsg)
 *	Returns the status of a completed RDMA/async send operation.
 * RDS_CMSG_RXPATH_LATENCY(recvmsg)
 *	Returns rds message latencies in various stages of receive
 *	path in nS. Its set per socket using SO_RDS_MSG_RXPATH_LATENCY
 *	socket option. Legitimate points are defined in
 *	enum rds_message_rxpath_latency. More points can be added in
 *	future. CSMG format is struct rds_cmsg_rx_trace.
 */
#define RDS_CMSG_RDMA_ARGS		1
#define RDS_CMSG_RDMA_DEST		2
#define RDS_CMSG_RDMA_MAP		3
#define RDS_CMSG_RDMA_SEND_STATUS	4
#define RDS_CMSG_CONG_UPDATE		5
#define RDS_CMSG_ATOMIC_FADD		6
#define RDS_CMSG_ATOMIC_CSWP		7
#define RDS_CMSG_MASKED_ATOMIC_FADD	8
#define RDS_CMSG_MASKED_ATOMIC_CSWP	9
#define RDS_CMSG_ASYNC_SEND		10
#define RDS_CMSG_RXPATH_LATENCY		11

#define RDS_INFO_FIRST			10000
#define RDS_INFO_COUNTERS		10000
#define RDS_INFO_CONNECTIONS		10001
/* 10002 aka RDS_INFO_FLOWS is deprecated */
#define RDS_INFO_SEND_MESSAGES		10003
#define RDS_INFO_RETRANS_MESSAGES       10004
#define RDS_INFO_RECV_MESSAGES          10005
#define RDS_INFO_SOCKETS                10006
#define RDS_INFO_TCP_SOCKETS            10007
#define RDS_INFO_IB_CONNECTIONS		10008
#define RDS_INFO_CONNECTION_STATS	10009
#define RDS_INFO_IWARP_CONNECTIONS	10010

/* PF_RDS6 options */
#define RDS6_INFO_CONNECTIONS		10011
#define RDS6_INFO_SEND_MESSAGES		10012
#define RDS6_INFO_RETRANS_MESSAGES	10013
#define RDS6_INFO_RECV_MESSAGES		10014
#define RDS6_INFO_SOCKETS		10015
#define RDS6_INFO_TCP_SOCKETS		10016
#define RDS6_INFO_IB_CONNECTIONS	10017
#define RDS_INFO_CONN_PATHS		10020
#define RDS6_INFO_CONN_PATHS		10021

#define RDS_INFO_LAST			10021

struct rds_info_counter {
	u_int8_t	name[32];
	u_int64_t	value;
} __attribute__((packed));

#define RDS_INFO_CONNECTION_FLAG_SENDING	0x01
#define RDS_INFO_CONNECTION_FLAG_CONNECTING	0x02
#define RDS_INFO_CONNECTION_FLAG_CONNECTED	0x04
#define RDS_INFO_CONNECTION_FLAG_ERROR		0x08

#define TRANSNAMSIZ	16

struct rds_info_connection {
	u_int64_t	next_tx_seq;
	u_int64_t	next_rx_seq;
	__be32		laddr;
	__be32		faddr;
	u_int8_t	transport[TRANSNAMSIZ];		/* null term ascii */
	u_int8_t	flags;
	u_int8_t        tos;
} __attribute__((packed));

struct rds6_info_connection {
	uint64_t	next_tx_seq;
	uint64_t	next_rx_seq;
	struct in6_addr	laddr;
	struct in6_addr	faddr;
	uint8_t		transport[TRANSNAMSIZ];		/* null term ascii */
	uint8_t		flags;
	uint8_t		tos;
} __attribute__((packed));

#define RDS_INFO_MESSAGE_FLAG_ACK               0x01
#define RDS_INFO_MESSAGE_FLAG_FAST_ACK          0x02

struct rds_info_message {
	u_int64_t	seq;
	u_int32_t	len;
	__be32		laddr;
	__be32		faddr;
	__be16		lport;
	__be16		fport;
	u_int8_t	flags;
	u_int8_t        tos;
} __attribute__((packed));

struct rds6_info_message {
	uint64_t	seq;
	uint32_t	len;
	struct in6_addr	laddr;
	struct in6_addr	faddr;
	__be16		lport;
	__be16		fport;
	uint8_t		flags;
	uint8_t		tos;
} __attribute__((packed));

struct rds_info_socket {
	u_int32_t	sndbuf;
	__be32		bound_addr;
	__be32		connected_addr;
	__be16		bound_port;
	__be16		connected_port;
	u_int32_t	rcvbuf;
	u_int64_t	inum;
	pid_t		pid;
	int32_t		cong;
} __attribute__((packed));

struct rds6_info_socket {
	uint32_t	sndbuf;
	struct in6_addr	bound_addr;
	struct in6_addr	connected_addr;
	__be16		bound_port;
	__be16		connected_port;
	uint32_t	rcvbuf;
	uint64_t	inum;
	pid_t		pid;
	int32_t		cong;
} __attribute__((packed));

struct rds_info_tcp_socket {
	__be32          local_addr;
	__be16          local_port;
	__be32          peer_addr;
	__be16          peer_port;
	u_int64_t       hdr_rem;
	u_int64_t       data_rem;
	u_int32_t       last_sent_nxt;
	u_int32_t       last_expected_una;
	u_int32_t       last_seen_una;
} __attribute__((packed));

struct rds6_info_tcp_socket {
	struct in6_addr	local_addr;
	__be16		local_port;
	struct in6_addr	peer_addr;
	__be16		peer_port;
	uint64_t	hdr_rem;
	uint64_t	data_rem;
	uint32_t	last_sent_nxt;
	uint32_t	last_expected_una;
	uint32_t	last_seen_una;
} __attribute__((packed));

#define RDS_IB_GID_LEN	16
struct rds_info_rdma_connection {
	__be32		src_addr;
	__be32		dst_addr;
	uint8_t		src_gid[RDS_IB_GID_LEN];
	uint8_t		dst_gid[RDS_IB_GID_LEN];

	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	rdma_mr_max;
	uint32_t	rdma_mr_size;
	uint8_t         tos;
	uint8_t         sl;
	uint32_t        cache_allocs;
	uint32_t	frag;
	uint16_t        flow_ctl_post_credit;
	uint16_t        flow_ctl_send_credit;
	int32_t		qp_num;
	uint32_t        recv_alloc_ctr;
	uint32_t        recv_free_ctr;
	int32_t		dst_qp_num;
	uint32_t	send_alloc_ctr;
	uint32_t	send_free_ctr;
	uint64_t	send_bytes;
	uint64_t	recv_bytes;
	uint64_t	r_read_bytes;	/* rdma_read_bytes */
	uint64_t	r_write_bytes;	/* rdma_write_bytes */
	uint64_t	tx_poll_ts;
	uint64_t	rx_poll_ts;
	uint64_t	tx_poll_cnt;
	uint64_t	rx_poll_cnt;
	int32_t		scq_vector;
	int32_t		rcq_vector;
};

struct rds6_info_rdma_connection {
	struct in6_addr	src_addr;
	struct in6_addr	dst_addr;
	uint8_t		src_gid[RDS_IB_GID_LEN];
	uint8_t		dst_gid[RDS_IB_GID_LEN];

	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	rdma_mr_max;
	uint32_t	rdma_mr_size;
	uint8_t         tos;
	uint8_t         sl;
	uint32_t        cache_allocs;
	uint32_t	frag;
	uint16_t        flow_ctl_post_credit;
	uint16_t        flow_ctl_send_credit;
	int32_t		qp_num;
	uint32_t	recv_alloc_ctr;
	uint32_t	recv_free_ctr;
	int32_t		dst_qp_num;
	uint32_t	send_alloc_ctr;
	uint32_t	send_free_ctr;
	uint64_t	send_bytes;
	uint64_t	recv_bytes;
	uint64_t	r_read_bytes;	/* rdma_read_bytes */
	uint64_t	r_write_bytes;	/* rdma_write_bytes */
	uint64_t	tx_poll_ts;
	uint64_t	rx_poll_ts;
	uint64_t	tx_poll_cnt;
	uint64_t	rx_poll_cnt;
	int32_t		scq_vector;
	int32_t		rcq_vector;
};

struct rds_path_info {
        time_t        attempt_time;
        time_t        connect_time;
        time_t        reset_time;
        uint32_t        disconnect_reason;
        uint32_t        connect_attempts;
        unsigned int    index;
        u_int8_t        flags;
} __attribute__((packed));

struct rds_info_connection_paths {
        struct in6_addr local_addr;
        struct in6_addr peer_addr;
        u_int8_t        transport[TRANSNAMSIZ];
        uint8_t         tos;
        u_int8_t        npaths;
        struct rds_path_info paths[];
} __attribute__((packed));

/*
 * Congestion monitoring.
 * Congestion control in RDS happens at the host connection
 * level by exchanging a bitmap marking congested ports.
 * By default, a process sleeping in poll() is always woken
 * up when the congestion map is updated.
 * With explicit monitoring, an application can have more
 * fine-grained control.
 * The application installs a 64bit mask value in the socket,
 * where each bit corresponds to a group of ports.
 * When a congestion update arrives, RDS checks the set of
 * ports that are now uncongested against the list bit mask
 * installed in the socket, and if they overlap, we queue a
 * cong_notification on the socket.
 *
 * To install the congestion monitor bitmask, use RDS_CONG_MONITOR
 * with the 64bit mask.
 * Congestion updates are received via RDS_CMSG_CONG_UPDATE
 * control messages.
 *
 * The correspondence between bits and ports is
 *	1 << (portnum % 64)
 */
#define RDS_CONG_MONITOR_SIZE	64
#define RDS_CONG_MONITOR_BIT(port)  (((unsigned int) port) % RDS_CONG_MONITOR_SIZE)
#define RDS_CONG_MONITOR_MASK(port) (1ULL << RDS_CONG_MONITOR_BIT(port))

/*
 * RDMA related types
 */

/*
 * This encapsulates a remote memory location.
 * In the current implementation, it contains the R_Key
 * of the remote memory region, and the offset into it
 * (so that the application does not have to worry about
 * alignment).
 */
typedef u_int64_t	rds_rdma_cookie_t;

struct rds_iovec {
	u_int64_t	addr;
	u_int64_t	bytes;
};

struct rds_get_mr_args {
	struct rds_iovec vec;
	u_int64_t	cookie_addr;
	uint64_t	flags;
};

struct rds_get_mr_for_dest_args {
	struct sockaddr_storage	dest_addr;
	struct rds_iovec	vec;
	u_int64_t		cookie_addr;
	uint64_t		flags;
};

struct rds_free_mr_args {
	rds_rdma_cookie_t cookie;
	u_int64_t	flags;
};

struct rds_rdma_args {
	rds_rdma_cookie_t cookie;
	struct rds_iovec remote_vec;
	u_int64_t	local_vec_addr;
	u_int64_t	nr_local;
	u_int64_t	flags;
	u_int64_t	user_token;
};

struct rds_atomic_args {
	rds_rdma_cookie_t cookie;
	uint64_t	local_addr;
	uint64_t	remote_addr;
	uint64_t	swap_add;
	uint64_t	compare;
	u_int64_t	flags;
	u_int64_t	user_token;
};

struct rds_reset {
	u_int8_t	tos;
	struct in_addr	src;
	struct in_addr	dst;
};

struct rds6_reset {
	uint8_t	tos;
	struct in6_addr	src;
	struct in6_addr	dst;
};

struct rds_asend_args {
	u_int64_t       user_token;
	u_int64_t       flags;
};

struct rds_rdma_send_notify {
	u_int64_t	user_token;
	int32_t		status;
};

#define RDS_RDMA_SEND_SUCCESS		0
#define RDS_RDMA_REMOTE_ERROR		1
#define RDS_RDMA_SEND_CANCELED		2
#define RDS_RDMA_SEND_DROPPED		3
#define RDS_RDMA_SEND_OTHER_ERROR	4

/*
 * Common set of flags for all RDMA related structs
 */
#define RDS_RDMA_READWRITE	0x0001
#define RDS_RDMA_FENCE		0x0002	/* use FENCE for immediate send */
#define RDS_RDMA_INVALIDATE	0x0004	/* invalidate R_Key after freeing MR */
#define RDS_RDMA_USE_ONCE	0x0008	/* free MR after use */
#define RDS_RDMA_DONTWAIT	0x0010	/* Don't wait in SET_BARRIER */
#define RDS_RDMA_NOTIFY_ME	0x0020	/* Notify when operation completes */
#define RDS_RDMA_SILENT		0x0040	/* Do not interrupt remote */
#define RDS_RDMA_REMOTE_COMPLETE 0x0080 /* Notify when data is available */
#define RDS_SEND_NOTIFY_ME      0x0100  /* Notify when operation completes */

/* netfilter related components */
struct rds_nf_hdr {
	struct in6_addr	saddr;     /* source address of request */
	struct in6_addr	daddr;     /* destination address */
	__be16		sport;     /* source port number */
	__be16		dport;     /* destination port number */
	__be16		protocol;  /* rds socket protocol family to use */

#define RDS_NF_HDR_FLAG_BOTH (0x1) /* request needs to go locally and remote */
#define RDS_NF_HDR_FLAG_DONE (0x2) /* the request is consumed and done */
	__be16 flags;     /* any configuration flags */
	struct sock *sk;
};

/* pull out the 2 rdshdr from the SKB structures passed around */
#define rds_nf_hdr_dst(skb) (&(((struct rds_nf_hdr *)skb_tail_pointer((skb)))[0]))
#define rds_nf_hdr_org(skb) (&(((struct rds_nf_hdr *)skb_tail_pointer((skb)))[1]))

/* temporary hack for a family that exists in the netfilter family */
#define PF_RDS_HOOK   11

enum rds_inet_hooks {
	NF_RDS_PRE_ROUTING,
	NF_RDS_FORWARD_ERROR,
	NF_RDS_NUMHOOKS
};

enum rds_hook_priorities {
	NF_RDS_PRI_FIRST = INT_MIN,
	NF_RDS_PRI_OKA   = 0,
	NF_RDS_PRI_LAST  = INT_MAX
};


#endif /* IB_RDS_H */
