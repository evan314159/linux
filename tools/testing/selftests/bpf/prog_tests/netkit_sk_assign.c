// SPDX-License-Identifier: GPL-2.0
/*
 * Test bpf_sk_assign() from netkit programs, which run on the xmit path
 * and hand the skb to the backlog of the peer device, and
 * IFLA_NETKIT_BPF_CTX, which controls the context that programs of the
 * primary device run in.
 */
#include <uapi/linux/if_link.h>
#include <net/if.h>
#include <poll.h>
#include <test_progs.h>

#include "network_helpers.h"
#include "netlink_helpers.h"
#include "test_netkit_sk_assign.skel.h"

#define NS_HOST		"nk_sk_host"
#define NS_POD		"nk_sk_pod"
#define NK_PRIMARY	"nk1"
#define NK_PEER		"nk0"
#define VETH_SRC	"veth_src"
#define VETH_DST	"veth_dst"

#define BIND_PORT	1234
#define CONNECT_PORT	4321
#define DADDR4		"192.168.2.3"
#define DADDR6		"fd00:2::3"
#define POD_ADDR4	"10.0.0.2"

#define TIMEOUT_MS	2000

struct iplink_req {
	struct nlmsghdr  n;
	struct ifinfomsg i;
	char             buf[1024];
};

static int create_netkit(int bpf_ctx)
{
	struct rtnl_handle rth = { .fd = -1 };
	struct iplink_req req = {};
	struct rtattr *linkinfo, *data;
	const char *type = "netkit";
	int err;

	err = rtnl_open(&rth, 0);
	if (!ASSERT_OK(err, "open_rtnetlink"))
		return err;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;

	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, NK_PRIMARY,
		  strlen(NK_PRIMARY));
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, type, strlen(type));
	data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_MODE, NETKIT_L3);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_BPF_CTX, bpf_ctx);
	addattr_nest_end(&req.n, data);
	addattr_nest_end(&req.n, linkinfo);

	err = rtnl_talk(&rth, &req.n, NULL);
	ASSERT_OK(err, "talk_rtnetlink");
	rtnl_close(&rth);
	return err;
}

/* Pod netns with the netkit peer, host netns with the primary. The host
 * has a local route for DADDR{4,6} but nothing listening on CONNECT_PORT,
 * so the pod only reaches the server bound to BIND_PORT via
 * bpf_sk_assign() from the peer program.
 */
static struct nstoken *setup(int bpf_ctx)
{
	struct nstoken *tok;

	SYS(fail, "ip netns add " NS_HOST);
	SYS(fail, "ip netns add " NS_POD);

	tok = open_netns(NS_HOST);
	if (!ASSERT_OK_PTR(tok, "open_netns_host"))
		goto fail;

	SYS(fail_close, "ip link set dev lo up");
	SYS(fail_close, "sysctl -wq net.ipv4.conf.all.rp_filter=0");
	SYS(fail_close, "sysctl -wq net.ipv4.conf.default.rp_filter=0");
	/* Create before netkit, so that the ifindex of VETH_SRC cannot
	 * exist in the pod netns.
	 */
	SYS(fail_close, "ip link add " VETH_SRC " type veth peer name " VETH_DST);
	SYS(fail_close, "ip link set dev " VETH_SRC " up");
	SYS(fail_close, "ip link set dev " VETH_DST " up");

	if (create_netkit(bpf_ctx))
		goto fail_close;

	SYS(fail_close, "ip link set dev " NK_PEER " netns " NS_POD);
	SYS(fail_close, "ip link set dev " NK_PRIMARY " up");
	SYS(fail_close, "ip addr add 10.0.0.1/24 dev " NK_PRIMARY);
	SYS(fail_close, "ip -6 addr add fd00::1/64 dev " NK_PRIMARY " nodad");
	SYS(fail_close, "ip route add local " DADDR4 "/32 dev lo");
	SYS(fail_close, "ip -6 route add local " DADDR6 "/128 dev lo");

	SYS(fail_close, "ip -n " NS_POD " link set dev lo up");
	SYS(fail_close, "ip -n " NS_POD " link set dev " NK_PEER " up");
	SYS(fail_close, "ip -n " NS_POD " addr add " POD_ADDR4 "/24 dev " NK_PEER);
	SYS(fail_close, "ip -n " NS_POD " -6 addr add fd00::2/64 dev " NK_PEER " nodad");
	SYS(fail_close, "ip -n " NS_POD " route add default dev " NK_PEER);
	SYS(fail_close, "ip -n " NS_POD " -6 route add default dev " NK_PEER);

	return tok;
fail_close:
	close_netns(tok);
fail:
	SYS_NOFAIL("ip netns del " NS_HOST);
	SYS_NOFAIL("ip netns del " NS_POD);
	return NULL;
}

static void cleanup(struct nstoken *tok)
{
	close_netns(tok);
	SYS_NOFAIL("ip netns del " NS_POD);
	SYS_NOFAIL("ip netns del " NS_HOST);
}

static int accept_any(int *fds, int nr)
{
	struct pollfd pfds[2] = {};
	int i;

	for (i = 0; i < nr; i++) {
		pfds[i].fd = fds[i];
		pfds[i].events = POLLIN;
	}
	if (!ASSERT_GT(poll(pfds, nr, TIMEOUT_MS), 0, "poll"))
		return -1;
	for (i = 0; i < nr; i++)
		if (pfds[i].revents & POLLIN)
			return fds[i];
	return -1;
}

static void run_sk_assign(int family, int type, int nr_listen)
{
	const char *daddr = family == AF_INET ? DADDR4 : DADDR6;
	const char *baddr = family == AF_INET ? "127.0.0.1" : "::1";
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	struct test_netkit_sk_assign *skel;
	int *servers = NULL, srv = -1;
	int client = -1, srv_client = -1;
	struct nstoken *tok, *pod;
	char buf[] = "testing";
	char rbuf[sizeof(buf)];
	struct bpf_link *link;
	int ifindex, zero = 0;
	__u64 fd;

	tok = setup(NETKIT_BPF_CTX_RX);
	if (!tok)
		return;

	skel = test_netkit_sk_assign__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;

	ifindex = if_nametoindex(NK_PRIMARY);
	if (!ASSERT_GT(ifindex, 0, "nk_ifindex"))
		goto out;
	link = bpf_program__attach_netkit(skel->progs.peer_assign, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "attach_peer"))
		goto out;
	skel->links.peer_assign = link;

	servers = start_reuseport_server(family, type, baddr, BIND_PORT,
					 TIMEOUT_MS, nr_listen);
	if (!ASSERT_OK_PTR(servers, "start_server"))
		goto out;
	/* With SO_REUSEPORT, the receive path may pick another socket of the
	 * group than the assigned one, and drops the reference held for it.
	 */
	fd = servers[0];
	if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.server_map),
					   &zero, &fd, BPF_ANY),
		       "update_server_map"))
		goto out;

	pod = open_netns(NS_POD);
	if (!ASSERT_OK_PTR(pod, "open_netns_pod"))
		goto out;
	client = connect_to_addr_str(family, type, daddr, CONNECT_PORT, NULL);
	close_netns(pod);
	if (!ASSERT_GE(client, 0, "connect"))
		goto out;

	if (type == SOCK_STREAM) {
		srv = accept_any(servers, nr_listen);
		if (!ASSERT_GE(srv, 0, "accept_any"))
			goto out;
		srv_client = accept(srv, NULL, NULL);
		if (!ASSERT_GE(srv_client, 0, "accept"))
			goto out;
		srv = srv_client;
	}

	/* For TCP, this is assigned the established socket. */
	if (!ASSERT_EQ(write(client, buf, sizeof(buf)), sizeof(buf), "write"))
		goto out;
	if (type == SOCK_DGRAM) {
		srv = accept_any(servers, nr_listen);
		if (!ASSERT_GE(srv, 0, "poll_dgram"))
			goto out;
	}
	if (!ASSERT_EQ(read(srv, rbuf, sizeof(rbuf)), sizeof(buf), "read"))
		goto out;

	ASSERT_EQ(skel->data->assign_ret, 0, "assign_ret");
	ASSERT_GE(skel->bss->nr_assigned, type == SOCK_STREAM ? 2 : 1,
		  "nr_assigned");
out:
	if (srv_client >= 0)
		close(srv_client);
	if (client >= 0)
		close(client);
	if (servers)
		free_fds(servers, nr_listen);
	test_netkit_sk_assign__destroy(skel);
	cleanup(tok);
}

static void run_primary_ctx(int bpf_ctx)
{
	bool primary = bpf_ctx == NETKIT_BPF_CTX_PRIMARY;
	LIBBPF_OPTS(bpf_netkit_opts, optl);
	LIBBPF_OPTS(bpf_tcx_opts, optt);
	struct test_netkit_sk_assign *skel;
	int ifindex, peer_ifindex, server = -1, client = -1, zero = 0, i;
	__u64 fd;
	struct nstoken *tok, *pod;
	struct bpf_link *link;
	char buf[] = "testing";

	tok = setup(bpf_ctx);
	if (!tok)
		return;

	skel = test_netkit_sk_assign__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out;

	ifindex = if_nametoindex(NK_PRIMARY);
	if (!ASSERT_GT(ifindex, 0, "nk_ifindex"))
		goto out;
	pod = open_netns(NS_POD);
	if (!ASSERT_OK_PTR(pod, "open_netns_pod"))
		goto out;
	peer_ifindex = if_nametoindex(NK_PEER);
	close_netns(pod);
	if (!ASSERT_GT(peer_ifindex, 0, "nk_peer_ifindex"))
		goto out;

	skel->bss->redirect_ifindex = if_nametoindex(VETH_SRC);
	link = bpf_program__attach_netkit(skel->progs.primary_ctx, ifindex, &optl);
	if (!ASSERT_OK_PTR(link, "attach_primary"))
		goto out;
	skel->links.primary_ctx = link;
	link = bpf_program__attach_tcx(skel->progs.redirect_target,
				       if_nametoindex(VETH_DST), &optt);
	if (!ASSERT_OK_PTR(link, "attach_tcx"))
		goto out;
	skel->links.redirect_target = link;

	/* A host socket, which the primary programs must not assign. */
	server = start_server(AF_INET, SOCK_DGRAM, "127.0.0.1", BIND_PORT,
			      TIMEOUT_MS);
	if (!ASSERT_GE(server, 0, "start_server"))
		goto out;
	fd = server;
	if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.server_map),
					   &zero, &fd, BPF_ANY),
		       "update_server_map"))
		goto out;

	client = connect_to_addr_str(AF_INET, SOCK_DGRAM, POD_ADDR4,
				     CONNECT_PORT, NULL);
	if (!ASSERT_GE(client, 0, "connect"))
		goto out;
	if (!ASSERT_EQ(write(client, buf, sizeof(buf)), sizeof(buf), "write"))
		goto out;

	/* With NETKIT_BPF_CTX_RX, programs of the primary run on the peer in
	 * the pod netns, so the ifindex of the host device does not resolve.
	 */
	ASSERT_EQ(skel->bss->primary_ifindex, primary ? ifindex : peer_ifindex,
		  "primary_ifindex");
	for (i = 0; primary && i < 100 && !READ_ONCE(skel->bss->nr_redirected); i++)
		usleep(1000);
	ASSERT_EQ(skel->bss->nr_redirected, primary ? 1 : 0, "nr_redirected");
	ASSERT_EQ(skel->data->primary_assign_ret,
		  primary ? -EOPNOTSUPP : -ENETUNREACH, "primary_assign_ret");
out:
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	test_netkit_sk_assign__destroy(skel);
	cleanup(tok);
}

void serial_test_netkit_sk_assign(void)
{
	if (test__start_subtest("ipv4_tcp"))
		run_sk_assign(AF_INET, SOCK_STREAM, 1);
	if (test__start_subtest("ipv6_tcp"))
		run_sk_assign(AF_INET6, SOCK_STREAM, 1);
	if (test__start_subtest("ipv4_udp"))
		run_sk_assign(AF_INET, SOCK_DGRAM, 1);
	if (test__start_subtest("ipv6_udp"))
		run_sk_assign(AF_INET6, SOCK_DGRAM, 1);
	if (test__start_subtest("ipv4_tcp_reuseport"))
		run_sk_assign(AF_INET, SOCK_STREAM, 2);
	if (test__start_subtest("ipv4_udp_reuseport"))
		run_sk_assign(AF_INET, SOCK_DGRAM, 2);
	if (test__start_subtest("bpf_ctx_rx"))
		run_primary_ctx(NETKIT_BPF_CTX_RX);
	if (test__start_subtest("bpf_ctx_primary"))
		run_primary_ctx(NETKIT_BPF_CTX_PRIMARY);
}
