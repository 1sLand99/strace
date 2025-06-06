/*
 * Check appending auxstr of setns(2) when --namespace=new is given.
 *
 * Copyright (c) 2024-2025 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tests.h"
#include "scno.h"

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int
main(void)
{
	const char *netns_path = "/proc/self/ns/net";
	skip_if_unavailable(netns_path);

	int netns_fd = open(netns_path, O_RDONLY);
	if (netns_fd < 0)
		perror_msg_and_skip("open(%s)", netns_path);
	char netns[PATH_MAX + 1];
	ssize_t n  = readlink(netns_path, netns, sizeof(netns));
	if (n < 0)
		perror_msg_and_fail("readlink: %s", netns_path);
	else if ((size_t) n >= sizeof(netns))
		error_msg_and_fail("readlink: %s: result is too large",
				   netns_path);
	netns[n] = '\0';

	if (syscall(__NR_unshare, 0x40000000) < 0)
		perror_msg_and_skip("unshare (CLONE_NEWNET)");

	int rc = syscall(__NR_setns, netns_fd, 0x40000000);
	if (rc < 0)
		perror_msg_and_skip("setns (CLONE_NEWNET)");
	printf("setns(%d, CLONE_NEWNET) = %s (%s)\n",
	       netns_fd, sprintrc(rc), netns);

	puts("+++ exited with 0 +++");

	return 0;
}
