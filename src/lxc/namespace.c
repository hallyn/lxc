/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2009
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <unistd.h>
#include <alloca.h>
#include <errno.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "namespace.h"
#include "log.h"

lxc_log_define(lxc_namespace, lxc);

struct clone_arg {
	int (*fn)(void *);
	void *arg;
};

static int do_clone(void *arg)
{
	struct clone_arg *clone_arg = arg;
	return clone_arg->fn(clone_arg->arg);
}

static pid_t do_lxc_clone(int (*fn)(void *), void *arg, int flags)
{
	struct clone_arg clone_arg = {
		.fn = fn,
		.arg = arg,
	};

	size_t stack_size = sysconf(_SC_PAGESIZE);
	void *stack = alloca(stack_size);
	pid_t ret;

#ifdef __ia64__
	ret = __clone2(do_clone, stack,
		       stack_size, flags | SIGCHLD, &clone_arg);
#else
	ret = clone(do_clone, stack  + stack_size, flags | SIGCHLD, &clone_arg);
#endif
	if (ret < 0)
		ERROR("Failed to clone (%#x): %s.", flags, strerror(errno));

	return ret;
}
/* Return < 0 on error, pid > 0 on success, 0 if we did not act */
static pid_t handle_userns_attach(int (*fn)(void *), void *arg, int flags)
{
	int p[2], ret;
	struct lxc_handler *handler = (struct lxc_handler *)arg;
	pid_t pid;

	if (handler->conf->inherit_ns_fd[LXC_NS_USER] == -1)
		return 0;

	if (pipe(p) < 0) {
		SYSERROR("Failed creating pipe")
		return -1;
	}

	ret = fork();
	if (ret < 0) {
		close(p[0]);
		close(p[1]);
		return ret;
	}
	if (ret > 0) { // parent
		close(p[1]);
		if (wait_for_pid(ret) != 0) {
			close(p[0]);
			return -1;
		}
		if (read(p[0], &pid, sizeof(pid_t)) != sizeof(pid_t))
			pid = -1;
		close(p[0]);
		return pid;
	}

	// child
	close(p[0]);
	ret = lxc_setns(handler->conf->inherit_ns_fd[LXC_NS_USER], 0);
	if (ret < 0) {
		SYSERROR("Failed to attach to user namespace");
		pid = -1;
		write(p[1], &pid, sizeof(pid_t));
		exit(1);
	}
	flags &= ~CLONE_NEWUSER;
	pid = do_lxc_clone(fn, arg, flags | CLONE_PARENT);
	write(p[1], &pid, sizeof(pid_t));
	exit(0);
}

pid_t lxc_clone(int (*fn)(void *), void *arg, int flags)
{
	pid_t ret;

	ret = handle_userns_attach(fn, arg, flags);
	if (ret != 0)
		return ret;

	return do_lxc_clone(fn, arg, flags);
}

/* Leave the user namespace at the first position in the array of structs so
 * that we always attach to it first when iterating over the struct and using
 * setns() to switch namespaces. This especially affects lxc_attach(): Suppose
 * you cloned a new user namespace and mount namespace as an unprivileged user
 * on the host and want to setns() to the mount namespace. This requires you to
 * attach to the user namespace first otherwise the kernel will fail this check:
 *
 *        if (!ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN) ||
 *            !ns_capable(current_user_ns(), CAP_SYS_CHROOT) ||
 *            !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
 *            return -EPERM;
 *
 *    in
 *
 *        linux/fs/namespace.c:mntns_install().
 */
const struct ns_info ns_info[LXC_NS_MAX] = {
	[LXC_NS_USER] = {"user", CLONE_NEWUSER, "CLONE_NEWUSER"},
	[LXC_NS_MNT] = {"mnt", CLONE_NEWNS, "CLONE_NEWNS"},
	[LXC_NS_PID] = {"pid", CLONE_NEWPID, "CLONE_NEWPID"},
	[LXC_NS_UTS] = {"uts", CLONE_NEWUTS, "CLONE_NEWUTS"},
	[LXC_NS_IPC] = {"ipc", CLONE_NEWIPC, "CLONE_NEWIPC"},
	[LXC_NS_NET] = {"net", CLONE_NEWNET, "CLONE_NEWNET"},
	[LXC_NS_CGROUP] = {"cgroup", CLONE_NEWCGROUP, "CLONE_NEWCGROUP"}
};

int lxc_namespace_2_cloneflag(char *namespace)
{
	int i;
	for (i = 0; i < LXC_NS_MAX; i++)
		if (!strcasecmp(ns_info[i].proc_name, namespace))
			return ns_info[i].clone_flag;

	ERROR("Invalid namespace name: %s.", namespace);
	return -1;
}

int lxc_fill_namespace_flags(char *flaglist, int *flags)
{
	char *token, *saveptr = NULL;
	int aflag;

	if (!flaglist) {
		ERROR("At least one namespace is needed.");
		return -1;
	}

	token = strtok_r(flaglist, "|", &saveptr);
	while (token) {

		aflag = lxc_namespace_2_cloneflag(token);
		if (aflag < 0)
			return -1;

		*flags |= aflag;

		token = strtok_r(NULL, "|", &saveptr);
	}
	return 0;
}
