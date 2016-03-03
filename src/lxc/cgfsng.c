/*
 * lxc: linux Container library
 *
 * Copyright © 2016 Canonical Ltd.
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@ubuntu.com>
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

/*
 * cgfs-ng.c: this is a new, simplified implementation of a filesystem
 * cgroup backend.  The original cgfs.c was designed to be as flexible
 * as possible.  It would try to find cgroup filesystems no matter where
 * or how you had them mounted, and deduce the most usable mount for
 * each controller.  It also was not designed for unprivileged use, as
 * that was reserved for cgmanager.
 *
 * This new implementation assumes that cgroup filesystems are mounted
 * under /sys/fs/cgroup/clist where clist is either the controller, or
 * a comman-separated list of controllers.
 */
#include "config.h"

lxc_log_define(lxc_cgfsng, lxc);

static void *cgfsng_init(const char *name)
{
	return NULL;
}

struct cgroup_ops *cgfs_ops_init(void)
{
	return &cgfs_ops;
}

static struct cgroup_ops cgfs_ops = {
	.init = cgfsng_init,
	.destroy = NULL,
	.create = NULL,
	.enter = NULL,
	.create_legacy = NULL,
	.get_cgroup = NULL,
	.canonical_path = NULL,
	.escape = NULL,
	.get = NULL,
	.set = NULL,
	.unfreeze = NULL,
	.setup_limits = NULL,
	.name = "cgroupfs-ng",
	.attach = NULL,
	.chown = NULL,
	.mount_cgroup = NULL,
	.nrtasks = NULL,
	.driver = CGFSNG,
};
