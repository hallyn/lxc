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
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>

#include "log.h"
#include "cgroup.h"
#include "utils.h"

lxc_log_define(lxc_cgfsng, lxc);

static struct cgroup_ops cgfsng_ops;

/*
 * A descriptor for a mounted hierarchy
 * @controllers: either NULL, or a null-terminated list of all
 *   the co-mounted controllers
 * @mountpoint: the mountpoint we will use.  It will be either
 *   /sys/fs/cgroup/controller or /sys/fs/cgroup/controllerlist
 * @base_cgroup: the cgroup under which the container cgroup path
     is created.  This will be either the caller's cgroup (if not
     root), or init's cgroup (if root).
 */
struct hierarchy {
	char **controllers;
	char *mountpoint;
	char *base_cgroup;
};

struct cgfsng_handler_data {
	struct hierarchy **hierarchies;
	char *cgroup_use;
	char *cgroup_pattern;
	char *container_cgroup; // cgroup we created for the container
	char *name; // container name
};

static void free_controllers(char **clist)
{
	if (clist) {
		int i;

		for (i = 0; clist[i]; i++)
			free(clist[i]);
		free(clist);
	}
}

/*
 * append an entry to the clist.  Do not fail.
 * *clist must be NULL the first time we are called.
 *
 * The last entry will always be NULL.
 */
static void must_append_controller(char ***clist, char *entry)
{
	int newentry;
	char *copy;

	if (!*clist) {
		do {
			*clist = malloc(2 * sizeof(char **));
		} while (!*clist);
		newentry = 0;
		(*clist)[1] = NULL;
	} else {
		char **tmp;
		for (newentry = 0; (*clist)[newentry]; newentry++);
		do {
			tmp = realloc((*clist), (newentry + 1) * sizeof(char **));
		} while (!tmp);
		tmp[newentry + 1] = NULL;
		*clist = tmp;
	}

	do {
		copy = strdup(entry);
	} while (!copy);
	(*clist)[newentry] = copy;
}

static void free_hierarchies(struct hierarchy **hlist)
{
	if (hlist) {
		int i;

		for (i = 0; hlist[i]; i++) {
			free(hlist[i]->mountpoint);
			free(hlist[i]->base_cgroup);
			free_controllers(hlist[i]->controllers);
		}
		free(hlist);
	}
}

static void free_handler_data(struct cgfsng_handler_data *d)
{
	free_hierarchies(d->hierarchies);
	free(d->cgroup_use);
	free(d->cgroup_pattern);
	free(d->container_cgroup);
	free(d->name);
	free(d);
}

static bool in_controller_list(char **list, char *entry)
{
	int i;

	if (!list)
		return false;
	for (i = 0; list[i]; i++)
		if (strcmp(list[i], entry) == 0)
			return true;

	return false;
}

struct hierarchy *get_hierarchy(struct cgfsng_handler_data *d, char *c)
{
	int i;

	if (!d || !d->hierarchies)
		return NULL;
	for (i = 0; d->hierarchies[i]; i++) {
		if (in_controller_list(d->hierarchies[i]->controllers, c))
			return d->hierarchies[i];
	}
	return NULL;
}

static bool controller_lists_intersect(char **l1, char **l2)
{
	int i;

	if (!l1 || !l2)
		return false;

	for (i = 0; l1[i]; i++) {
		if (in_controller_list(l2, l1[i]))
			return true;
	}
	return false;
}

static bool controller_list_is_dup(struct hierarchy **hlist, char **clist)
{
	struct hierarchy *s;
	if (!hlist)
		return false;
	for (s = hlist[0]; s; s++)
		if (controller_lists_intersect(s->controllers, clist))
			return true;
	return false;

}

static bool controller_found(struct hierarchy **hlist, char *entry)
{
	int i;
	if (!hlist)
		return false;

	for (i = 0; hlist[i]; i++)
		if (in_controller_list(hlist[i]->controllers, entry))
			return true;
	return false;
}

static bool all_controllers_found(struct cgfsng_handler_data *d)
{
	char *p, *saveptr = NULL;
	struct hierarchy ** hlist = d->hierarchies;

	if (!controller_found(hlist, "systemd")) {
		ERROR("no systemd controller mountpoint found");
		return false;
	}
	if (!controller_found(hlist, "freezer")) {
		ERROR("no freezer controller mountpoint found");
		return false;
	}
	
	for (p = strtok_r(d->cgroup_use, ",", &saveptr); p;
			p = strtok_r(NULL, ",", &saveptr)) {
		if (!controller_found(hlist, p)) {
			ERROR("no %s controller mountpoint found", p);
			return false;
		}
	}
	return true;
}

static bool is_cgroup_mountinfo_line(char *line)
{
	int i;
	char *p = line;

	for (i = 0; i < 3; i++) {
		p = index(p, ' ');
		if (!p)
			return false;
		p++;
	}

	return strncmp(p, "/sys/fs/cgroup/", 15) == 0;
}

static bool is_lxcfs(const char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;
	return strncmp(p, " - fuse.lxcfs ", 14);
}

/*
 * There are other ways we could get this info.  For lxcfs, field 3
 * is /cgroup/controller-list.  For cgroupfs, we could parse the mount
 * options.  But we simply assume that the mountpoint must be
 * /sys/fs/cgroup/controller-list
 */
static char **get_controllers(char *line)
{
	// the fourth field is /sys/fs/cgroup/comma-delimited-controller-list
	int i;
	char *p = line, *tok, *saveptr = NULL;
	char **aret = NULL;

	for (i = 0; i < 3; i++) {
		p = index(p, ' ');
		if (!p)
			goto out_free;
		p++;
	}
	if (!p)
		goto out_free;
	if (strncmp(p, "/sys/fs/cgroup/", 15) != 0)
		goto out_free;
	p += 15;
	for (tok = strtok_r(p, ",", &saveptr); tok;
			tok = strtok_r(NULL, ",", &saveptr))
		must_append_controller(&aret, tok);

	return aret;

out_free:
	free_controllers(aret);
	return NULL;
}

static bool is_cgroupfs(char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;
	return strncmp(p, " - cgroup ", 10);
}

static void add_controller(struct cgfsng_handler_data *d, char **clist,
			   char *mountpoint, char *base_cgroup)
{
	struct hierarchy *new;

	do {
		new = malloc(sizeof(*new));
	} while (!new);
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->base_cgroup = base_cgroup;
}

static char *get_mountpoint(char *line)
{
	int i;
	char *p = line, *p2, *sret;
	size_t len;

	for (i = 0; i < 3; i++) {
		p = index(p, ' ');
		if (!p)
			return NULL;
		p++;
	}
	p2 = index(p, ' ');
	if (!p2)
		return NULL;
	len = p2 - p;
	do {
		sret = malloc(len + 1);
	} while (!sret);
	memcpy(sret, p, len);
	sret[len] = '\0';
	return sret;
}

static char *copy_to_eol(char *p)
{
	char *p2 = index(p, '\n'), *sret;
	size_t len;

	if (!p2)
		return NULL;
	
	len = p2 - p;
	do {
		sret = malloc(len + 1);
	} while (!sret);
	memcpy(sret, p2, len);
	sret[len] = '\0';
	return sret;
}

/*
 * cgline: pointer to character after the first ':' in a line in a
 * \n-terminated /proc/self/cgroup file. Check whether * controller c is
 * present.
 */
static bool controller_in_clist(char *cgline, char *c)
{
	char *tok, *saveptr = NULL, *eol, *tmp;
	size_t len;

	eol = index(cgline, ':');
	if (!eol)
		return false;

	len = eol - cgline;
	tmp = alloca(len + 1);
	memcpy(tmp, cgline, len);
	tmp[len] = '\0';

	for (tok = strtok_r(tmp, ",", &saveptr); tok;
			tok = strtok_r(NULL, ",", &saveptr)) {
		if (strcmp(tok, c) == 0)
			return true;
	}
	return false;
}

static char *get_current_cgroup(char *basecginfo, char *controller)
{
	char *p = basecginfo;

	while (1) {
		p = index(p, ':');
		if (!p)
			return NULL;
		p++;
		if (controller_in_clist(p, controller)) {
			p = index(p, ':');
			if (!p)
				return NULL;
			p++;
			return copy_to_eol(p);
		}

		p = index(p, '\n');
		if (!p)
			return NULL;
		p++;
	}
}

static char *read_file(char *fnam)
{
	FILE *f;
	long flen;
	char *buf;

	f = fopen(fnam, "r");
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) < 0) {
		fclose(f);
		return NULL;
	}
	if ((flen = ftell(f)) < 0) {
		fclose(f);
		return NULL;
	}
	do {
		buf = malloc(flen+1);
	} while (!buf);
	buf[flen] = '\0';
	if (fread(buf, 1, flen, f) != flen) {
		fclose(f);
		free(buf);
		return NULL;
	}
	fclose(f);
	return buf;
}

static char *must_make_path(const char *first, ...) __attribute__((sentinel));

static bool test_writeable(char *mountpoint, char *path)
{
	char *fullpath = must_make_path(mountpoint, path, "XXXXXX", NULL);

	if (!mkdtemp(fullpath))
		return false;
	(void)rmdir(fullpath);
	return true;
}

static bool parse_hierarchies(struct cgfsng_handler_data *d)
{
	FILE *f;
	char * line = NULL, *basecginfo;
	size_t len = 0;

	if (geteuid())
		basecginfo = read_file("/proc/self/cgroup");
	else
		basecginfo = read_file("/proc/1/cgroup");
	if (!basecginfo)
		return false;

	if ((f = fopen("/proc/self/mountinfo", "r")) == NULL) {
		ERROR("Failed opening /proc/self/mountinfo");
		return false;
	}

	/* we support simple cgroup mounts and lxcfs mounts */
	while (getline(&line, &len, f) != -1) {
		char **controller_list = NULL;
		char *mountpoint, *base_cgroup;

		if (!is_cgroup_mountinfo_line(line))
			continue;
		if (!is_lxcfs(line) && !is_cgroupfs(line))
			continue;

		controller_list = get_controllers(line);
		if (!controller_list)
			continue;

		if (controller_list_is_dup(d->hierarchies, controller_list)) {
			free(controller_list);
			continue;
		}

		mountpoint = get_mountpoint(line);
		if (!mountpoint) {
			ERROR("Error reading mountinfo: bad line '%s'", line);
			free_controllers(controller_list);
			continue;
		}

		base_cgroup = get_current_cgroup(basecginfo, controller_list[0]);
		if (!base_cgroup) {
			ERROR("Failed to find current cgroup for controller '%s'", controller_list[0]);
			free_controllers(controller_list);
			free(mountpoint);
			continue;
		}
		prune_init_scope(base_cgroup);
		if (!test_writeable(mountpoint, base_cgroup)) {
			free_controllers(controller_list);
			free(mountpoint);
			free(base_cgroup);
			continue;
		}
		add_controller(d, controller_list, mountpoint, base_cgroup);
	}

	free(basecginfo);

	fclose(f);
	free(line);

	/* verify that all controllers in cgroup.use and all crucial
	 * controllers are accounted for
	 */
	if (!all_controllers_found(d))
		return false;

	return true;
}

static void *cgfsng_init(const char *name)
{
	struct cgfsng_handler_data *d;
	const char *cgroup_use, *cgroup_pattern;

	do {
		d = malloc(sizeof(*d));
	} while (!d);
	memset(d, 0, sizeof(*d));

	do {
		d->name = strdup(name);
	} while (!d->name);

	errno = 0;
	cgroup_use = lxc_global_config_value("lxc.cgroup.use");
	if (!cgroup_use && errno != 0) {
		SYSERROR("Error reading list of cgroups to use");
		goto out_free;
	}
	do {
		d->cgroup_use = strdup(cgroup_use);
	} while (!d->cgroup_use);
	cgroup_pattern = lxc_global_config_value("lxc.cgroup.pattern");
	if (!cgroup_pattern) {
		// Note that lxc_global_config_value fills this in if needed,
		// so this should never be NULL.
		ERROR("Error getting cgroup pattern");
		goto out_free;
	}
	do {
		d->cgroup_pattern = strdup(cgroup_pattern);
	} while (!d->cgroup_pattern);

	if (!parse_hierarchies(d))
		goto out_free;

	return d;

out_free:
	free_handler_data(d);
	return NULL;
}

static char *must_make_path(const char *first, ...)
{
	va_list args;
	char *cur, *dest;
	size_t full_len = strlen(first);

	do {
		dest = strdup(first);
	} while (!dest);

	va_start(args, first);
	while ((cur = va_arg(args, char *)) != NULL) {
		char *new;
		full_len += strlen(cur);
		if (cur[0] != '/')
			full_len++;
		do {
			new = realloc(dest, full_len + 1);
		} while (!new);
		dest = new;
		if (cur[0] != '/')
			strcat(dest, "/");
		strcat(dest, cur);
	}
	va_end(args);

	return dest;
}

static int cgroup_rmdir(char *dirname)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	int r = 0;

	dir = opendir(dirname);
	if (!dir)
		return -1;

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		char *pathname;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		pathname = must_make_path(dirname, direntp->d_name, NULL);

		if (lstat(pathname, &mystat)) {
			if (!r)
				WARN("failed to stat %s\n", pathname);
			r = -1;
			goto next;
		}

		if (!S_ISDIR(mystat.st_mode))
			goto next;
		if (cgroup_rmdir(pathname) < 0)
			r = -1;
next:
		free(pathname);
	}

	if (rmdir(dirname) < 0) {
		if (!r)
			WARN("%s: failed to delete %s: %m", __func__, dirname);
		r = -1;
	}

	if (closedir(dir) < 0) {
		if (!r)
			WARN("%s: failed to delete %s: %m", __func__, dirname);
		r = -1;
	}
	return r;
}

static int rmdir_wrapper(void *data)
{
	char *path = data;

	if (setresgid(0,0,0) < 0)
		SYSERROR("Failed to setgid to 0");
	if (setresuid(0,0,0) < 0)
		SYSERROR("Failed to setuid to 0");
	if (setgroups(0, NULL) < 0)
		SYSERROR("Failed to clear groups");

	return cgroup_rmdir(path);
}

void recursive_destroy(char *path, struct lxc_conf *conf)
{
	int r;
	if (conf && !lxc_list_empty(&conf->id_map))
		r = userns_exec_1(conf, rmdir_wrapper, path);
	else
		r = cgroup_rmdir(path);

	if (r < 0)
		ERROR("Error destroying %s\n", path);
}

static void cgfsng_destroy(void *hdata, struct lxc_conf *conf)
{
	struct cgfsng_handler_data *d = hdata;

	if (!d)
		return;

	if (d->container_cgroup && d->hierarchies) {
		int i;
		for (i = 0; d->hierarchies[i]; i++) {
			char *fullpath = must_make_path(d->hierarchies[i]->mountpoint, d->hierarchies[i]->base_cgroup, d->container_cgroup, NULL);

			recursive_destroy(fullpath, conf);
			free(fullpath);
		}
	}

	free_handler_data(d);
}

struct cgroup_ops *cgfsng_ops_init(void)
{
	return &cgfsng_ops;
}

static bool create_path_for_hierarchy(struct hierarchy *h, char *cgname)
{
	char *fullpath = must_make_path(h->mountpoint, h->base_cgroup, cgname, NULL);
	int ret;

	ret = mkdir(fullpath, 0755);
	free(fullpath);
	return ret == 0;
}

static void remove_path_for_hierarchy(struct hierarchy *h, char *cgname)
{
	char *fullpath = must_make_path(h->mountpoint, h->base_cgroup, cgname, NULL);

	if (rmdir(fullpath) < 0)
		SYSERROR("Failed to clean up cgroup %s from failed creation attempt", fullpath);
	free(fullpath);
}


/*
 * Try to create the same cgrou pin all hierarchies.
 * Start with cgroup_pattern; next cgroup_pattern-1, -2, ..., -999
 */
static inline bool cgfsng_create(void *hdata)
{
	struct cgfsng_handler_data *d = hdata;
	char *tmp, *cgname, *offset;
	int i, idx = 0;
	size_t len;

	if (!d)
		return false;
	if (d->container_cgroup) {
		WARN("cgfsng_create called a second time");
		return false;
	}

	tmp = lxc_string_replace("%n", d->name, d->cgroup_pattern);
	if (!tmp) {
		ERROR("Failed expanding cgroup name pattern");
		return false;
	}
	len = strlen(tmp) + 5; // leave room for -NNN\0
	do {
		cgname = malloc(len);
	} while (!cgname);
	strcpy(cgname, tmp);
	free(tmp);
	offset = cgname + len - 4;

again:
	if (idx == 1000)
		goto out_free;
	if (idx)
		snprintf(offset, 5, "-%d", idx);
	for (i = 0; d->hierarchies[i]; i++) {
		if (!create_path_for_hierarchy(d->hierarchies[i], cgname)) {
			int j;
			for (j = 0; j < i; j++)
				remove_path_for_hierarchy(d->hierarchies[j], cgname);
			idx++;
			goto again;
		}
		/* Done */
		d->container_cgroup = cgname;
	}

out_free:
	free(cgname);
	return false;
}

static const char *cgfsng_canonical_path(void *hdata)
{
	struct cgfsng_handler_data *d = hdata;

	return d->container_cgroup;
}

static bool cgfsng_enter(void *hdata, pid_t pid)
{
	struct cgfsng_handler_data *d = hdata;
	char pidstr[25];
	int i, len;

	len = snprintf(pidstr, 25, "%d", pid);
	if (len < 0 || len > 25)
		return false;

	for (i = 0; d->hierarchies[i]; i++) {
		// TODO - fall back to tasks if needed?
		char *fullpath = must_make_path(d->hierarchies[i]->mountpoint,
						d->hierarchies[i]->base_cgroup,
						d->container_cgroup, "cgroup.procs",
						NULL);
		if (lxc_write_to_file(fullpath, pidstr, len, false) != len) {
			ERROR("Failed to enter %s\n", fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

struct chown_data {
	struct cgfsng_handler_data *d;
	uid_t origuid; // target uid in parent namespace
};

static int chown_cgroup_wrapper(void *data)
{
	struct chown_data *arg = data;
	struct cgfsng_handler_data *d = arg->d;
	uid_t destuid;
	int i;

	if (setresgid(0,0,0) < 0)
		SYSERROR("Failed to setgid to 0");
	if (setresuid(0,0,0) < 0)
		SYSERROR("Failed to setuid to 0");
	if (setgroups(0, NULL) < 0)
		SYSERROR("Failed to clear groups");

	destuid = get_ns_uid(arg->origuid);

	for (i = 0; d->hierarchies[i]; i++) {
		char *fullpath = must_make_path(d->hierarchies[i]->mountpoint,
						d->hierarchies[i]->base_cgroup,
						d->container_cgroup, NULL);
		if (chown(fullpath, destuid, 0) < 0) {
			SYSERROR("Error chowning %s", fullpath);
			free(fullpath);
			return -1;
		}
		// TODO - do we need to chown tasks and cgroup.procs too?

		free(fullpath);
	}

	return 0;
}

static bool cgfsns_chown(void *hdata, struct lxc_conf *conf)
{
	struct cgfsng_handler_data *d = hdata;
	struct chown_data wrap;

	if (!d)
		return false;

	if (lxc_list_empty(&conf->id_map))
		return true;

	wrap.d = d;
	wrap.origuid = geteuid();

	if (userns_exec_1(conf, chown_cgroup_wrapper, &wrap) < 0) {
		ERROR("Error requesting cgroup chown in new namespace");
		return false;
	}

	return true;
}

static bool cgfsng_mount(void *hdata, const char *root, int type)
{
	if (cgns_supported())
		return true;
	// TODO - implement this.  Not needed for cgroup namespaces
	return false;
}

/*
 * TODO - implement this at some point
 * This is not called on any modern kernel, so low priority.
 * Just add up the nrtasks for all sub-cgroups in the freezer subsystem.
 */
static int cgfsng_nrtasks(void *hdata) {
	return 0;
}

/* Only root needs to escape to the cgroup of its init */
static bool cgfsng_escape(void *hdata)
{
	struct cgfsng_handler_data *d = hdata;
	int i;

	if (geteuid())
		return true;

	for (i = 0; d->hierarchies[i]; i++) {
		// TODO - fall back to tasks if needed?
		char *fullpath = must_make_path(d->hierarchies[i]->mountpoint,
						d->hierarchies[i]->base_cgroup,
						"cgroup.procs", NULL);
		if (lxc_write_to_file(fullpath, "0", 2, false) != 1) {
			ERROR("Failed to enter %s\n", fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

#define THAWED "THAWED"
#define THAWED_LEN (strlen(THAWED))

static bool cgfsng_unfreeze(void *hdata)
{
	struct cgfsng_handler_data *d = hdata;
	char *fullpath;
	struct hierarchy *h = get_hierarchy(d, "freezer");

	if (!d || !h)
		return false;
	fullpath = must_make_path(h->mountpoint, h->base_cgroup, d->container_cgroup, "freezer.state", NULL);
	if (lxc_write_to_file(fullpath, THAWED, THAWED_LEN, false) != THAWED_LEN) {
		free(fullpath);
		return false;
	}
	free(fullpath);
	return true;
}

static struct cgroup_ops cgfsng_ops = {
	.init = cgfsng_init,
	.destroy = cgfsng_destroy,
	.create = cgfsng_create,
	.enter = cgfsng_enter,
	.canonical_path = cgfsng_canonical_path,
	.escape = cgfsng_escape,
	.get_cgroup = NULL,
	.get = NULL,
	.set = NULL,
	.unfreeze = cgfsng_unfreeze,
	.setup_limits = NULL,
	.name = "cgroupfs-ng",
	.attach = NULL,
	.chown = cgfsns_chown,
	.mount_cgroup = cgfsng_mount,
	.nrtasks = cgfsng_nrtasks,
	.driver = CGFSNG,

	/* unsupported */
	.create_legacy = NULL,
};
