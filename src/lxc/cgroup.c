/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "config.h"
#include "commands.h"

#include <lxc/log.h>
#include <lxc/cgroup.h>
#include <lxc/start.h>

#if IS_BIONIC
#include <../include/lxcmntent.h>
#else
#include <mntent.h>
#endif

lxc_log_define(lxc_cgroup, lxc);

#define MTAB "/proc/mounts"

/* In the case of a bind mount, there could be two long pathnames in the
 * mntent plus options so use large enough buffer size
 */
#define LARGE_MAXPATHLEN 4 * MAXPATHLEN

/* Check if a mount is a cgroup hierarchy for any subsystem.
 * Return the first subsystem found (or NULL if none).
 */
static char *mount_has_subsystem(const struct mntent *mntent)
{
	FILE *f;
	char *c, *ret = NULL;
	char line[MAXPATHLEN];

	/* read the list of subsystems from the kernel */
	f = fopen("/proc/cgroups", "r");
	if (!f)
		return 0;

	/* skip the first line, which contains column headings */
	if (!fgets(line, MAXPATHLEN, f)) {
		fclose(f);
		return 0;
	}

	while (fgets(line, MAXPATHLEN, f)) {
		c = strchr(line, '\t');
		if (!c)
			continue;
		*c = '\0';

		ret = hasmntopt(mntent, line);
		if (ret)
			break;
	}

	fclose(f);
	return ret;
}

/*
 * Determine mountpoint for a cgroup subsystem.
 * @subsystem: cgroup subsystem (i.e. freezer).  If this is NULL, the first
 * cgroup mountpoint with any subsystems is used.
 * @mnt: a passed-in buffer of at least size MAXPATHLEN into which the path
 * is copied.
 *
 * Returns 0 on success, -1 on error.
 */
static int get_cgroup_mount(const char *subsystem, char *mnt)
{
	struct mntent mntent_r;
	FILE *file = NULL;
	int ret, err = -1;

	char buf[LARGE_MAXPATHLEN] = {0};

	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		return -1;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {
		if (strcmp(mntent_r.mnt_type, "cgroup") != 0)
			continue;

		if (subsystem) {
			if (!hasmntopt(&mntent_r, subsystem))
				continue;
		} else {
			if (!mount_has_subsystem(&mntent_r))
				continue;
		}

		ret = snprintf(mnt, MAXPATHLEN, "%s", mntent_r.mnt_dir);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto fail;

		DEBUG("using cgroup mounted at '%s'", mnt);
		err = 0;
		goto out;
	};

fail:
	DEBUG("Failed to find cgroup for %s\n",
	      subsystem ? subsystem : "(NULL)");
out:
	endmntent(file);
	return err;
}

/*
 * cgroup_path_get: Get the absolute path to a particular subsystem,
 * plus a passed-in (to be appended) relative cgpath for a container.
 *
 * @subsystem : subsystem of interest (e.g. "freezer")
 * @cgrelpath : a container's relative cgroup path (e.g. "lxc/c1")
 *
 * Returns absolute path on success, NULL on error. The caller must free()
 * the returned path.
 *
 * Note that @subsystem may be the name of an item (e.g. "freezer.state")
 * in which case the subsystem will be determined by taking the string up
 * to the first '.'
 */
char *cgroup_path_get(const char *subsystem, const char *cgrelpath)
{
	int rc;

	char *buf = NULL;
	char *cgabspath = NULL;

	buf = malloc(MAXPATHLEN * sizeof(char));
	if (!buf) {
		ERROR("malloc failed");
		goto out1;
	}

	cgabspath = malloc(MAXPATHLEN * sizeof(char));
	if (!cgabspath) {
		ERROR("malloc failed");
		goto out2;
	}

	/* lxc_cgroup_set passes a state object for the subsystem,
	 * so trim it to just the subsystem part */
	if (subsystem) {
		rc = snprintf(cgabspath, MAXPATHLEN, "%s", subsystem);
		if (rc < 0 || rc >= MAXPATHLEN) {
			ERROR("subsystem name too long");
			goto err3;
		}
		char *s = index(cgabspath, '.');
		if (s)
			*s = '\0';
		DEBUG("%s: called for subsys %s name %s\n", __func__,
		      subsystem, cgrelpath);
	}
	if (get_cgroup_mount(subsystem ? cgabspath : NULL, buf)) {
		ERROR("cgroup is not mounted");
		goto err3;
	}

	rc = snprintf(cgabspath, MAXPATHLEN, "%s/%s", buf, cgrelpath);
	if (rc < 0 || rc >= MAXPATHLEN) {
		ERROR("name too long");
		goto err3;
	}

	DEBUG("%s: returning %s for subsystem %s relpath %s", __func__,
		cgabspath, subsystem, cgrelpath);
	goto out2;

err3:
	free(cgabspath);
	cgabspath = NULL;
out2:
	free(buf);
out1:
	return cgabspath;
}

/*
 * lxc_cgroup_path_get: Get the absolute pathname for a cgroup
 * file for a running container.
 *
 * @subsystem : subsystem of interest (e.g. "freezer"). If NULL, then
 *              the first cgroup entry in mtab will be used.
 * @name      : name of container to connect to
 * @lxcpath   : the lxcpath in which the container is running
 *
 * This is the exported function, which determines cgpath from the
 * lxc-start of the @name container running in @lxcpath.
 *
 * Returns path on success, NULL on error. The caller must free()
 * the returned path.
 */
char *lxc_cgroup_path_get(const char *subsystem, const char *name,
			  const char *lxcpath)
{
	char *cgabspath;
	char *cgrelpath;

	cgrelpath = lxc_cmd_get_cgroup_path(name, lxcpath, subsystem);
	if (!cgrelpath)
		return NULL;

	cgabspath = cgroup_path_get(subsystem, cgrelpath);
	free(cgrelpath);
	return cgabspath;
}

/*
 * do_cgroup_set: Write a value into a cgroup file
 *
 * @path      : absolute path to cgroup file
 * @value     : value to write into file
 *
 * Returns 0 on success, < 0 on error.
 */
static int do_cgroup_set(const char *path, const char *value)
{
	int fd, ret;

	if ((fd = open(path, O_WRONLY)) < 0) {
		SYSERROR("open %s : %s", path, strerror(errno));
		return -1;
	}

	if ((ret = write(fd, value, strlen(value))) < 0) {
		close(fd);
		SYSERROR("write %s : %s", path, strerror(errno));
		return ret;
	}

	if ((ret = close(fd)) < 0) {
		SYSERROR("close %s : %s", path, strerror(errno));
		return ret;
	}
	return 0;
}

/*
 * lxc_cgroup_set_bypath: Write a value into a cgroup file
 *
 * @cgrelpath : a container's relative cgroup path (e.g. "lxc/c1")
 * @filename  : the cgroup file to write (e.g. "freezer.state")
 * @value     : value to write into file
 *
 * Returns 0 on success, < 0 on error.
 */
int lxc_cgroup_set_bypath(const char *cgrelpath, const char *filename, const char *value)
{
	int ret;
	char *cgabspath;
	char path[MAXPATHLEN];

	cgabspath = cgroup_path_get(filename, cgrelpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", cgabspath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	ret = do_cgroup_set(path, value);

out:
	free(cgabspath);
	return ret;
}

/*
 * lxc_cgroup_set: Write a value into a cgroup file
 *
 * @name      : name of container to connect to
 * @filename  : the cgroup file to write (e.g. "freezer.state")
 * @value     : value to write into file
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns 0 on success, < 0 on error.
 */
int lxc_cgroup_set(const char *name, const char *filename, const char *value,
		   const char *lxcpath)
{
	int ret;
	char *cgabspath;
	char path[MAXPATHLEN];

	cgabspath = lxc_cgroup_path_get(filename, name, lxcpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", cgabspath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	ret = do_cgroup_set(path, value);

out:
	free(cgabspath);
	return ret;
}

/*
 * lxc_cgroup_get: Read value from a cgroup file
 *
 * @name      : name of container to connect to
 * @filename  : the cgroup file to read (e.g. "freezer.state")
 * @value     : a pre-allocated buffer to copy the answer into
 * @len       : the length of pre-allocated @value
 * @lxcpath   : the lxcpath in which the container is running
 *
 * Returns the number of bytes read on success, < 0 on error
 *
 * If you pass in NULL value or 0 len, the return value will be the size of
 * the file, and @value will not contain the contents.
 *
 * Note that we can't get the file size quickly through stat or lseek.
 * Therefore if you pass in len > 0 but less than the file size, your only
 * indication will be that the return value will be equal to the passed-in ret.
 * We will not return the actual full file size.
 */
int lxc_cgroup_get(const char *name, const char *filename, char *value,
		   size_t len, const char *lxcpath)
{
	int fd, ret;
	char *cgabspath;
	char path[MAXPATHLEN];

	cgabspath = lxc_cgroup_path_get(filename, name, lxcpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/%s", cgabspath, filename);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("open %s : %s", path, strerror(errno));
		ret = -1;
		goto out;
	}

	if (!len || !value) {
		char buf[100];
		int count = 0;
		while ((ret = read(fd, buf, 100)) > 0)
			count += ret;
		if (ret >= 0)
			ret = count;
	} else {
		memset(value, 0, len);
		ret = read(fd, value, len);
	}

	if (ret < 0)
		ERROR("read %s : %s", path, strerror(errno));

	close(fd);
out:
	free(cgabspath);
	return ret;
}

int lxc_cgroup_nrtasks(const char *cgrelpath)
{
	char *cgabspath = NULL;
	char path[MAXPATHLEN];
	int pid, ret;
	FILE *file;

	cgabspath = cgroup_path_get(NULL, cgrelpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(path, MAXPATHLEN, "%s/tasks", cgabspath);
	if (ret < 0 || ret >= MAXPATHLEN) {
		ERROR("pathname too long");
		ret = -1;
		goto out;
	}

	file = fopen(path, "r");
	if (!file) {
		SYSERROR("fopen '%s' failed", path);
		ret = -1;
		goto out;
	}

	ret = 0;
	while (fscanf(file, "%d", &pid) != EOF)
		ret++;

	fclose(file);

out:
	free(cgabspath);
	return ret;
}

static void set_clone_children(struct mntent *m)
{
	char path[MAXPATHLEN];
	FILE *fout;
	int ret;

	if (!in_cgroup_list(m->mnt_opts, "cpuset"))
		return;
	ret = snprintf(path, MAXPATHLEN, "%s/cgroup.clone_children", m->mntdir);
	if (ret < 0 || ret > MAXPATHLEN)
		return;
	fout = fopen(path, "w");
	if (!fout)
		return;
	fprintf(fout, "1\n");
	fclose(fout);
}

static int in_cgroup_list(char *s, char *list)
{
	char *token, *str, *saveptr = NULL;

	if (!list || !s)
		return 0;

	for (str = strdupa(list); (token = strtok_r(str, ",", &saveptr)); str = NULL) {
		if (strcmp(s, token) == 0)
			return 1;
	}

	return 0;
}

static bool have_visited(char *opts, char *visited, char *all_subsystems)
{
	char *str, *s = NULL, *token;

	for (str = strdupa(opts); (token = strtok_r(str, ",", &s)); str = NULL) {
		if (!in_cgroup_list(token, all_subsystems))
			continue;
		if (visited && in_cgroup_list(token, visited))
			return true;
	}

	return false;
}

static bool is_in_desclist(struct cgroup_desc *d, char *opts, char *all_subsystems)
{
	while (d) {
		if (have_visited(opts, d->subsystems, all_subsystems)
			return true;
		d = d->next;
	}
	return false;
}

static char *record_visited(char *opts, char *all_subsystems)
{
	char *s = NULL, *token, *str;
	int oldlen = 0, newlen, ret, toklen;
	char *visited = NULL;

	for (str = strdupa(opts); (token = strtok_r(str, ",", &s)); str = NULL) {
		if (!in_cgroup_list(token, all_subsystems))
			continue;
		toklen = strlen(token);
		newlen = oldlen + toklen +  1; // ',' + token or token + '\0'
		visited = realloc(visited, newlen);
		if (!visited)
			return -1;
		if (oldlen)
			strcat(visited, ",");
		strcat(visited, token);
	}

	return visited;
}
 
static char *get_all_subsystems(void)
{
	FILE *f;
	char *line = NULL, *ret = NULL;
	size_t len;
	int first = 1;

	/* read the list of subsystems from the kernel */
	f = fopen("/proc/cgroups", "r");
	if (!f)
		return NULL;

	while (getline(&line, &len, f) != -1) {
		char *c;
		int oldlen, newlen, inc;

		/* skip the first line */
		if (first) {
			first=0;
			continue;
		}

		c = strchr(line, '\t');
		if (!c)
			continue;
		*c = '\0';

		oldlen = ret ? strlen(ret) : 0;
		newlen = oldlen + strlen(line) + 2;
		ret = realloc(ret, newlen);
		if (!ret)
			goto out;
		inc = snprintf(ret + oldlen, newlen, ",%s", line);
		if (inc < 0 || inc >= newlen) {
			free(ret);
			ret = NULL;
			goto out;
		}
	}

out:
	if (line)
		free(line);
	fclose(f);
	return ret;
}

/*
 * /etc/lxc/lxc.conf can contain lxc.cgroup.use = entries.
 * If any of those are present, then lxc will ONLY consider
 * cgroup filesystems mounted at one of the listed entries.
 */
static char *get_cgroup_uselist()
{
	FILE *f;
	char *line = NULL, *ret = NULL;
	size_t sz = 0, retsz = 0;

	if ((f = fopen(LXC_GLOBAL_CONF, "r")) == NULL)
		return NULL;
	while (getline(&line, &sz, f) != -1) {
		char *p = line[0];
		while (*p && isblank(*p))
			p++;
		if (strncmp(p, "lxc.cgroup.use", 14) != 0)
			continue;
		p = index(p, '=');
		if (!p)
			continue;
		p++;
		while (*p && isblank(*p))
			p++;
		if (strlen(p) < 1)
			continue;
		newsz = retsz + strlen(p);
		if (retsz == 0)
			newsz += 1;  // for trailing \0
		// the last line in the file could lack \n
		if (p[strlen(p)-1] != \n)
			newsz += 1;
		ret = realloc(ret, newsz);
		if (!ret) {
			ERROR("Out of memory reading cgroup uselist");
			fclose(f);
			free(line);
			return -ENOMEM;
		}
		if (retsz == 0)
			strcpy(ret, p);
		else
			strcat(ret, p);
		if (p[strlen(p)-1] != \n)
			ret[newsz-2] = '\0';
		ret[newsz-1] = '\0';
		retsz = newsz;
	}

	if (line)
		free(line);
	return ret;
}

static bool is_in_uselist(char *uselist, struct mntent *m)
{
	char *p;
	if (!uselist)
		return true;
	if (!*uselist)
		return false;
	while (*uselist) {
		p = index(uselist, '\n');
		if (strncmp(mntent->mnt_dir, uselist, p-uselist) == 0)
			return true;
		uselist = p+1;
	}
	return false;
}

/*
 * is_my_cgroup: check whether our pid is found in the passed-in cgroup tasks
 * file.
 * @path:  in full path to a cgroup tasks file
 * Note that in most cases the file will simply not exist, which is ok - it
 * just means that's not our cgroup.
 */
static bool is_my_cgroup(char *path)
{
	int me = getpid(), cmppid;
	FILE *f = fopen(path, "r");
	char *line = NULL;
	size_t sz = 0;

	if (!f)
		return false;
	while (getline(&line, &sz, f) != -1) {
		if (sscanf(line, "%d", &cmppid) == 1 && cmppid == me) {
			fclose(f);
			free(line);
			return true;
		}
	}
	fclose(f);
	return false;
}

static bool find_real_cgroup(struct cgroup_desc *d, char *path)
{
	FILE *f;
	char *line = NULL, *p, *p2;
	int ret = 0;
	size_t len;

	if ((f = fopen("/proc/self/cgroup", "r")) == NULL) {
		SYSERROR("Error opening /proc/self/cgroups");
		return false;
	}

	while (getline(&line, &len, f) != -1) {
		if (!(p = index(line, ':')))
			continue;
		if (!(p2 = index(++p, ':')))
			continue;
		*p2 = '\0';
		// in case of multiple mounts it may be more correct to
		// insist all subsystems be the same
		if (in_cgroup_list(p, d->subsystems))
			goto found;
       }

	if (line)
		free(line);
	fclose(f);
	return false;;

found:
	fclose(f);
	ret = snprintf(path, MAXPATHLEN, "%s", p2+1);
	if (ret < 0 || ret >= MAXPATHLEN) {
		free(line);
		return false;
	}
	free(line);
	return true;
}


/*
 * for a given cgroup mount entry, and a to-be-created container,
 * 1. Figure out full path of the cgroup we are currently in,
 * 2. Find a new free cgroup which is $path / $lxc_name with an
 *    optional '-$n' where n is an ever-increasing integer.
 */
static char *find_free_cgroup(struct cgroup_desc *d, char *lxc_name)
{
	char tail[20], cgpath[MAXPATHLEN], path[MAXPATHLEN];
	int i = 0;

	if (!find_real_cgroup(d, cgpath))
		return NULL;

	/*
	 * If d->mntpt is '/a/b/c/d', and the mountpoint is /x/y/z,
	 * then look for ourselves in:
	 *    /x/y/z/a/b/c/d/tasks
	 *    /x/y/z/b/c/d/tasks
	 *    /x/y/z/c/d/tasks
	 *    /x/y/z/d/tasks
	 *    /x/y/z/tasks
	 */
	cgp = cgpath;
	while (cgp[0]) {
		struct stat sb;
		ret = snprintf(path, MAXPATHLEN, "%s%s/tasks", d->mntpt, cgp);
		if (ret < 0 || ret >= MAXPATHLEN)
			return NULL;
		if (!is_my_cgroup(path)) {
			// does not exist, try the next one
			cgp = index(cgp, '/');
			if (!cgp)
				break;
			continue;
		}
	}
	if (!cgp || !*cgp)
		return NULL;
	// found it, path has our tasks file
	if (strlen(path) + strlen(lxc_name) + 20 > MAXPATHLEN) {
		ERROR("Error: cgroup path too long");
		return NULL;
	}
	tail[0] = '\0';
	while (1) {
		int freebytes;
		if (!(cgp = rindex(path, '/'))) // can't be
			return NULL;
		freebytes = MAXPATHLEN - (cgp - path);
		if (i) {
			ret = snprintf(tail, 20, "-%d", i);
			if (ret < 0 || ret >= 20)
				return NULL;
		}
		ret = snprintf(cgp, freebytes, "/%s%s", lxc_name, tail);
		if (ret < 0 || ret >= freebytes)
			return NULL;
		if (stat(path, &sb) == -1 && errno == EEXIST)
			break;
		i++;
	}

	l = strlen(cgpath);
	ret = snprintf(cgpath + l, MAXPATHLEN - l, "/%s%s", lxc_name, tail);
	if (ret < 0 || ret >= freebytes) {
		ERROR("Out of memory");
		return NULL;
	}
	if ((d->realcgroup = strdup(cgpath) == NULL) {
		ERROR("Out of memory");
		return NULL;
	}
	return strdup(path);
}

/*
 * For a new container, find a cgroup path which is unique in all cgroup mounts.
 * I.e. if r1 is already running, then /lxc/r1-1 may be used.
 *
 * @lxcgroup: the cgroup 'group' the contaienr should run in.  By default, this
 * is just 'lxc'.  Admins may wish to group some containers into other groups,
 * i.e. 'build', to take advantage of cgroup hierarchy to simplify group
 * administration.  Also, unprivileged users who are placed into a cgroup by
 * libcgroup_pam will be using that cgroup rather than the system-wide 'lxc'
 * group.
 * @name: the name of the container
 *
 * The chosen cgpath is returned as a strdup'd string.  The caller will have to
 * free that eventually, however the lxc monitor will keep that string so as to
 * return it in response to a LXC_COMMAND_CGROUP query.
 *
 * Note the path is relative to cgroup mounts.  I.e. if the freezer subsystem
 * is at /sys/fs/cgroup/freezer, and this fn returns '/lxc/r1', then the
 * freezer cgroup's full path will be /sys/fs/cgroup/freezer/lxc/r1/.
 *
 * Races won't be determintal, you'll just end up with leftover unused cgroups
 */
struct cgroup_desc *lxc_cgroup_path_create(const char *name)
{
	int i = 0, ret;
	struct cgroup_desc *retdesc;
	char path[MAXPATHLEN], tail[12];
	FILE *file = NULL;
	struct mntent mntent_r;
	char buf[LARGE_MAXPATHLEN] = {0};
	char *all_subsystems = get_all_subsystems();
	char *cgroup_uselist = get_cgroup_uselist();

	if (cgroup_uselist == -ENOMEM) {
		if (all_subsystems)
			free(all_subsystems);
		return NULL;
	}
	if (!all_subsystems) {
		ERROR("failed to get a list of all cgroup subsystems");
		if (cgroup_uselist)
			free(cgroup_uselist);
		return NULL;
	}
	file = setmntent(MTAB, "r");
	if (!file) {
		SYSERROR("failed to open %s", MTAB);
		free(all_subsystems);
		if (cgroup_uselist)
			free(cgroup_uselist);
		return NULL;
	}

	while ((getmntent_r(file, &mntent_r, buf, sizeof(buf)))) {

		if (strcmp(mntent_r.mnt_type, "cgroup"))
			continue;

		if (cgroup_uselist && !is_in_uselist(cgroup_uselist, mntent_r))
			continue;

		/* make sure we haven't checked this subsystem already */
		if (is_in_desclist(ret_desc, mntent_r.mnt_opts, all_subsystems))
			continue;

		if (!(newdesc = malloc(sizeof(struct cgroup_desc)))) {
			ERROR("Out of memory reading cgroups");
			goto fail;
		}
		newdesc->next = NULL;
		newdesc->mntpt = strdup(mntent_r.mnt_dir);
		newdesc->subsystems = record_visited(mntent_r.mnt_opts, all_subsystems);
		newdesc->realcgroup = NULL;
		newdesc->curcgroup = find_free_cgroup(newdesc, name);
		if (!newdesc->mntpt || !newdesc->subsystems || !newdesc->curcgroup) {
			ERROR("Out of memory reading cgroups");
			goto fail;
		}

		set_clone_children(&mntent_r);

		if (mkdir(path, 0755)) {
			ERROR("Error creating cgroup %s", path);
			goto fail;
		}
		newdesc->next = retdesc;
		retdesc = newdesc;
	}

	endmntent(file);
	free(all_subsystems);
	if (cgroup_uselist)
		free(cgroup_uselist);
	return retdesc;

fail:
	endmntent(file);
	free(all_subsystems);
	if (cgroup_uselist)
		free(cgroup_uselist);
	if (newdesc) {
		if (newdesc->mntpt)
			free(newdesc->mntpt);
		if (newdesc->subsystems)
			free(newdesc->subsystems);
		if (newdesc->curcgroup)
			free(newdesc->curcgroup);
		free(newdesc);
	}
	while (retdesc) {
		struct cgroup_desc *t = retdesc;
		retdesc = retdesc->next;
		if (t->mntpt)
			free(t->mntpt);
		if (t->subsystems)
			free(t->subsystems);
		if (t->curcgroup)
			free(t->curcgroup);
		free(t);

	}
	return NULL;
}

int lxc_cgroup_enter(struct cgroup_desc *cgroups, pid_t pid)
{
	char path[MAXPATHLEN];

	while (cgroups) {
		if (!cgroups->subsystems)
			goto next;
		ret = snprintf(path, MAXPATHLEN, "%s/tasks", cgroups->curcgroup);
		if (ret < 0 || ret >= MAXPATHLEN) {
			ERROR("Error entering cgroup");
			return -1;
		}
		fout = fopen(path, "w");
		if (!fout) {
			SYSERROR("Error entering cgroup");
			return -1;
		}
		if (fprintf(fout, "%d\n", (int)pid) < 0) {
			ERROR("Error writing pid to %s", path);
			fclose(fout);
			return -1;
		}
		if (fclose(fout) < 0) {
			SYSERROR("Error writing pid to %s", path);
			return -1;
		}

next:
		cgroups = cgroups->next;
	}
	return 0;
}

static int cgroup_rmdir(char *dirname)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	int ret;
	char pathname[MAXPATHLEN];

	dir = opendir(dirname);
	if (!dir) {
		WARN("failed to open directory: %m");
		return -1;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		int rc;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
				!strcmp(direntp->d_name, ".."))
			continue;

		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", dirname, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			ERROR("pathname too long");
			continue;
		}
		ret = stat(pathname, &mystat);
		if (ret)
			continue;
		if (S_ISDIR(mystat.st_mode))
			cgroup_rmdir(pathname);
	}

	ret = rmdir(dirname);

	if (closedir(dir))
		ERROR("failed to close directory");
	return ret;
}

/*
 * for each mounted cgroup, destroy the cgroup for the container
 */
int lxc_cgroup_destroy_desc(struct cgroup_desc *cgroups)
{
	while (cgroups) {
		char *next = cgroups->next;
		if (cgroup_rmdir(cgroups->curcgroup) < 0)
			SYSERROR("removing cgroup directory %s", cgroups->curcgroup);
		free(cgroups->mntpt);
		free(cgroups->subsystems);
		free(cgroups->curcgroup);
		free(cgroups);
		cgroups = next;
	}
}

int lxc_cgroup_attach(pid_t pid, const char *name, const char *lxcpath)
{
	FILE *f;
	char *line = NULL, ret = -1;
	size_t len = 0;
	int first = 1;
	char *dirpath;

	/* read the list of subsystems from the kernel */
	f = fopen("/proc/cgroups", "r");
	if (!f)
		return NULL;

	while (getline(&line, &len, f) != -1) {
		char *c;
		int oldlen, newlen, inc;

		/* skip the first line */
		if (first) {
			first=0;
			continue;
		}

		c = strchr(line, '\t');
		if (!c)
			continue;
		*c = '\0';
		dirpath = lxc_cmd_get_cgroup_path(name, lxcpath);
		if (!dirpath)
			continue;

		INFO("joining pid %d to cgroup %s", pid, dirpath);
		if (lxc_cgroup_enter(dirpath, pid)) {
			ERROR("Failed joining %d to %s\n", pid, dirpath);
			goto out;
		}
	}
	ret = 0;

out:
	if (line)
		free(line);
	fclose(f);
	return ret;
}

bool is_in_subcgroup(int pid, const char *subsystem, struct cgroup_desc *d)
{
	char filepath[MAXPATHLEN], *line = NULL, v1[MAXPATHLEN], v2[MAXPATHLEN];
	FILE *f;
	int ret, junk;
	size_t sz = 0, l1 = strlen(cgpath), l2;
	char *end = index(subsystem, '.');
	int len = end ? (end - subsystem) : strlen(subsystem);
	const char *cgpath = NULL;

	while (d) {
		if (in_cgroup_list("devices", d->subsystems)) {
			cgpath = d->realcgroup;
			break;
		}
		d = d->next;
	}
	if (!d)
		return false;

	ret = snprintf(filepath, MAXPATHLEN, "/proc/%d/cgroup", pid);
	if (ret < 0 || ret >= MAXPATHLEN)
		return false;
	if ((f = fopen(filepath, "r")) == NULL)
		return false;
	while (getline(&line, &sz, f) != -1) {
		// nr:subsystem:path
		v2[0] = v2[1] = '\0';
		ret = sscanf(line, "%d:%[^:]:%s", &junk, v1, v2);
		if (ret != 3) {
			fclose(f);
			free(line);
			return false;
		}
		len = end ? end - subsystem : strlen(subsystem);
		if (strncmp(v1, subsystem, len) != 0)
			continue;
		// v2 will start with '/', skip it by using v2+1
		// we must be in SUBcgroup, so make sure l2 > l1
		l2 = strlen(v2+1);
		if (l2 > l1 && strncmp(v2+1, cgpath, l1) == 0) {
			fclose(f);
			free(line);
			return true;
		}
	}
	fclose(f);
	if (line)
		free(line);
	return false;
}

char *cgroup_get_subsys_path(struct lxc_handler *handler, const char *subsys)
{
	struct cgroup_desc *d;

	for (d = handler->cgroup; d; d = d->next) {
		if (in_cgroup_list(subsys, d->subsystems))
			return d->realcgroup;
	}

	return NULL;
}
