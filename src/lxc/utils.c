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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "utils.h"
#include "log.h"

lxc_log_define(lxc_utils, lxc);

static int _recursive_rmdir_onedev(char *dirname, dev_t pdev)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	int ret, failed=0;
	char pathname[MAXPATHLEN];

	dir = opendir(dirname);
	if (!dir) {
		ERROR("%s: failed to open %s", __func__, dirname);
		return 0;
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
			failed=1;
			continue;
		}
		ret = lstat(pathname, &mystat);
		if (ret) {
			ERROR("%s: failed to stat %s", __func__, pathname);
			failed=1;
			continue;
		}
		if (mystat.st_dev != pdev)
			continue;
		if (S_ISDIR(mystat.st_mode)) {
			if (!_recursive_rmdir_onedev(pathname, pdev))
				failed=1;
		} else {
			if (unlink(pathname) < 0) {
				ERROR("%s: failed to delete %s", __func__, pathname);
				failed=1;
			}
		}
	}

	if (rmdir(dirname) < 0) {
		ERROR("%s: failed to delete %s", __func__, dirname);
		failed=1;
	}

	if (closedir(dir)) {
		ERROR("%s: failed to close directory %s", __func__, dirname);
		failed=1;
	}

	return !failed;
}

/* returns 1 on success, 0 if there were any failures */
extern int lxc_rmdir_onedev(char *path)
{
	struct stat mystat;

	if (lstat(path, &mystat) < 0) {
		ERROR("%s: failed to stat %s", __func__, path);
		return 0;
	}

	return _recursive_rmdir_onedev(path, mystat.st_dev);
}

static int mount_fs(const char *source, const char *target, const char *type)
{
	/* the umount may fail */
	if (umount(target))
		WARN("failed to unmount %s : %s", target, strerror(errno));

	if (mount(source, target, type, 0, NULL)) {
		ERROR("failed to mount %s : %s", target, strerror(errno));
		return -1;
	}

	DEBUG("'%s' mounted on '%s'", source, target);

	return 0;
}

extern int lxc_setup_fs(void)
{
	if (mount_fs("proc", "/proc", "proc"))
		return -1;

	/* if we can't mount /dev/shm, continue anyway */
	if (mount_fs("shmfs", "/dev/shm", "tmpfs"))
		INFO("failed to mount /dev/shm");

	/* If we were able to mount /dev/shm, then /dev exists */
	/* Sure, but it's read-only per config :) */
	if (access("/dev/mqueue", F_OK) && mkdir("/dev/mqueue", 0666)) {
		DEBUG("failed to create '/dev/mqueue'");
		return 0;
	}

	/* continue even without posix message queue support */
	if (mount_fs("mqueue", "/dev/mqueue", "mqueue"))
		INFO("failed to mount /dev/mqueue");

	return 0;
}

/* borrowed from iproute2 */
extern int get_u16(unsigned short *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;

	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFFFF)
		return -1;

	*val = res;

	return 0;
}

extern int mkdir_p(const char *dir, mode_t mode)
{
	const char *tmp = dir;
	const char *orig = dir;
	char *makeme;

	do {
		dir = tmp + strspn(tmp, "/");
		tmp = dir + strcspn(dir, "/");
		makeme = strndup(orig, dir - orig);
		if (*makeme) {
			if (mkdir(makeme, mode) && errno != EEXIST) {
				SYSERROR("failed to create directory '%s'\n", makeme);
				free(makeme);
				return -1;
			}
		}
		free(makeme);
	} while(tmp != dir);

	return 0;
}

static char *copy_global_config_value(char *p)
{
	int len = strlen(p);
	char *retbuf;

	if (len < 1)
		return NULL;
	if (p[len-1] == '\n') {
		p[len-1] = '\0';
		len--;
	}
	retbuf = malloc(len+1);
	if (!retbuf)
		return NULL;
	strcpy(retbuf, p);
	return retbuf;
}

#define DEFAULT_VG "lxc"
#define DEFAULT_ZFSROOT "lxc"

const char *lxc_global_config_value(const char *option_name)
{
	static const char *options[][2] = {
		{ "lvm_vg",          DEFAULT_VG      },
		{ "zfsroot",         DEFAULT_ZFSROOT },
		{ "lxcpath",         LXCPATH         },
		{ "cgroup.pattern",  DEFAULT_CGROUP_PATTERN },
		{ NULL, NULL },
	};
	static const char *values[sizeof(options) / sizeof(options[0])] = { 0 };
	const char *(*ptr)[2];
	size_t i;
	char buf[1024], *p, *p2;
	FILE *fin = NULL;

	for (i = 0, ptr = options; (*ptr)[0]; ptr++, i++) {
		if (!strcmp(option_name, (*ptr)[0]))
			break;
	}
	if (!(*ptr)[0]) {
		errno = EINVAL;
		return NULL;
	}
	if (values[i])
		return values[i];

	fin = fopen_cloexec(LXC_GLOBAL_CONF, "r");
	if (fin) {
		while (fgets(buf, 1024, fin)) {
			if (buf[0] == '#')
				continue;
			p = strstr(buf, option_name);
			if (!p)
				continue;
			/* see if there was just white space in front
			 * of the option name
			 */
			for (p2 = buf; p2 < p; p2++) {
				if (*p2 != ' ' && *p2 != '\t')
					break;
			}
			if (p2 < p)
				continue;
			p = strchr(p, '=');
			if (!p)
				continue;
			/* see if there was just white space after
			 * the option name
			 */
			for (p2 += strlen(option_name); p2 < p; p2++) {
				if (*p2 != ' ' && *p2 != '\t')
					break;
			}
			if (p2 < p)
				continue;
			p++;
			while (*p && (*p == ' ' || *p == '\t')) p++;
			if (!*p)
				continue;
			values[i] = copy_global_config_value(p);
			goto out;
		}
	}
	/* could not find value, use default */
	values[i] = (*ptr)[1];
	/* special case: if default value is NULL,
	 * and there is no config, don't view that
	 * as an error... */
	if (!values[i])
		errno = 0;

out:
	if (fin)
		fclose(fin);
	return values[i];
}

const char *default_lvm_vg(void)
{
	return lxc_global_config_value("lvm_vg");
}

const char *default_zfs_root(void)
{
	return lxc_global_config_value("zfsroot");
}
const char *default_lxc_path(void)
{
	return lxc_global_config_value("lxcpath");
}

int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		return -1;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

int lxc_wait_for_pid_status(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		return -1;
	}
	if (ret != pid)
		goto again;
	return status;
}

ssize_t lxc_write_nointr(int fd, const void* buf, size_t count)
{
	ssize_t ret;
again:
	ret = write(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

ssize_t lxc_read_nointr(int fd, void* buf, size_t count)
{
	ssize_t ret;
again:
	ret = read(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

ssize_t lxc_read_nointr_expect(int fd, void* buf, size_t count, const void* expected_buf)
{
	ssize_t ret;
	ret = lxc_read_nointr(fd, buf, count);
	if (ret <= 0)
		return ret;
	if ((size_t)ret != count)
		return -1;
	if (expected_buf && memcmp(buf, expected_buf, count) != 0) {
		errno = EINVAL;
		return -1;
	}
	return ret;
}

#if HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
int sha1sum_file(char *fnam, unsigned char *digest)
{
	char *buf;
	int ret;
	FILE *f;
	long flen;

	if (!fnam)
		return -1;
	if ((f = fopen_cloexec(fnam, "r")) < 0) {
		SYSERROR("Error opening template");
		return -1;
	}
	if (fseek(f, 0, SEEK_END) < 0) {
		SYSERROR("Error seeking to end of template");
		fclose(f);
		return -1;
	}
	if ((flen = ftell(f)) < 0) {
		SYSERROR("Error telling size of template");
		fclose(f);
		return -1;
	}
	if (fseek(f, 0, SEEK_SET) < 0) {
		SYSERROR("Error seeking to start of template");
		fclose(f);
		return -1;
	}
	if ((buf = malloc(flen+1)) == NULL) {
		SYSERROR("Out of memory");
		fclose(f);
		return -1;
	}
	if (fread(buf, 1, flen, f) != flen) {
		SYSERROR("Failure reading template");
		free(buf);
		fclose(f);
		return -1;
	}
	if (fclose(f) < 0) {
		SYSERROR("Failre closing template");
		free(buf);
		return -1;
	}
	buf[flen] = '\0';
	ret = gnutls_hash_fast(GNUTLS_DIG_SHA1, buf, flen, (void *)digest);
	free(buf);
	return ret;
}
#endif

char** lxc_va_arg_list_to_argv(va_list ap, size_t skip, int do_strdup)
{
	va_list ap2;
	size_t count = 1 + skip;
	char **result;

	/* first determine size of argument list, we don't want to reallocate
	 * constantly...
	 */
	va_copy(ap2, ap);
	while (1) {
		char* arg = va_arg(ap2, char*);
		if (!arg)
			break;
		count++;
	}
	va_end(ap2);

	result = calloc(count, sizeof(char*));
	if (!result)
		return NULL;
	count = skip;
	while (1) {
		char* arg = va_arg(ap, char*);
		if (!arg)
			break;
		arg = do_strdup ? strdup(arg) : arg;
		if (!arg)
			goto oom;
		result[count++] = arg;
	}

	/* calloc has already set last element to NULL*/
	return result;

oom:
	free(result);
	return NULL;
}

const char** lxc_va_arg_list_to_argv_const(va_list ap, size_t skip)
{
	return (const char**)lxc_va_arg_list_to_argv(ap, skip, 0);
}

FILE *fopen_cloexec(const char *path, const char *mode)
{
	int open_mode = 0;
	int step = 0;
	int fd;
	int saved_errno = 0;
	FILE *ret;

	if (!strncmp(mode, "r+", 2)) {
		open_mode = O_RDWR;
		step = 2;
	} else if (!strncmp(mode, "r", 1)) {
		open_mode = O_RDONLY;
		step = 1;
	} else if (!strncmp(mode, "w+", 2)) {
		open_mode = O_RDWR | O_TRUNC | O_CREAT;
		step = 2;
	} else if (!strncmp(mode, "w", 1)) {
		open_mode = O_WRONLY | O_TRUNC | O_CREAT;
		step = 1;
	} else if (!strncmp(mode, "a+", 2)) {
		open_mode = O_RDWR | O_CREAT | O_APPEND;
		step = 2;
	} else if (!strncmp(mode, "a", 1)) {
		open_mode = O_WRONLY | O_CREAT | O_APPEND;
		step = 1;
	}
	for (; mode[step]; step++)
		if (mode[step] == 'x')
			open_mode |= O_EXCL;
	open_mode |= O_CLOEXEC;

	fd = open(path, open_mode, 0666);
	if (fd < 0)
		return NULL;

	ret = fdopen(fd, mode);
	saved_errno = errno;
	if (!ret)
		close(fd);
	errno = saved_errno;
	return ret;
}
