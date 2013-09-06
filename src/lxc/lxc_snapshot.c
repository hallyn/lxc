/*
 *
 * Copyright © 2013 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2013 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "../lxc/lxccontainer.h"

#include <stdio.h>
#include <libgen.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include <lxc/bdev.h>

#include "arguments.h"
#include "utils.h"

lxc_log_define(lxc_snapshot, lxc);

char *newname;
char *snapshot;

#define DO_SNAP 1
#define DO_LIST 2
#define DO_RESTORE 3
int action;

int do_snapshot(struct lxc_container *c)
{
	int ret;

	ret = c->snapshot(c);
	if (ret < 0) {
		ERROR("Error creating a snapshot");
		return -1;
	}

	INFO("Created snapshot snap%d\n", ret);
	return 0;
}

int do_list_snapshots(struct lxc_container *c)
{
	struct lxc_snapshot *s;
	int i, n;

	n = c->snapshot_list(c, &s);
	if (n < 0) {
		ERROR("Error listing snapshots");
		return -1;
	}
	if (n == 0) {
		printf("No snapshots\n");
		return 0;
	}
	for (i=0; i<n; i++) {
		printf("%s : %s %s %s\n", s[i].lxcpath, s[i].name, s[i].timestamp, s[i].comment_pathname ? s[i].comment_pathname : "");
		s[i].free(&s[i]);
	}
	free(s);
	return 0;
}

int do_restore_snapshots(struct lxc_container *c, char *snap, char *new)
{
	return c->snapshot_restore(c, snapshot, newname) ? 0 : -1;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'l': action = DO_LIST; break;
	case 'r': snapshot = arg; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"list", required_argument, 0, 'l'},
	{"restore", required_argument, 0, 'r'},
	LXC_COMMON_OPTIONS
};


static struct lxc_arguments my_args = {
	.progname = "lxc-create",
	.helpfn   = create_helpfn,
	.help     = "\
--name=NAME [-w] [-r] [-t timeout] [-P lxcpath]\n\
\n\
lxc-create creates a container\n\
\n\
Options :\n\
  -l, --list        list snapshots\n\
  -r, --restore=s   restore snapshot s, i.e. 'snap0'\n\",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

/*
 * lxc-snapshot -P lxcpath -n container
 * lxc-snapshot -P lxcpath -n container -l
 * lxc-snapshot -P lxcpath -n container -r snap3 recovered_1
 */

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int ret = 0;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(1);

	if (my_args.argc > 1) {
		ERROR("Too many arguments");
		return -1;
	}
	if (my_args.argc == 1)
		newname = my_args.argv[0];

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(1);

	if (geteuid()) {
		if (access(my_args.lxcpath[0], O_RDWR) < 0) {
			fprintf(stderr, "You lack access to %s\n", my_args.lxcpath[0]);
			exit(1);
		}
	}

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "System error loading container\n");
		exit(1);
	}

	switch(action) {
	case DO_SNAP:
		ret = do_snapshot(c);
		break;
	case DO_LIST:
		ret = do_list_snapshots(c);
		break;
	case DO_RESTORE:
		ret = do_restore_snapshots(c, snapshot, newname);
		break;
	}

	lxc_container_put(c);

	exit(ret);
}
