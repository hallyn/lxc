/*
 *
 * Copyright © 2014 Tycho Andersen <tycho.andersen@canonical.com>.
 * Copyright © 2014 Canonical Ltd.
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

#include <stdio.h>
#include <errno.h>

#include <lxc/lxccontainer.h>

#include "log.h"
#include "config.h"
#include "lxc.h"
#include "arguments.h"

static char *checkpoint_dir;

static const struct option my_longopts[] = {
	{"checkpoint-dir", required_argument, 0, 'D'},
	LXC_COMMON_OPTIONS
};

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	switch (c) {
	case 'D':
		checkpoint_dir = strdup(arg);
		if (!checkpoint_dir)
			return -1;
		break;
	}
	return 0;
}

static struct lxc_arguments my_args = {
	.progname = "lxc-checkpoint",
	.help     = "\
--name=NAME\n\
\n\
lxc-checkpoint checkpoints a container\n\
\n\
Options :\n\
  -n, --name=NAME           NAME for name of the container\n\
  -D, --checkpoint-dir=DIR directory to save the checkpoint in\n\
",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int ret;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(1);

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "System error loading %s\n", my_args.name);
		exit(1);
	}

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", my_args.name);
		lxc_container_put(c);
		exit(1);
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "%s is not defined\n", my_args.name);
		lxc_container_put(c);
		exit(1);
	}


	if (!c->is_running(c)) {
		fprintf(stderr, "%s not running, not checkpointing.\n", my_args.name);
		lxc_container_put(c);
		exit(1);
	}

	ret = c->checkpoint(c, checkpoint_dir);
	lxc_container_put(c);

	if (ret < 0) {
		fprintf(stderr, "Checkpointing %s failed.\n", my_args.name);
		if (ret == -ENOSYS)
			fprintf(stderr, "CRIU was not enabled at compile time.\n");
		return 1;
	}

	return 0;
}
