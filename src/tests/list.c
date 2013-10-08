/* list.c
 *
 * Copyright © 2013 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
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
#include <stdlib.h>
#include <lxc/lxccontainer.h>

int main(int argc, char *argv[])
{
	char *lxcpath = NULL;
	struct lxc_container **clist;
	int n, n2;

	if (argc > 1)
		lxcpath = argv[1];

	n = list_defined_containers(lxcpath, NULL);
	printf("Found %d defined containers\n", n);
	n2 = list_defined_containers(lxcpath, &clist);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (n=0; n<n2; n++) {
		struct lxc_container *c = clist[n];
		printf("Found defined container %s\n", c->name);
		lxc_container_put(c);
	}
	free(clist);

	n = list_active_containers(lxcpath, NULL);
	printf("Found %d active containers\n", n);
	n2 = list_active_containers(lxcpath, &clist);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (n=0; n<n2; n++) {
		printf("Found active container %s\n", clist[n]->name);
		lxc_container_put(clist[n]);
	}
	free(clist);

	exit(0);
}
