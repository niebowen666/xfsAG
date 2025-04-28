#ifndef __PARTITIOS_HELPERS_H
#define __PARTITIOS_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define DISK_NAME_LEN	32

struct partition {
	char *name;
	unsigned int dev;
};

struct partitions {
	struct partition *items;
	int sz;
};

struct partitions *partitions__load(void);
void partitions__free(struct partitions *partitions);
const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev);
const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name);


#endif
