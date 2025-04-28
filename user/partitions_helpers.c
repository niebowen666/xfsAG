#include "partitions_helpers.h"
#include "kernel_helpers.h"

char targ_dev_prefix[] = "nvme";
bool cmp_dev_nvme(char *dev_name, int lenth){
    for(int i = 0; i < lenth && dev_name != '\0'; i++){
        if(i >= 4) return true;
        if(dev_name[i] != targ_dev_prefix[i]) return false;
    }
    return false;
}

static int partitions__add_partition(struct partitions *partitions,
				     const char *name, unsigned int dev)
{
	struct partition *partition;
	void *tmp;

	tmp = realloc(partitions->items, (partitions->sz + 1) *
		sizeof(*partitions->items));
	if (!tmp)
		return -1;
	partitions->items = tmp;
	partition = &partitions->items[partitions->sz];
	partition->name = strdup(name);
	partition->dev = dev;
	partitions->sz++;

	return 0;
}

struct partitions *partitions__load(void)
{
	char part_name[DISK_NAME_LEN];
	unsigned int devmaj, devmin;
	unsigned long long nop;
	struct partitions *partitions;
	char buf[64];
	FILE *f;

	f = fopen("/proc/partitions", "r");
	if (!f)
		return NULL;

	partitions = calloc(1, sizeof(*partitions));
	if (!partitions)
		goto err_out;

	while (fgets(buf, sizeof(buf), f) != NULL) {
		/* skip heading */
		if (buf[0] != ' ' || buf[0] == '\n')
			continue;
		if (sscanf(buf, "%u %u %llu %s", &devmaj, &devmin, &nop,
				part_name) != 4)
			goto err_out;
        if(!cmp_dev_nvme(part_name, DISK_NAME_LEN))
            continue;
		if (partitions__add_partition(partitions, part_name,
						MKDEV(devmaj, devmin)))
			goto err_out;
	}

	fclose(f);
	return partitions;

err_out:
	partitions__free(partitions);
	fclose(f);
	return NULL;
}

void partitions__free(struct partitions *partitions)
{
	int i;

	if (!partitions)
		return;

	for (i = 0; i < partitions->sz; i++)
		free(partitions->items[i].name);
	free(partitions->items);
	free(partitions);
}

const struct partition *
partitions__get_by_dev(const struct partitions *partitions, unsigned int dev)
{
	int i;

	for (i = 0; i < partitions->sz; i++) {
		if (partitions->items[i].dev == dev)
			return &partitions->items[i];
	}

	return NULL;
}

const struct partition *
partitions__get_by_name(const struct partitions *partitions, const char *name)
{
	int i;

	for (i = 0; i < partitions->sz; i++) {
		if (strcmp(partitions->items[i].name, name) == 0)
			return &partitions->items[i];
	}

	return NULL;
}
