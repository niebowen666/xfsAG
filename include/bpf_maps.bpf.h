#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <bpf/bpf_helpers.h>
#include <asm-generic/errno.h>
#include "maps_helpers.h"


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_AG_CNT);
	__type(key, u32);
	__type(value, ag_infos);
} map_ag_infos SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct file_rwu_key);
	__type(value, enum rwu_type);
} map_file_rwu SEC(".maps");

#endif /* __MAPS_BPF_H */
