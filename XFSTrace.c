#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xfs/xfs.h>
#include <xfs/xfs_fs.h>
#include <xfs/xfs_format.h>
#include "xfs.skel.h"
#include "output_helpers.h"
#include "maps_helpers.h"
#include "partitions_helpers.h"


static struct config {
	char *dev;
	time_t interval;
	bool verbose;
	int times;
} config = {
	.interval = 5,
	.times = 100000000,
};

struct xfs_config{
	unsigned int block_size;
	unsigned int sector_size;
	unsigned int inode_size;
	unsigned int ag_blocks;
	unsigned int data_blocks;
	unsigned int ag_count;
	unsigned long long system_up;
} xfs_config = {

};

char buffer[20];
__u64 ag_sizes[MAX_AG_CNT] = {};

FILE *fp_ag;
bool exiting;
const char *argp_program_version = "XFSTrace 4.0";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show XFS filesystem pattern.\n"
"\n"
"USAGE: XFSTrace [--help] [-d DEV] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    XFSTrace -d /dev/nvme0n1		# trace sdc only(must be the absolute path)\n"
"    XFSTrace -d /dev/nvme0n1 1 10	# print 1 second summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "verbose", 'V', NULL, 0, "Verbose debug output" },
	{ "dev", 'd', "DEVICE", 0, "Trace this device where the target XFS is made only" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'd':
    	config.dev = arg;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			config.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			config.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
    	return ARGP_ERR_UNKNOWN;	
	}
	
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !config.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

int endian_convert_b_to_l(__u64 num, int lenth)
{
	unsigned char *p = &num;
	__u64 res = 0;
	for(int i = 0; i < lenth; i++){
		int off = (lenth - 1 - i) * 8;
		__u64 it = *(p+i) << off;
		res += it;
	}
	return res;
}

void print_ag_infos(int fd_ag_infos)
{
	struct ag_infos ag_infos_val = {};
	char path[50];
	char string[50];

	my_print(fp_ag, true, "%s", buffer);
	my_print(fp_ag, false, "%-5s %-12s %-20s %-20s ", 
		"agno", "ag_size(MB)"/*, "buffer_read_cnt"*/, "direct_read_cnt", "buffer_write_cnt");
	my_print(fp_ag, true, "%-20s %-20s %-20s", 
		"direct_write_cnt", "buffer_update_cnt", "direct_update_cnt");
	for(int key = 0; key < xfs_config.ag_count; key++){
		bool bre = true;
		if(bpf_map_lookup_elem(fd_ag_infos, &key, &ag_infos_val))
			continue;
		for (int i = 0; i < RWU_TYPE_CNT; i++) {
			if (ag_infos_val.rwu_cnt[i])
				bre = false;
		}
		if (bre)
			break;
		my_print(fp_ag, false, "%-5d %-12lld %-20lld %-20lld ", 
			key, ag_infos_val.ag_size, /*ag_infos_val.rwu_cnt[RWU_TYPE_BUFFER_READ],*/
			ag_infos_val.rwu_cnt[RWU_TYPE_DIRECT_READ], ag_infos_val.rwu_cnt[RWU_TYPE_BUFFER_WRITE]);
		my_print(fp_ag, true, "%-20lld %-20lld %-20lld",  
			ag_infos_val.rwu_cnt[RWU_TYPE_DIRECT_WRITE], ag_infos_val.rwu_cnt[RWU_TYPE_BUFFER_UPDATE],
			ag_infos_val.rwu_cnt[RWU_TYPE_DIRECT_UPDATE]);
	}
}

static int get_mounts_dir_by_dev(const char* dev, char* dir)
{
	FILE* f;
	char mount_dev[256];
	char mount_dir[256];
	char mount_type[256];
	char mount_opts[256];
	int mount_freq;
	int mount_passno;
	int match;

	f = fopen("/proc/mounts", "r");
	if (!f) {
		fprintf(stdout, "could not open /proc/mounts\n");
		return -1;
	}

	do {
		match = fscanf(f, "%255s %255s %255s %255s %d %d\n",
			mount_dev, mount_dir, mount_type,
			mount_opts, &mount_freq, &mount_passno);
		if (match == 6 && strcmp(dev, mount_dev) == 0) {
			memcpy(dir, mount_dir, sizeof(mount_dir));
			fclose(f);
			return 0;
		}
	} while (match != EOF);

	fclose(f);
	return -1;
}

void initialize_map_ag_infos(int fd_ag_infos)
{
	struct ag_infos ag_infos_val = {};

	for(int key = 0; key < xfs_config.ag_count; key++){
		ag_infos_val.ag_size = ag_sizes[key];
		if (bpf_map_update_elem(fd_ag_infos, &key, &ag_infos_val, BPF_ANY) != 0) {
			perror("failed to update map!");
			continue;
		}
	}
}

void xfs_info_get(){
	struct sysinfo info;
	time_t curtime;
	if (sysinfo(&info)) {
		fprintf(stderr, "Failed to get sysinfo, errno:%u, reason:%s\n", errno, strerror(errno));
	}
	time(&curtime);
	xfs_config.system_up = curtime - info.uptime;
	int fd_xfs_dev = open(config.dev, O_RDONLY);
	if (fd_xfs_dev < 0) {
		perror("fail!");
		return;
	}
	struct xfs_sb sb;
	if(pread(fd_xfs_dev, &sb, sizeof(sb), 0) != sizeof(sb)){
		perror("fail!");
		return;
	}
	xfs_config.block_size = endian_convert_b_to_l(sb.sb_blocksize, sizeof(sb.sb_blocksize));
	xfs_config.sector_size = endian_convert_b_to_l(sb.sb_sectsize, sizeof(sb.sb_sectsize));
	xfs_config.inode_size = endian_convert_b_to_l(sb.sb_inodesize, sizeof(sb.sb_inodesize));
	xfs_config.ag_blocks = endian_convert_b_to_l(sb.sb_agblocks, sizeof(sb.sb_agblocks));
	xfs_config.data_blocks = endian_convert_b_to_l(sb.sb_dblocks, sizeof(sb.sb_dblocks));
	xfs_config.ag_count = endian_convert_b_to_l(sb.sb_agcount, sizeof(sb.sb_agcount));

	for(int i = 0; i < xfs_config.ag_count; i++){
		//AG Size info
		if(i == xfs_config.ag_count - 1)
			ag_sizes[i] = xfs_config.data_blocks % xfs_config.ag_blocks;
		else
			ag_sizes[i] = xfs_config.ag_blocks;
		ag_sizes[i] *= xfs_config.block_size;
		ag_sizes[i] /= 1024*1024;
	}
}

void get_device_name_from_path(char *device_name) {
	int len = strlen(config.dev);
	int pos;
	for (pos = len - 1; pos >= 0; pos--) {
		if (config.dev[pos] == '/') break;
	}
	pos = pos >= 0 ? pos + 1 : 0;
	memcpy(device_name, config.dev + pos, sizeof(device_name));
}

int main(int argc, char **argv)
{
	time_t cur_time;
	struct tm* info;
	int fd_ag_infos;                                       //bpf file descriptor	
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct xfs_bpf *obj;
	struct statfs sfs;
	int err;
	char device_name[20];
	char mount_dir[256];

	fp_ag = fopen("result/ag_infos.log", "w");
	if(!fp_ag)
    	goto cleanup;
	
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if (!config.dev) {
		fprintf(stderr, "error: no device is offered\n");
		goto cleanup;
	}
	//if the dev is mounted or made by xfs
	if (get_mounts_dir_by_dev(config.dev, mount_dir)) {
		fprintf(stderr, "error: failed to find %s\n", config.dev);
		goto cleanup;
	}	
	statfs(mount_dir, &sfs);
	if (sfs.f_type != XFS_SUPER_MAGIC) {
		fprintf(stderr, "error: the fs is not xfs\n");
		goto cleanup;
	}

	//get the device_name like nvme0n1
	get_device_name_from_path(device_name);
	struct partitions* partitions = partitions__load();
	if (!partitions) {
		fprintf(stderr, "error: failed to load partitions\n");
		goto cleanup;
	}
	struct partition* partition = partitions__get_by_name(partitions, device_name);
	if (!partition) {
		fprintf(stderr, "error: failed to find the dev in partitions\n");
		goto cleanup;
	}
	libbpf_set_print(libbpf_print_fn);
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	/* bpf open */
	obj = xfs_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "error: failed to open BPF object\n");
		goto cleanup;
	}

	/* XFS configuration */
	xfs_info_get();
	obj->rodata->ag_count = xfs_config.ag_count;
	obj->rodata->device_num = partition->dev;
	//printf("dev:%d\n", partition->dev);

	/* bpf load */
	err = xfs_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* bpf attach */
	err = xfs_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	/* INT EVENT */
	signal(SIGINT, sig_handler);

	/* program begin */
	printf("Performing the initial configuration...\n");
	/* initialize the MAP map_ag_infos */
	fd_ag_infos = bpf_map__fd(obj->maps.map_ag_infos);
	initialize_map_ag_infos(fd_ag_infos);

	printf("Tracing a device with XFS filesystem... Hit Ctrl-C to end.\n");
	/* main: poll */
	my_print(fp_ag, true, "ag_count:%d", xfs_config.ag_count);
	while (!exiting) {
		sleep(config.interval);
		time(&cur_time);
		info = localtime(&cur_time);
		strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);

		print_ag_infos(fd_ag_infos);
	}
cleanup:
	xfs_bpf__destroy(obj);
	partitions__free(partitions);
	fclose(fp_ag);
	close(fd_ag_infos);
	return 0;
}
