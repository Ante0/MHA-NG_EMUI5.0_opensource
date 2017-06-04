/**
 * main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "f2fs_fs.h"
#include "sload.h"
#include <libgen.h>
#include <dirent.h>
#include "node.h"

void sload_usage()
{
    MSG(0, "\nUsage: sload.f2fs [options] device\n");
    MSG(0, "[options]:\n");
	MSG(0, "  -f source directory [path of the source directory]\n");
	MSG(0, "  -t mount point [prefix of target fs path, default:/]\n");
    MSG(0, "  -d debug level [default:0]\n");
    exit(1);
}

void f2fs_parse_options(int argc, char *argv[], char **source, char **mount)
{
    int option = 0;
    char *prog = basename(argv[0]);

    if (!strcmp("sload.f2fs", prog)) {
        const char *option_string = "d:f:t:";

        while ((option = getopt(argc, argv, option_string)) != EOF) {
            switch (option) {
            case 'd':
                config.dbg_lv = atoi(optarg);
                MSG(0, "Info: Debug level = %d\n",
                            config.dbg_lv);
                break;
            case 'f':
				*source = (char *)optarg;
                break;
			case 't':
				*mount = (char *)optarg;
				break;
            default:
                MSG(0, "\tError: Unknown option %c\n", option);
                sload_usage();
                break;
            }
        }
    }
	if (!(*source)) {
        MSG(0, "\tError: Source directory not speified\n");
        sload_usage();
	}
    if ((optind + 1) != argc) {
        MSG(0, "\tError: Device not specified\n");
        sload_usage();
    }
    config.device_name = argv[optind];
}

int main(int argc, char **argv)
{
	char *fromDir, *mountPoint;

	fromDir = NULL;
	mountPoint = NULL;

	f2fs_init_configuration(&config);
	f2fs_parse_options(argc, argv, &fromDir, &mountPoint);
	if (f2fs_dev_is_umounted(&config) < 0)
		return -1;
	/* Get device */
	if (f2fs_get_device_info(&config) < 0)
		return -1;

	f2fs_format_with_source(fromDir, mountPoint);

	f2fs_finalize_device(&config);
	return 0;
}
