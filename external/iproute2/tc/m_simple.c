

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "utils.h"
#include "tc_util.h"
#include <linux/tc_act/tc_defact.h>

#ifndef SIMP_MAX_DATA
#define SIMP_MAX_DATA   32
#endif
static void explain(void)
{
	fprintf(stderr, "Usage: ... simple STRING\n"
		"STRING being an arbitrary string\n"
		"example: \"simple blah\"\n");
}

static void usage(void)
{
	explain();
	exit(-1);
}

static int
parse_simple(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
	     struct nlmsghdr *n)
{
	struct tc_defact sel = {};
	int argc = *argc_p;
	char **argv = *argv_p;
	int ok = 0;
	struct rtattr *tail;
	char *simpdata = NULL;


	while (argc > 0) {
		if (matches(*argv, "simple") == 0) {
			NEXT_ARG();
			simpdata = *argv;
			ok = 1;
			argc--;
			argv++;
			break;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}

	}

	if (!ok) {
		explain();
		return -1;
	}

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.index, *argv, 10)) {
				fprintf(stderr, "simple: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	if (strlen(simpdata) > (SIMP_MAX_DATA - 1)) {
		fprintf(stderr, "simple: Illegal string len %zu <%s> \n",
			strlen(simpdata), simpdata);
		return -1;
	}

	sel.action = TC_ACT_PIPE;

	tail = NLMSG_TAIL(n);
	addattr_l(n, MAX_MSG, tca_id, NULL, 0);
	addattr_l(n, MAX_MSG, TCA_DEF_PARMS, &sel, sizeof(sel));
	addattr_l(n, MAX_MSG, TCA_DEF_DATA, simpdata, SIMP_MAX_DATA);
	tail->rta_len = (char *)NLMSG_TAIL(n) - (char *)tail;

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_simple(struct action_util *au, FILE * f, struct rtattr *arg)
{
	struct tc_defact *sel;
	struct rtattr *tb[TCA_DEF_MAX + 1];
	char *simpdata;

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_DEF_MAX, arg);

	if (tb[TCA_DEF_PARMS] == NULL) {
		fprintf(f, "[NULL simple parameters]");
		return -1;
	}
	sel = RTA_DATA(tb[TCA_DEF_PARMS]);

	if (tb[TCA_DEF_DATA] == NULL) {
		fprintf(f, "[missing simple string]");
		return -1;
	}

	simpdata = RTA_DATA(tb[TCA_DEF_DATA]);

	fprintf(f, "Simple <%s>\n", simpdata);
	fprintf(f, "\t index %d ref %d bind %d", sel->index,
		sel->refcnt, sel->bindcnt);

	if (show_stats) {
		if (tb[TCA_DEF_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_DEF_TM]);
			print_tm(f, tm);
		}
	}
	fprintf(f, "\n");

	return 0;
}

struct action_util simple_action_util = {
	.id = "simple",
	.parse_aopt = parse_simple,
	.print_aopt = print_simple,
};
