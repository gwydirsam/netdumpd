/*-
 * Copyright (c) 2017 Dell EMC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/nv.h>

#include <netinet/netdump/netdump.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libcasper.h>
#include <libcasper_service.h>

#include "netdumpd.h"

/* XXX this gets relative paths */
int
netdump_cap_handler(cap_channel_t *cap, const char *reason, const char *ip,
    const char *hostname, const char *infofile, const char *corefile)
{
	nvlist_t *nvl;
	int error;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "exec_handler");
	nvlist_add_string(nvl, "reason", reason);
	nvlist_add_string(nvl, "ip", ip);
	nvlist_add_string(nvl, "hostname", hostname);
	nvlist_add_string(nvl, "infofile", infofile);
	nvlist_add_string(nvl, "corefile", corefile);
	nvl = cap_xfer_nvlist(cap, nvl, 0);
	if (nvl == NULL)
		return (errno);

	if (nvlist_exists_number(nvl, "error") &&
	    (error = (int)nvlist_get_number(nvl, "error")) != 0)
		return (error);
	nvlist_destroy(nvl);
	return (0);
}

static int
handler_command(const char *cmd, const nvlist_t *limits, nvlist_t *nvlin,
    nvlist_t *nvlout __unused)
{
	const char *argv[7];
	pid_t pid;
	int fd;

	if (strcmp(cmd, "exec_handler") != 0)
		return (EINVAL);

	fd = nvlist_get_descriptor(limits, "handlerfd");
	/* XXX hack */
	if (lseek(fd, 0, SEEK_SET) != 0)
		return (errno);

	if ((pid = fork()) < 0)
		return (errno);
	if (pid == 0) {
		argv[0] = nvlist_get_string(limits, "handler_script");
		argv[1] = nvlist_get_string(nvlin, "reason");
		argv[2] = nvlist_get_string(nvlin, "ip");
		argv[3] = nvlist_get_string(nvlin, "hostname");
		argv[4] = nvlist_get_string(nvlin, "infofile");
		argv[5] = nvlist_get_string(nvlin, "corefile");
		argv[6] = NULL;
		(void)fexecve(fd, __DECONST(char *const *, argv), NULL);
		_exit(1);
	}
	return (0);
}

static int
handler_limits(const nvlist_t *oldlimits, const nvlist_t *newlimits)
{
	const char *name;
	void *cookie;
	int nvtype;
	bool hasfd, hasscript;

	/* Only allow limits to be set once. */
	if (oldlimits != NULL)
		return (ENOTCAPABLE);

	cookie = NULL;
	hasfd = hasscript = false;
	while ((name = nvlist_next(newlimits, &nvtype, &cookie)) != NULL) {
		if (nvtype == NV_TYPE_DESCRIPTOR &&
		    strcmp(name, "handlerfd") == 0)
			hasfd = true;
		else if (nvtype == NV_TYPE_STRING &&
		    strcmp(name, "handler_script") == 0)
			hasscript = true;
		else
			return (EINVAL);
	}
	if (!hasfd || !hasscript)
		return (EINVAL);
	return (0);
}

CREATE_SERVICE("netdumpd.handler", handler_limits, handler_command, 0);
