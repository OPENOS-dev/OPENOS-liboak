/*
 * Copyright (C) 2026 OPENOS-dev
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the OPENOS-PROJECT-LICENSE (OPL) v1.2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * OPL for more details.
 *
 * You should have received a copy of the OPL along with this program.
 * If not, see <https://github.com/OPENOS-dev/OPL>.
 */

/*
 * liboak.c — OPENOS Settings API 实现 (见 liboak.h)
 * 依赖 libsodium (SHA-256) + POSIX (unix socket / fork/exec)。
 */

#define _GNU_SOURCE
#include "liboak.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>

#define OAK_SOCKET     "/run/openos/oak.sock"       /* openos-securityd */
#define SETTINGS_SOCK  "/run/openos/settingsd.sock" /* openos-settingsd */
#define SK_DEFAULT     "/etc/openos/security/oak-sk.key"
#define HASH_LEN       32
#define SK_MAX         1024

/* 本应用用 OAK-SK 加密 (同一共享密钥) */
static char g_sk_path[256] = SK_DEFAULT;
static unsigned char g_sk[SK_MAX];
static size_t g_sk_len = 0;

void oak_set_sk_path(const char *path)
{
	snprintf(g_sk_path, sizeof g_sk_path, "%s",
		 path ? path : SK_DEFAULT);
}

static int load_sk(void)
{
	FILE *f = fopen(g_sk_path, "rb");
	if (!f)
		return -1;
	g_sk_len = fread(g_sk, 1, sizeof g_sk, f);
	fclose(f);
	while (g_sk_len > 0 &&
	       (g_sk[g_sk_len-1]=='\n' || g_sk[g_sk_len-1]=='\r' ||
		g_sk[g_sk_len-1]==' ' || g_sk[g_sk_len-1]=='\t'))
		g_sk_len--;
	return g_sk_len > 0 ? 0 : -1;
}

/* H2 = SHA256(H1 || OAK-SK); H1 = SHA256(明文请求) */
static int oak_compute_h2(const unsigned char *plain, size_t plain_len,
			  unsigned char h2[32])
{
	unsigned char h1[32];
	unsigned char buf[64 + SK_MAX];

	if (crypto_hash_sha256(h1, plain, plain_len) != 0)
		return -1;
	memcpy(buf, h1, 32);
	memcpy(buf + 32, g_sk, g_sk_len);
	if (crypto_hash_sha256(h2, buf, 32 + g_sk_len) != 0)
		return -1;
	return 0;
}

static void bin2hex(const unsigned char *in, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++)
		sprintf(out + i * 2, "%02x", in[i]);
}

/* ---- Unix socket 发送一行并读响应 ---- */
static int oak_send_recv(const char *path, const char *line,
			 char *resp, size_t resp_sz)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ssize_t n;

	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		close(fd);
		return -1;
	}
	write(fd, line, strlen(line));
	n = read(fd, resp, resp_sz - 1);
	if (n > 0)
		resp[n] = '\0';
	close(fd);
	return n > 0 ? 0 : -1;
}

/* ---- 自动创建设置守护 (若未运行) ---- */
static int ensure_settingsd(void)
{
	/* 探测 socket 是否在 */
	int probe = socket(AF_UNIX, SOCK_STREAM, 0);
	if (probe >= 0) {
		struct sockaddr_un a;
		memset(&a, 0, sizeof a);
		a.sun_family = AF_UNIX;
		strncpy(a.sun_path, SETTINGS_SOCK, sizeof a.sun_path - 1);
		if (connect(probe, (struct sockaddr *)&a, sizeof a) == 0) {
			close(probe);
			return 0;   /* 已在运行 */
		}
		close(probe);
	}

	/* 未运行: fork/exec 启动 openos-settingsd (后台) */
	pid_t pid = fork();
	if (pid == 0) {
		execl("/usr/bin/openos-settingsd", "openos-settingsd",
		      (char *)NULL);
		_exit(127);
	}
	if (pid < 0)
		return -1;
	/* 短暂等待 socket 出现 */
	for (int i = 0; i < 50; i++) {
		usleep(100000);
		probe = socket(AF_UNIX, SOCK_STREAM, 0);
		if (probe >= 0) {
			struct sockaddr_un a;
			memset(&a, 0, sizeof a);
			a.sun_family = AF_UNIX;
			strncpy(a.sun_path, SETTINGS_SOCK,
				sizeof a.sun_path - 1);
			if (connect(probe, (struct sockaddr *)&a,
				    sizeof a) == 0) {
				close(probe);
				return 0;
			}
			close(probe);
		}
	}
	return -1;
}

enum oak_status oak_authorized(const char *app_id)
{
	char line[128], resp[128];

	if (load_sk() != 0)
		return OAK_ERR_CRYPTO;
	snprintf(line, sizeof line, "AUTH %s\n", app_id ? app_id : "?");
	if (oak_send_recv(SETTINGS_SOCK, line, resp, sizeof resp) != 0)
		return OAK_ERR_SOCKET;
	if (strncmp(resp, "GRANTED", 7) == 0)
		return OAK_OK;
	if (strncmp(resp, "PENDING", 7) == 0)
		return OAK_PENDING;
	return OAK_DENIED;
}

enum oak_status oak_settings_request(const struct oak_settings_req *req,
				     const char *app_id,
				     const char *app_pubkey)
{
	char plain[512];
	char h2hex[65];
	char line[640];
	char resp[256];
	unsigned char h2[32];
	int plen;

	if (!req || req->kind < 0 || req->kind >= OAK_SET_MAX)
		return OAK_ERR_PARAM;
	if (load_sk() != 0)
		return OAK_ERR_CRYPTO;

	/* 构造明文请求 */
	plen = snprintf(plain, sizeof plain, "%d %s %s %s %s",
			req->kind, req->target, req->value,
			app_id ? app_id : "?", app_pubkey ? app_pubkey : "");
	if (plen < 0 || (size_t)plen >= sizeof plain)
		return OAK_ERR_PARAM;

	/* OAK 加密: H2 = SHA256(H1 + SK) */
	if (oak_compute_h2((unsigned char *)plain, (size_t)plen, h2) != 0)
		return OAK_ERR_CRYPTO;
	bin2hex(h2, 32, h2hex);

	/* 确保设置守护在运行 */
	if (ensure_settingsd() != 0)
		return OAK_ERR_SOCKET;

	/* 发给 settingsd: SET <kind> <target> <value> <app_id> <H2> */
	snprintf(line, sizeof line, "SET %d %s %s %s %s\n",
		 req->kind, req->target, req->value,
		 app_id ? app_id : "?", h2hex);
	if (oak_send_recv(SETTINGS_SOCK, line, resp, sizeof resp) != 0)
		return OAK_ERR_SOCKET;

	if (strncmp(resp, "OK", 2) == 0)
		return OAK_OK;
	if (strncmp(resp, "PENDING", 7) == 0)
		return OAK_PENDING;
	return OAK_DENIED;
}
