/*
 * liboak.h — OPENOS Settings API (OAK 加密通信)
 *
 * 让应用程序通过 OAK 加密通道与 OPENOS Security / 设置守护通信，
 * 并自动创建设置守护 + 在应用首次请求时询问用户授权。
 *
 * 流程:
 *   1. 应用调用 oak_settings_request() -> 通过 OAK-SK 派生密钥加密请求
 *   2. liboak 发现 openos-settingsd 未运行 -> 自动拉起 (fork/exec)
 *   3. settingsd 收到请求 -> 若该应用未授权, 弹通知询问用户允许/拒绝
 *   4. 用户允许 -> 持久化授权 -> 转发到 /proc/oak/subjects (内核)
 *   5. 返回: OAK_OK / OAK_DENIED / OAK_PENDING (等待用户确认)
 *
 * 加密: 与 openos-securityd 相同 (H2 = SHA256(H1 + OAK-SK)), OAK-SK 从
 *       环境变量 OPENOS_OAK_SK 或 KEYS/.private/oak-sk.key 读取。
 *
 * 依赖: libsodium (SHA-256)。C 接口, 供应用链接。
 */

#ifndef OPENOS_LIBOAK_H
#define OPENOS_LIBOAK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* OAK 操作结果 */
enum oak_status {
	OAK_OK = 0,		/* 成功且已授权 */
	OAK_DENIED,		/* 被拒绝 (用户拒绝/内核拒绝) */
	OAK_PENDING,		/* 已请求, 等待用户授权确认 */
	OAK_ERR_PARAM,		/* 参数错误 */
	OAK_ERR_SOCKET,		/* socket/通信错误 */
	OAK_ERR_CRYPTO,		/* 加密/密钥错误 */
	OAK_ERR_UNAUTH,		/* 未经 OAK 认证 */
};

/* 设置项类别 (对应 /proc/oak 能力) */
enum oak_setting_kind {
	OAK_SET_WATCHDOG = 0,	/* 登记 watchdog PID */
	OAK_SET_BUILTIN,	/* 登记内置守护 PID */
	OAK_SET_WHITELIST,	/* 白名单 add/del */
	OAK_SET_SUBJECT,	/* 子安全主体 register/pubkey */
	OAK_SET_UNLOCK,		/* 解锁凭据 */
	OAK_SET_MAX,
};

/* 单次设置请求 (明文部分, 会被 OAK 加密包裹) */
struct oak_settings_req {
	enum oak_setting_kind kind;
	char target[64];	/* 目标名 (role/subject) */
	char value[256];	/* 值 (pid / capmask / pubkey hex...) */
};

/* ---- 核心 API ---- */

/*
 * 应用请求一个设置变更。
 *   req: 明文设置请求
 *   app_id: 应用标识 (用于授权判断)
 *   app_pubkey: 应用公钥 hex (OAK 注册用, 可空)
 * 返回: OAK_OK 已应用 / OAK_PENDING 等待用户确认 / 其他错误。
 */
enum oak_status oak_settings_request(const struct oak_settings_req *req,
				     const char *app_id,
				     const char *app_pubkey);

/* 查询某应用是否已获授权 (设置守护持久化判断) */
enum oak_status oak_authorized(const char *app_id);

/* 设置 OAK-SK 来源 (默认: env OPENOS_OAK_SK -> KEYS/.private/oak-sk.key) */
void oak_set_sk_path(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* OPENOS_LIBOAK_H */
