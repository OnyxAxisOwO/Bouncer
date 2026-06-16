"""
title: Bouncer
version: 0.6.0
author: Open WebUI Community (Optimized & IP Hardened)
description: 工业级访问控制与频率限制过滤器。支持账户/IP 双层限流、Cloudflare真实IP识别、上下文裁剪、关键词过滤、动态冷却提示。
license: MIT
"""

import re
import json
import time
from typing import Optional, Callable, Awaitable, Any
from pydantic import BaseModel, Field

# 全局限流存储
GLOBAL_USER_HISTORY = {}
GLOBAL_IP_HISTORY = {}


class Filter:
    class Valves(BaseModel):
        config_json: str = Field(
            default='{"base":{"enabled":true,"admin_effective":false}}',
            description="请使用 Bouncer Config Editor 快速生成配置 JSON 并粘贴于此。",
        )

    def __init__(self):
        self.valves = self.Valves()
        print("=== BOUNCER INIT ===")

    # =========================================================
    # 配置解析
    # =========================================================
    def get_cfg(self):
        try:
            return json.loads(self.valves.config_json)
        except json.JSONDecodeError as e:
            print(f"🚨 BOUNCER 配置错误: JSON 格式非法! 错误信息: {e}")
            return {"base": {"enabled": False}}

    # =========================================================
    # 用户信息脱敏
    # =========================================================
    def safe_user(self, user):
        if not isinstance(user, dict):
            return user

        u = dict(user)

        for k in ("profile_image_url", "profile_banner_image_url"):
            if k in u:
                u[k] = "<omitted>"

        return u

    # =========================================================
    # 获取真实客户端IP
    # Cloudflare -> XFF -> request.client.host
    # =========================================================
    def _get_client_ip(self, request):
        if not request:
            return "unknown"

        try:
            headers = request.headers

            # Cloudflare真实IP
            cf_ip = headers.get("cf-connecting-ip")
            if cf_ip:
                return cf_ip.strip()

            # 反向代理
            xff = headers.get("x-forwarded-for")
            if xff:
                return xff.split(",")[0].strip()

            # fallback
            return request.client.host

        except Exception:
            return "unknown"

    # =========================================================
    # 提取消息文本
    # =========================================================
    def _extract_text(self, msg, filter_media=True):
        if not msg:
            return ""

        content = msg.get("content", "")

        # 纯文本
        if isinstance(content, str):
            return content

        # 多模态
        if isinstance(content, list):
            parts = []

            for p in content:
                if not isinstance(p, dict):
                    continue

                ptype = p.get("type", "")

                # 文本块
                if ptype == "text" or "text" in p:
                    parts.append(p.get("text", ""))
                    continue

                # 非文本
                if filter_media:
                    label = ptype or "media"
                    parts.append(f"<{label} omitted>")
                else:
                    raw = json.dumps(p, ensure_ascii=False)

                    if len(raw) > 200:
                        raw = raw[:200] + "...<truncated>"

                    parts.append(raw)

            return " ".join(parts)

        return str(content)

    # =========================================================
    # 输入/输出日志
    # =========================================================
    def _log_messages(self, body, log_cfg, direction):
        filter_media = log_cfg.get("filter_media", True)

        msgs = body.get("messages", [])

        if not isinstance(msgs, list):
            return

        if direction == "inlet":
            target_role, prefix = "user", "📥 INPUT"
        else:
            target_role, prefix = "assistant", "📤 OUTPUT"

        last = next(
            (m for m in reversed(msgs) if m.get("role") == target_role),
            None,
        )

        print(f"{prefix}: " f"{self._extract_text(last, filter_media=filter_media)}")

    # =========================================================
    # 文本屏蔽
    # =========================================================
    def _mask_text(self, text, pattern, mask_mode, custom_mask):
        if not text:
            return text, False

        hit = {"found": False}

        def _repl(m):
            hit["found"] = True

            matched = m.group(0)

            if mask_mode == "star":
                return "*" * len(matched)

            elif mask_mode == "custom":
                return custom_mask

            else:
                return "#" * len(matched)

        new_text = pattern.sub(_repl, text)

        return new_text, hit["found"]

    # =========================================================
    # 关键词过滤
    # =========================================================
    def _apply_keyword_filter(self, body, kw_cfg, dprint):
        keywords = [k for k in kw_cfg.get("keywords", []) if k]

        if not keywords:
            return False, ""

        pattern = re.compile(
            "|".join(re.escape(k) for k in keywords),
            re.IGNORECASE,
        )

        mode = kw_cfg.get("mode", "mask")
        scan_roles = kw_cfg.get("scan_roles", ["user"])
        mask_mode = kw_cfg.get("mask_mode", "hash")
        custom_mask = kw_cfg.get("custom_mask", "(此内容已屏蔽)")

        msgs = body.get("messages", [])

        if not isinstance(msgs, list):
            return False, ""

        any_masked = False

        for msg in msgs:
            if not isinstance(msg, dict):
                continue

            if msg.get("role") not in scan_roles:
                continue

            content = msg.get("content", "")

            # BLOCK模式
            if mode == "block":

                if isinstance(content, str):
                    m = pattern.search(content)

                    if m:
                        return True, m.group(0)

                elif isinstance(content, list):

                    for p in content:
                        if isinstance(p, dict) and isinstance(p.get("text"), str):
                            m = pattern.search(p["text"])

                            if m:
                                return True, m.group(0)

                continue

            # MASK模式
            if isinstance(content, str):

                new_text, hit = self._mask_text(
                    content,
                    pattern,
                    mask_mode,
                    custom_mask,
                )

                if hit:
                    msg["content"] = new_text
                    any_masked = True

            elif isinstance(content, list):

                for p in content:
                    if isinstance(p, dict) and isinstance(p.get("text"), str):

                        new_text, hit = self._mask_text(
                            p["text"],
                            pattern,
                            mask_mode,
                            custom_mask,
                        )

                        if hit:
                            p["text"] = new_text
                            any_masked = True

        if any_masked:
            dprint(f"🔇 关键词过滤: 已屏蔽命中内容 " f"(mask/{mask_mode})")

        return False, ""

    # =========================================================
    # 主入口
    # =========================================================
    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __request__=None,
        __event_emitter__: Optional[Callable[[Any], Awaitable[None]]] = None,
    ) -> dict:

        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})

        # 日志闭包
        def dprint(*args):
            if log_cfg.get("enabled", True) and log_cfg.get("bouncer_log", True):
                print(*args)

        dprint("\n=== BOUNCER RUNNING ===")

        # =========================================================
        # 全局开关
        # =========================================================
        if not cfg.get("base", {}).get("enabled", True):
            dprint("💡 Bouncer disabled globally.")
            return body

        if not __user__:
            dprint("🚨 错误: 未能获取到用户上下文")
            return body

        # =========================================================
        # 管理员豁免
        # =========================================================
        user_role = __user__.get("role", "user")

        admin_effective = cfg.get("base", {}).get("admin_effective", True)

        if user_role == "admin" and not admin_effective:
            dprint("👑 管理员触发豁免")
            return body

        user_id = __user__.get("id", "unknown")
        email = __user__.get("email", "unknown")
        current_model = body.get("model", "")

        # =========================================================
        # 获取真实IP
        # =========================================================
        client_ip = self._get_client_ip(__request__)

        if log_cfg.get("user_dict", True):
            dprint(f"USER: {email} | " f"IP: {client_ip} | " f"MODEL: {current_model}")
        else:
            dprint(
                f"USER: <redacted> | " f"IP: {client_ip} | " f"MODEL: {current_model}"
            )

        # =========================================================
        # 白名单 / 黑名单
        # =========================================================
        is_exempt = False

        exemption_cfg = cfg.get("exemption", {})

        if exemption_cfg.get("enabled", False) and email in exemption_cfg.get(
            "emails", []
        ):
            dprint(f"😇 用户 {email} 在豁免名单中")
            is_exempt = True

        if not is_exempt:

            # 黑名单
            for ban_rule in cfg.get("ban_reasons", []):

                if email in ban_rule.get("emails", []):

                    deny_msg = ban_rule.get(
                        "msg",
                        "Account Suspended",
                    )

                    dprint(f"🚫 拦截: 用户 {email} 在黑名单中")

                    raise Exception(deny_msg)

            # 白名单
            whitelist_cfg = cfg.get("whitelist", {})

            if whitelist_cfg.get("enabled", False) and email not in whitelist_cfg.get(
                "emails", []
            ):

                deny_msg = cfg.get(
                    "custom_strings",
                    {},
                ).get(
                    "whitelist_deny",
                    "Access Denied: Not in whitelist.",
                )

                raise Exception(deny_msg)

        # =========================================================
        # 用户组决议
        # =========================================================
        user_groups = sorted(
            cfg.get("user_groups", []),
            key=lambda x: x.get("priority", 0),
            reverse=True,
        )

        my_ug = None

        for ug in user_groups:
            if email in ug.get("emails", []):
                my_ug = ug
                break

        if not my_ug:
            for ug in user_groups:
                if ug.get("id") == "default":
                    my_ug = ug
                    break

        if not my_ug:
            my_ug = {
                "id": "default",
                "name": "Fallback",
                "default_permissions": {},
            }

        # =========================================================
        # 模型组决议
        # =========================================================
        my_mg = {
            "id": "default",
            "name": "Default Models",
            "ads": {},
        }

        for mg in cfg.get("model_groups", []):
            if current_model in mg.get("models", []):
                my_mg = mg
                break

        dprint(
            f"🎯 匹配路线: "
            f"[用户组: {my_ug.get('name')}] "
            f"-> "
            f"[模型组: {my_mg.get('name')}]"
        )

        permissions = my_ug.get("permissions", {})

        if my_mg["id"] in permissions:
            limit_cfg = permissions[my_mg["id"]]
        else:
            limit_cfg = my_ug.get(
                "default_permissions",
                {},
            )

        # =========================================================
        # 上下文裁剪
        # =========================================================
        clip_val = limit_cfg.get("clip", 0)

        if clip_val > 0 and "messages" in body and isinstance(body["messages"], list):

            original_len = len(body["messages"])

            if original_len > clip_val:

                body["messages"] = body["messages"][-clip_val:]

                dprint(
                    f"✂️ 上下文裁剪: "
                    f"保留最近 {clip_val} 条 "
                    f"(原 {original_len} 条)"
                )

        # =========================================================
        # 关键词过滤
        # =========================================================
        if not is_exempt:

            if "keyword_filter" in my_mg:
                kw_cfg = my_mg["keyword_filter"]
            else:
                kw_cfg = cfg.get("keyword_filter", {})

            if kw_cfg.get("enabled", False):

                blocked, hit_kw = self._apply_keyword_filter(
                    body,
                    kw_cfg,
                    dprint,
                )

                if blocked:

                    deny_msg = kw_cfg.get(
                        "block_msg",
                        "您的消息包含敏感内容，已被拦截。",
                    )

                    dprint(f"🚫 关键词拦截: " f"命中 '{hit_kw}'")

                    raise Exception(deny_msg)

        # =========================================================
        # 输入日志
        # =========================================================
        if log_cfg.get("enabled", True) and log_cfg.get("inlet", False):
            self._log_messages(body, log_cfg, "inlet")

        # =========================================================
        # 豁免放行
        # =========================================================
        if is_exempt:
            dprint("✅ 流控放行 (豁免身份)")
            return body

        # =========================================================
        # 用户级限流
        # =========================================================
        rpm = limit_cfg.get("rpm", 0)
        rph = limit_cfg.get("rph", 0)
        win_time = limit_cfg.get("win_time", 0)
        win_limit = limit_cfg.get("win_limit", 0)

        now = time.time()

        global GLOBAL_USER_HISTORY

        is_global_limit = cfg.get(
            "global_limit",
            {},
        ).get("enabled", False)

        history_key = user_id if is_global_limit else f"{user_id}::{my_mg['id']}"

        if history_key not in GLOBAL_USER_HISTORY:
            GLOBAL_USER_HISTORY[history_key] = []

        history = GLOBAL_USER_HISTORY[history_key]

        max_history_sec = max(
            3600,
            win_time * 60,
        )

        history = [t for t in history if now - t < max_history_sec]

        rpm_history = [t for t in history if now - t < 60]

        rph_history = [t for t in history if now - t < 3600]

        win_history = [t for t in history if now - t < (win_time * 60)]

        is_rate_limited = False
        limit_reason = ""
        seconds_to_wait = 0

        # RPM
        if rpm > 0 and len(rpm_history) >= rpm:

            is_rate_limited = True

            limit_reason = f"每分钟最多请求 {rpm} 次"

            seconds_to_wait = max(
                1,
                int(rpm_history[0] + 60 - now),
            )

        # RPH
        elif rph > 0 and len(rph_history) >= rph:

            is_rate_limited = True

            limit_reason = f"每小时最多请求 {rph} 次"

            seconds_to_wait = max(
                1,
                int(rph_history[0] + 3600 - now),
            )

        # 自定义窗口
        elif win_time > 0 and win_limit > 0 and len(win_history) >= win_limit:

            is_rate_limited = True

            limit_reason = f"{win_time}分钟内最多请求 " f"{win_limit} 次"

            seconds_to_wait = max(
                1,
                int(win_history[0] + (win_time * 60) - now),
            )

        # 命中用户限流
        if is_rate_limited:

            resume_epoch = now + seconds_to_wait

            resume_time_str = time.strftime(
                "%H:%M:%S",
                time.localtime(resume_epoch),
            )

            if seconds_to_wait < 60:
                wait_str = f"{seconds_to_wait} 秒"
            else:
                wait_str = (
                    f"{int(seconds_to_wait // 60)} 分 "
                    f"{int(seconds_to_wait % 60)} 秒"
                )

            raise Exception(
                "🚨 账户请求频率超限！\n"
                f"原因: {limit_reason}\n"
                f"请在 {wait_str} 后重试\n"
                f"预计恢复时间: {resume_time_str}"
            )

        # IP限流
        ip_cfg = cfg.get("ip_limit", {})

        ip_enabled = ip_cfg.get("enabled", False)

        if ip_enabled:

            global GLOBAL_IP_HISTORY

            ip_rpm = ip_cfg.get("rpm", 0)
            ip_rph = ip_cfg.get("rph", 0)
            ip_win_time = ip_cfg.get("win_time", 0)
            ip_win_limit = ip_cfg.get("win_limit", 0)

            if client_ip not in GLOBAL_IP_HISTORY:
                GLOBAL_IP_HISTORY[client_ip] = []

            ip_history = GLOBAL_IP_HISTORY[client_ip]

            ip_max_history_sec = max(
                3600,
                ip_win_time * 60,
            )

            ip_history = [t for t in ip_history if now - t < ip_max_history_sec]

            ip_rpm_history = [t for t in ip_history if now - t < 60]

            ip_rph_history = [t for t in ip_history if now - t < 3600]

            ip_win_history = [t for t in ip_history if now - t < (ip_win_time * 60)]

            ip_limited = False
            ip_reason = ""
            ip_wait = 0

            # RPM
            if ip_rpm > 0 and len(ip_rpm_history) >= ip_rpm:

                ip_limited = True

                ip_reason = f"同IP每分钟最多 " f"{ip_rpm} 次请求"

                ip_wait = max(
                    1,
                    int(ip_rpm_history[0] + 60 - now),
                )

            # RPH
            elif ip_rph > 0 and len(ip_rph_history) >= ip_rph:

                ip_limited = True

                ip_reason = f"同IP每小时最多 " f"{ip_rph} 次请求"

                ip_wait = max(
                    1,
                    int(ip_rph_history[0] + 3600 - now),
                )

            # 自定义窗口
            elif (
                ip_win_time > 0
                and ip_win_limit > 0
                and len(ip_win_history) >= ip_win_limit
            ):

                ip_limited = True

                ip_reason = (
                    f"{ip_win_time}分钟内 " f"同IP最多请求 " f"{ip_win_limit} 次"
                )

                ip_wait = max(
                    1,
                    int(ip_win_history[0] + (ip_win_time * 60) - now),
                )

            # 命中IP限流
            if ip_limited:

                ip_resume_epoch = now + ip_wait

                ip_resume_time = time.strftime(
                    "%H:%M:%S",
                    time.localtime(ip_resume_epoch),
                )

                if ip_wait < 60:
                    ip_wait_str = f"{ip_wait} 秒"
                else:
                    ip_wait_str = f"{int(ip_wait // 60)} 分 " f"{int(ip_wait % 60)} 秒"

                dprint(f"🚫 IP限流触发 " f"IP={client_ip} " f"WAIT={ip_wait_str}")

                raise Exception(
                    "🚨 当前IP请求频率过高！\n"
                    f"IP: {client_ip}\n"
                    f"原因: {ip_reason}\n"
                    f"请在 {ip_wait_str} 后重试\n"
                    f"预计恢复时间: {ip_resume_time}"
                )

            # 记录IP请求
            ip_history.append(now)

            GLOBAL_IP_HISTORY[client_ip] = ip_history

        # =========================================================
        # 记录用户请求
        # =========================================================
        history.append(now)

        GLOBAL_USER_HISTORY[history_key] = history

        dprint(
            f"✅ 流控放行 "
            f"[USER={history_key}] "
            f"[IP={client_ip}] "
            f"[RPM={len(rpm_history)+1}]"
        )

        return body

    # =========================================================
    # Stream Hook
    # =========================================================
    async def stream(self, event: dict) -> dict:
        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})

        if log_cfg.get("enabled", True) and log_cfg.get("stream", False):

            raw = json.dumps(event, ensure_ascii=False)

            if len(raw) > 500:
                raw = raw[:500] + "...<truncated>"

            print(f"🌀 STREAM: {raw}")

        return event

    # =========================================================
    # Outlet Hook
    # =========================================================
    async def outlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
    ) -> dict:

        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})

        if log_cfg.get("enabled", True) and log_cfg.get("outlet", False):
            self._log_messages(body, log_cfg, "outlet")

        return body
