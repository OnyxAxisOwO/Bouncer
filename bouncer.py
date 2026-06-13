"""
title: Bouncer
version: 0.5.1
author: Open WebUI Community (Optimized & Sync with WebUI)
description: 工业级访问控制与频率限制过滤器。支持用户组优先级、跨组限流隔离、上下文裁剪、白名单模式认证及动态冷却倒计时提示。
license: MIT
"""

import re
import json
import time
from typing import Optional, Callable, Awaitable, Any
from pydantic import BaseModel, Field

# 全局字典，用于单进程内的内存流控
GLOBAL_USER_HISTORY = {}


class Filter:
    class Valves(BaseModel):
        config_json: str = Field(
            default='{"base":{"enabled":true,"admin_effective":false}}',
            description="请使用 Bouncer Config Editor 快速生成配置 JSON 并粘贴于此。",
        )

    def __init__(self):
        self.valves = self.Valves()
        print("=== BOUNCER INIT ===")

    def get_cfg(self):
        """安全解析 JSON 配置，防止格式错误导致全盘崩溃"""
        try:
            return json.loads(self.valves.config_json)
        except json.JSONDecodeError as e:
            print(f"🚨 BOUNCER 配置错误: JSON 格式非法! 错误信息: {e}")
            return {"base": {"enabled": False}}

    def safe_user(self, user):
        if not isinstance(user, dict):
            return user
        u = dict(user)
        for k in ("profile_image_url", "profile_banner_image_url"):
            if k in u:
                u[k] = "<omitted>"
        return u

    def _extract_text(self, msg, filter_media=True):
        if not msg:
            return ""
        content = msg.get("content", "")

        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts = []
            for p in content:
                if not isinstance(p, dict):
                    continue
                ptype = p.get("type", "")

                if ptype == "text" or "text" in p:
                    parts.append(p.get("text", ""))
                    continue

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
            (m for m in reversed(msgs) if m.get("role") == target_role), None
        )
        print(f"{prefix}: {self._extract_text(last, filter_media=filter_media)}")

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

    def _apply_keyword_filter(self, body, kw_cfg, dprint):
        keywords = [k for k in kw_cfg.get("keywords", []) if k]
        if not keywords:
            return False, ""

        pattern = re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE)

        mode = kw_cfg.get("mode", "mask")
        scan_roles = kw_cfg.get("scan_roles", ["user"])
        mask_mode = kw_cfg.get("mask_mode", "hash")
        custom_mask = kw_cfg.get("custom_mask", "(此内容已屏蔽)")

        msgs = body.get("messages", [])
        if not isinstance(msgs, list):
            return False, ""

        any_masked = False

        for msg in msgs:
            if not isinstance(msg, dict) or msg.get("role") not in scan_roles:
                continue
            content = msg.get("content", "")

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

            if isinstance(content, str):
                new_text, hit = self._mask_text(
                    content, pattern, mask_mode, custom_mask
                )
                if hit:
                    msg["content"] = new_text
                    any_masked = True
            elif isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and isinstance(p.get("text"), str):
                        new_text, hit = self._mask_text(
                            p["text"], pattern, mask_mode, custom_mask
                        )
                        if hit:
                            p["text"] = new_text
                            any_masked = True

        if any_masked:
            dprint(f"🔇 关键词过滤: 已屏蔽命中内容 (mask/{mask_mode})")
        return False, ""

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[Any], Awaitable[None]]] = None,
    ) -> dict:
        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})

        def dprint(*args):
            if log_cfg.get("enabled", True) and log_cfg.get("bouncer_log", True):
                print(*args)

        dprint("\n=== BOUNCER RUNNING ===")

        if not cfg.get("base", {}).get("enabled", True):
            dprint("💡 Bouncer disabled globally.")
            return body

        if not __user__:
            dprint("🚨 错误: 未能获取到用户上下文")
            return body

        user_role = __user__.get("role", "user")
        admin_effective = cfg.get("base", {}).get("admin_effective", True)
        if user_role == "admin" and not admin_effective:
            dprint("👑 管理员触发豁免：Bouncer 过滤器已跳过")
            return body

        user_id = __user__.get("id", "unknown")
        email = __user__.get("email", "unknown")
        current_model = body.get("model", "")

        if log_cfg.get("user_dict", True):
            dprint(f"USER: {email} | MODEL: {current_model}")
        else:
            dprint(f"USER: <redacted> | MODEL: {current_model}")

        # 白名单与黑名单检查
        is_exempt = False
        exemption_cfg = cfg.get("exemption", {})
        if exemption_cfg.get("enabled", False) and email in exemption_cfg.get("emails", []):
            dprint(f"😇 用户 {email} 在豁免名单中，跳过后续所有检查")
            is_exempt = True

        if not is_exempt:
            for ban_rule in cfg.get("ban_reasons", []):
                if email in ban_rule.get("emails", []):
                    deny_msg = ban_rule.get("msg", "Account Suspended")
                    dprint(f"🚫 拦截: 用户 {email} 在黑名单中")
                    raise Exception(deny_msg)

            whitelist_cfg = cfg.get("whitelist", {})
            if whitelist_cfg.get("enabled", False) and email not in whitelist_cfg.get("emails", []):
                deny_msg = cfg.get("custom_strings", {}).get(
                    "whitelist_deny", "Access Denied: Not in whitelist."
                )
                dprint(f"❌ 拦截: 用户 {email} 不不在白名单中")
                raise Exception(deny_msg)

            auth_cfg = cfg.get("auth", {})
            if auth_cfg.get("enabled", False):
                providers = [p.lower() for p in auth_cfg.get("providers", [])]
                deny_msg = auth_cfg.get(
                    "deny_msg", "Access Denied: Your email provider is not supported."
                )
                email_domain = email.split("@")[-1].lower() if "@" in email else ""

                if email_domain not in providers:
                    dprint(f"❌ 拦截: 域名 {email_domain} 触发域名安全策略")
                    raise Exception(deny_msg)

        # 决议用户组与模型组
        user_groups = sorted(
            cfg.get("user_groups", []), key=lambda x: x.get("priority", 0), reverse=True
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
            my_ug = {"id": "default", "name": "Fallback", "default_permissions": {}}

        my_mg = {"id": "default", "name": "Default Models", "ads": {}}
        for mg in cfg.get("model_groups", []):
            if current_model in mg.get("models", []):
                my_mg = mg
                break

        dprint(f"🎯 匹配路线: [用户组: {my_ug.get('name')}] -> [模型组: {my_mg.get('name')}]")

        permissions = my_ug.get("permissions", {})
        if my_mg["id"] in permissions:
            limit_cfg = permissions[my_mg["id"]]
        else:
            limit_cfg = my_ug.get("default_permissions", {})

        if not is_exempt and not limit_cfg.get("enabled", False):
            deny_template = cfg.get("custom_strings", {}).get(
                "group_no_permission",
                "Access Denied: User group '{u_group}' cannot access model group '{m_group}'",
            )
            deny_msg = deny_template.replace(
                "{u_group}", my_ug.get("name", "Unknown")
            ).replace("{m_group}", my_mg.get("name", "Unknown"))
            dprint(f"⛔ 拒绝访问: 用户组权限被关闭 ({deny_msg})")
            raise Exception(deny_msg)

        # 广告公告
        if __event_emitter__ and current_model:
            ad_cfg = my_mg.get("ads", {})
            if not ad_cfg.get("enabled", False):
                ad_cfg = cfg.get("ads", {})

            if ad_cfg.get("enabled", False):
                contents = ad_cfg.get("content", [])
                if contents:
                    import random
                    ad_text = random.choice(contents)
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {"description": f"[AD] {ad_text}", "done": True},
                        }
                    )

        # 上下文裁剪
        clip_val = limit_cfg.get("clip", 0)
        if clip_val > 0 and "messages" in body and isinstance(body["messages"], list):
            original_len = len(body["messages"])
            if original_len > clip_val:
                body["messages"] = body["messages"][-clip_val:]
                dprint(f"✂️ 上下文裁剪: 保留最近 {clip_val} 条 (原 {original_len} 条)")

        # 关键词过滤
        if not is_exempt:
            if "keyword_filter" in my_mg:
                kw_cfg = my_mg["keyword_filter"]
            else:
                kw_cfg = cfg.get("keyword_filter", {})

            if kw_cfg.get("enabled", False):
                blocked, hit_kw = self._apply_keyword_filter(body, kw_cfg, dprint)
                if blocked:
                    deny_msg = kw_cfg.get(
                        "block_msg", "您的消息包含敏感内容，已被拦截，请修改后重试。"
                    )
                    dprint(f"🚫 关键词拦截: 命中 '{hit_kw}' -> {deny_msg}")
                    raise Exception(deny_msg)

        if log_cfg.get("enabled", True) and log_cfg.get("inlet", False):
            self._log_messages(body, log_cfg, "inlet")

        # ====== 8. 多级频率限制与降级 (Rate Limiting & Fallback - 已优化) ======
        if is_exempt:
            dprint("✅ 流控放行 (豁免身份)")
            return body

        rpm = limit_cfg.get("rpm", 0)
        rph = limit_cfg.get("rph", 0)
        win_time = limit_cfg.get("win_time", 0)  # 分钟
        win_limit = limit_cfg.get("win_limit", 0)

        if rpm == 0 and rph == 0 and win_limit == 0:
            dprint("✅ 流控放行 (该组无上限设置)")
            return body

        now = time.time()
        global GLOBAL_USER_HISTORY

        is_global_limit = cfg.get("global_limit", {}).get("enabled", False)
        history_key = user_id if is_global_limit else f"{user_id}::{my_mg['id']}"

        if history_key not in GLOBAL_USER_HISTORY:
            GLOBAL_USER_HISTORY[history_key] = []
        history = GLOBAL_USER_HISTORY[history_key]

        # 清理过期历史（保留最长窗口期的数据，最少保留 1 小时）
        max_history_sec = max(3600, win_time * 60)
        history = [t for t in history if now - t < max_history_sec]

        # 提取各个窗口的时间队列
        rpm_history = [t for t in history if now - t < 60]
        rph_history = [t for t in history if now - t < 3600]
        win_history = [t for t in history if now - t < (win_time * 60)]

        is_rate_limited = False
        limit_reason = ""
        seconds_to_wait = 0  # 核心：计算需要等待的秒数

        if rpm > 0 and len(rpm_history) >= rpm:
            is_rate_limited = True
            limit_reason = f"每分钟最多请求 {rpm} 次 (Max {rpm} RPM)"
            # 释放第1个名额需要等待的时间 = 最早的那次请求 + 60秒 - 当前时间
            seconds_to_wait = max(1, int(rpm_history[0] + 60 - now))
            
        elif rph > 0 and len(rph_history) >= rph:
            is_rate_limited = True
            limit_reason = f"每小时最多请求 {rph} 次 (Max {rph} RPH)"
            # 释放第1个名额需要等待的时间 = 最早的那次请求 + 3600秒 - 当前时间
            seconds_to_wait = max(1, int(rph_history[0] + 3600 - now))
            
        elif win_time > 0 and win_limit > 0 and len(win_history) >= win_limit:
            is_rate_limited = True
            limit_reason = f"{win_time}分钟内最多请求 {win_limit} 次"
            seconds_to_wait = max(1, int(win_history[0] + (win_time * 60) - now))

        if is_rate_limited:
            # 计算预计恢复的绝对时间点描述 (例如 "23:05:12")
            resume_epoch = now + seconds_to_wait
            resume_time_str = time.strftime("%H:%M:%S", time.localtime(resume_epoch))
            
            # 格式化人类易读的倒计时文本
            if seconds_to_wait < 60:
                wait_str = f"{seconds_to_wait} 秒"
            else:
                wait_str = f"{int(seconds_to_wait // 60)} 分 {int(seconds_to_wait % 60)} 秒"

            fallback_cfg = cfg.get("fallback", {})
            if fallback_cfg.get("enabled", False):
                fallback_model = fallback_cfg.get("model", "")
                dprint(f"⚠️ 流控触发 ({limit_reason}) -> 降级至: {fallback_model}")
                body["model"] = fallback_model

                if fallback_cfg.get("notify", True) and __event_emitter__:
                    # 降级通知同样支持注入等待参数
                    notify_msg = fallback_cfg.get(
                        "notify_msg", "频率超限。已自动切至备用模型。将在 {resume_time} ({wait_time}后) 恢复主模型。"
                    )
                    notify_msg = notify_msg.format(
                        reason=limit_reason, 
                        wait_time=wait_str, 
                        resume_time=resume_time_str
                    )
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {"description": f"⚠️ {notify_msg}", "done": True},
                        }
                    )
            else:
                # 读取自定义拦截模板
                deny_pattern = cfg.get("custom_strings", {}).get(
                    "rate_limit_deny", 
                    "🚨 触发请求频率限制！\n原因: {reason}\n请在 {wait_time} 后重试，预计恢复时间为 {resume_time}。"
                )
                
                # 动态把计算结果渲染进提示里
                deny_msg = deny_pattern.format(
                    reason=limit_reason, 
                    wait_time=wait_str, 
                    resume_time=resume_time_str
                )
                
                dprint(f"❌ 拒绝请求: 触发流控。需等待 {wait_str}，于 {resume_time_str} 恢复。")
                raise Exception(deny_msg)

        # 放行，记录此次请求
        history.append(now)
        GLOBAL_USER_HISTORY[history_key] = history
        dprint(
            f"✅ 流控放行 [RPM:{len(rpm_history)+1} RPH:{len(rph_history)+1} WIN:{len(win_history)+1}] | Key: {history_key}"
        )

        return body

    async def stream(self, event: dict) -> dict:
        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})
        if log_cfg.get("enabled", True) and log_cfg.get("stream", False):
            raw = json.dumps(event, ensure_ascii=False)
            if len(raw) > 500:
                raw = raw[:500] + "...<truncated>"
            print(f"🌀 STREAM: {raw}")
        return event

    async def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})
        if log_cfg.get("enabled", True) and log_cfg.get("outlet", False):
            self._log_messages(body, log_cfg, "outlet")
        return body