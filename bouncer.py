"""
title: Bouncer
version: 0.5.0
author: Open WebUI Community (Optimized & Sync with WebUI)
description: 工业级访问控制与频率限制过滤器。100% 匹配前端 WebUI 配置，支持用户组优先级、跨组限流隔离、上下文裁剪及白名单模式认证。含输入/输出/流式日志、多模态(base64)过滤，以及按模型组配置的关键词拦截/屏蔽。
license: MIT
"""

import re
import json
import time
from typing import Optional, Callable, Awaitable, Any
from pydantic import BaseModel, Field

# 全局字典，用于单进程内的内存流控
# 键值格式根据 global_limit 决定: "user_id" 或 "user_id::model_group_id"
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
        """
        兼容纯文本与多模态(content 为 list)的消息。
        filter_media=True 时，把图片/base64 等非文本块替换成占位符，
        防止 data:image/...;base64, 这种巨长字符串糊满日志。
        """
        if not msg:
            return ""
        content = msg.get("content", "")

        # 纯文本：直接返回
        if isinstance(content, str):
            return content

        # 多模态：content 是一个 block 列表
        if isinstance(content, list):
            parts = []
            for p in content:
                if not isinstance(p, dict):
                    continue
                ptype = p.get("type", "")

                # 文本块原样保留
                if ptype == "text" or "text" in p:
                    parts.append(p.get("text", ""))
                    continue

                # 非文本块（图片/音频/文件等）
                if filter_media:
                    # OpenAI 风格: {"type":"image_url","image_url":{"url":"data:..."}}
                    # Anthropic 风格: {"type":"image","source":{...}}
                    label = ptype or "media"
                    parts.append(f"<{label} omitted>")
                else:
                    # 不过滤时也别直接 dump 整个 dict（base64 会爆），截断一下
                    raw = json.dumps(p, ensure_ascii=False)
                    if len(raw) > 200:
                        raw = raw[:200] + "...<truncated>"
                    parts.append(raw)
            return " ".join(parts)

        # 其它意外类型，兜底转字符串
        return str(content)

    def _log_messages(self, body, log_cfg, direction):
        """
        统一打印输入/输出日志。
        direction: "inlet" 取最后一条 user 消息；"outlet" 取最后一条 assistant 消息。
        """
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
        """
        按 mask_mode 替换命中的关键词。
        - hash : 按命中长度替换为 #（习近平下台 -> #####）
        - star : 按命中长度替换为 *
        - custom: 整段替换为 custom_mask（如 (此内容已屏蔽)）
        返回 (新文本, 是否命中)。
        """
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
            else:  # hash 为默认
                return "#" * len(matched)

        new_text = pattern.sub(_repl, text)
        return new_text, hit["found"]

    def _apply_keyword_filter(self, body, kw_cfg, dprint):
        """
        关键词过滤核心。
        - block 模式: 命中即返回 (True, 命中词)，由调用方负责 raise 拦截。
        - mask  模式: 就地改写 body["messages"] 中命中内容，返回 (False, "")。
        兼容纯文本与多模态(content 为 list，只动其中的 text 块，不碰图片)。
        """
        keywords = [k for k in kw_cfg.get("keywords", []) if k]
        if not keywords:
            return False, ""

        # 合并成单个正则，IGNORECASE 兼顾英文关键词大小写
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

            # ---- block 模式: 发现一处即拦截 ----
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

            # ---- mask 模式: 就地替换 ----
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

        # === 自定义日志输出闭包 ===
        def dprint(*args):
            if log_cfg.get("enabled", True) and log_cfg.get("bouncer_log", True):
                print(*args)

        dprint("\n=== BOUNCER RUNNING ===")

        # 1. 全局开关检查
        if not cfg.get("base", {}).get("enabled", True):
            dprint("💡 Bouncer disabled globally.")
            return body

        if not __user__:
            dprint("🚨 错误: 未能获取到用户上下文")
            return body

        # 2. 管理员豁免逻辑
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

        # ====== 3. 基础安全拦截与黑白名单 (Identity & Auth) ======
        is_exempt = False
        # 1) 豁免名单检查
        exemption_cfg = cfg.get("exemption", {})
        if exemption_cfg.get("enabled", False) and email in exemption_cfg.get(
            "emails", []
        ):
            dprint(f"😇 用户 {email} 在豁免名单中，跳过后续所有检查")
            is_exempt = True

        if not is_exempt:
            # 2) 封禁名单检查 (Ban List - 同步前端功能)
            for ban_rule in cfg.get("ban_reasons", []):
                if email in ban_rule.get("emails", []):
                    deny_msg = ban_rule.get("msg", "Account Suspended")
                    dprint(f"🚫 拦截: 用户 {email} 在黑名单中")
                    raise Exception(deny_msg)

            # 3) 白名单检查
            whitelist_cfg = cfg.get("whitelist", {})
            if whitelist_cfg.get("enabled", False) and email not in whitelist_cfg.get(
                "emails", []
            ):
                deny_msg = cfg.get("custom_strings", {}).get(
                    "whitelist_deny", "Access Denied: Not in whitelist."
                )
                dprint(f"❌ 拦截: 用户 {email} 不在白名单中")
                raise Exception(deny_msg)

            # 4) 邮箱域名认证 (白名单模式 - 不在列表则拦截)
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

        # ====== 4. 用户组与模型组决议 (Group Resolution) ======
        # 解析当前用户组 (带 priority 优先级排序)
        user_groups = sorted(
            cfg.get("user_groups", []), key=lambda x: x.get("priority", 0), reverse=True
        )
        my_ug = None
        for ug in user_groups:
            if email in ug.get("emails", []):
                my_ug = ug
                break

        # 找不到指定用户组，寻找默认兜底组
        if not my_ug:
            for ug in user_groups:
                if ug.get("id") == "default":
                    my_ug = ug
                    break

        # 极端防崩情况
        if not my_ug:
            my_ug = {"id": "default", "name": "Fallback", "default_permissions": {}}

        # 解析当前模型组
        my_mg = {"id": "default", "name": "Default Models", "ads": {}}
        for mg in cfg.get("model_groups", []):
            if current_model in mg.get("models", []):
                my_mg = mg
                break

        dprint(
            f"🎯 匹配路线: [用户组: {my_ug.get('name')}] -> [模型组: {my_mg.get('name')}]"
        )

        # ====== 5. 权限提取与访问拒绝 (Permissions Extraction) ======
        permissions = my_ug.get("permissions", {})
        if my_mg["id"] in permissions:
            limit_cfg = permissions[my_mg["id"]]
        else:
            limit_cfg = my_ug.get("default_permissions", {})

        # 如果提取出的权限配置 enabled 为 false，说明根本没有访问权限！
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

        # ====== 6. 广告公告逻辑 (Ads) ======
        if __event_emitter__ and current_model:
            # 优先检查组独立广告，若未开启则回退到全局广告
            ad_cfg = my_mg.get("ads", {})
            if not ad_cfg.get("enabled", False):
                ad_cfg = cfg.get("ads", {})

            if ad_cfg.get("enabled", False):
                contents = ad_cfg.get("content", [])
                if contents:
                    import random

                    ad_text = random.choice(contents)  # 根据 UI，应当随机选择一条
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {"description": f"[AD] {ad_text}", "done": True},
                        }
                    )

        # ====== 7. 上下文裁剪 (Clipping) ======
        clip_val = limit_cfg.get("clip", 0)
        if clip_val > 0 and "messages" in body and isinstance(body["messages"], list):
            original_len = len(body["messages"])
            if original_len > clip_val:
                body["messages"] = body["messages"][-clip_val:]
                dprint(f"✂️ 上下文裁剪: 保留最近 {clip_val} 条 (原 {original_len} 条)")

        # ====== 7.4 关键词过滤 (Keyword Filter) ======
        # 解析关键词配置: 模型组若自带 keyword_filter 则完全覆盖全局；否则用全局兜底。
        # 这样某个组可单独设 block，其它组用 mask，甚至某组显式关闭。
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

        # ====== 7.5 日志: 用户输入 (在裁剪+关键词过滤之后，打印的就是真正发给模型的内容) ======
        if log_cfg.get("enabled", True) and log_cfg.get("inlet", False):
            self._log_messages(body, log_cfg, "inlet")

        # ====== 8. 多级频率限制与降级 (Rate Limiting & Fallback) ======
        if is_exempt:
            dprint("✅ 流控放行 (豁免身份)")
            return body

        rpm = limit_cfg.get("rpm", 0)
        rph = limit_cfg.get("rph", 0)
        win_time = limit_cfg.get("win_time", 0)  # minutes
        win_limit = limit_cfg.get("win_limit", 0)

        # 无任何限制则直接放行
        if rpm == 0 and rph == 0 and win_limit == 0:
            dprint("✅ 流控放行 (该组无上限设置)")
            return body

        now = time.time()
        global GLOBAL_USER_HISTORY

        # 判断全局统计开关
        is_global_limit = cfg.get("global_limit", {}).get("enabled", False)
        history_key = user_id if is_global_limit else f"{user_id}::{my_mg['id']}"

        if history_key not in GLOBAL_USER_HISTORY:
            GLOBAL_USER_HISTORY[history_key] = []
        history = GLOBAL_USER_HISTORY[history_key]

        # 动态计算最大历史保留时间
        max_history_sec = max(3600, win_time * 60)
        history = [t for t in history if now - t < max_history_sec]

        # 统计频次
        rpm_count = len([t for t in history if now - t < 60])
        rph_count = len([t for t in history if now - t < 3600])
        win_count = len([t for t in history if now - t < (win_time * 60)])

        is_rate_limited = False
        limit_reason = ""

        if rpm > 0 and rpm_count >= rpm:
            is_rate_limited, limit_reason = True, f"Max {rpm} RPM"
        elif rph > 0 and rph_count >= rph:
            is_rate_limited, limit_reason = True, f"Max {rph} RPH"
        elif win_time > 0 and win_limit > 0 and win_count >= win_limit:
            is_rate_limited, limit_reason = True, f"Max {win_limit} reqs / {win_time}m"

        if is_rate_limited:
            fallback_cfg = cfg.get("fallback", {})
            if fallback_cfg.get("enabled", False):
                fallback_model = fallback_cfg.get("model", "")
                dprint(f"⚠️ 流控触发 ({limit_reason}) -> 降级至: {fallback_model}")
                body["model"] = fallback_model

                if fallback_cfg.get("notify", True) and __event_emitter__:
                    notify_msg = fallback_cfg.get(
                        "notify_msg", "Rate limit exceeded. Switched to fallback model."
                    )
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {"description": f"⚠️ {notify_msg}", "done": True},
                        }
                    )
            else:
                deny_pattern = cfg.get("custom_strings", {}).get(
                    "rate_limit_deny", "Rate Limit Exceeded: {reason}"
                )
                dprint(f"❌ 拒绝请求: 触发流控 ({limit_reason})")
                raise Exception(deny_pattern.format(reason=limit_reason))

        # 放行，记录此次请求
        history.append(now)
        GLOBAL_USER_HISTORY[history_key] = history
        dprint(
            f"✅ 流控放行 [RPM:{rpm_count+1} RPH:{rph_count+1} WIN:{win_count+1}] | Key: {history_key}"
        )

        return body

    async def stream(self, event: dict) -> dict:
        """流式输出钩子。logging.stream 为 true 时逐块打印。"""
        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})
        if log_cfg.get("enabled", True) and log_cfg.get("stream", False):
            raw = json.dumps(event, ensure_ascii=False)
            # 流式 chunk 一般不含 base64，但保险起见也截断超长内容
            if len(raw) > 500:
                raw = raw[:500] + "...<truncated>"
            print(f"🌀 STREAM: {raw}")
        return event

    async def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        """响应完成钩子。logging.outlet 为 true 时打印模型回复。"""
        cfg = self.get_cfg()
        log_cfg = cfg.get("logging", {})
        if log_cfg.get("enabled", True) and log_cfg.get("outlet", False):
            self._log_messages(body, log_cfg, "outlet")
        return body