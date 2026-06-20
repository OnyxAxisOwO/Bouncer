# Bouncer

> 📍 开源免费的 Open WebUI 企业级访问控制与多级频率限制过滤器

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.5.1-green.svg)]()

## 简介

Bouncer 是一个专为 [Open WebUI](https://openwebui.com/) 设计的工业级网关管理过滤器。通过精细的规则配置，可以实现用户分级、模型分组、访问控制、频率限制、关键词过滤等功能，确保你的 LLM 应用安全、可控、高效。

## ✨ 核心功能

### 🔐 访问控制
- **白名单模式** - 仅允许特定邮箱访问
- **黑名单模式** - 封禁特定用户账号
- **豁免列表** - 信任的用户跳过所有检查
- **邮箱域名限制** - 按公司域名控制访问

### 👥 用户与模型分组
- **用户组管理** - 按优先级匹配用户，分配不同权限配置
- **模型组管理** - 将模型归组，对每个组设置独立的限流规则

### 🚦 多级频率限制
- **按分钟限制 (RPM)** - 每分钟最多请求数
- **按小时限制 (RPH)** - 每小时最多请求数
- **时间窗口限制** - 自定义时间窗口内的请求限制
- **全局或分组隔离** - 支持全局计数或按模型组分别计数

### 🎯 智能降级
- **自动降级** - 触发限流时自动切换到更廉价的备用模型
- **用户提醒** - 动态显示冷却倒计时和恢复时间
- **零中断体验** - 用户请求不被拒绝，而是自动降级处理

### 🔇 关键词过滤
- **屏蔽模式** - 用自定义文本替换敏感词
- **拦截模式** - 直接拒绝包含敏感内容的请求
- **灵活样式** - 支持井号、星号或自定义屏蔽方式
- **按角色扫描** - 自定义扫描哪些消息角色

### 📋 其他功能
- **上下文裁剪** - 限制用户能看到的历史消息条数
- **广告系统** - 随机发送通知消息（全局或按模型组）
- **日志记录** - 精细的服务端日志，支持隐藏敏感信息
- **自定义消息** - 自定义拒绝提示文本和占位符

## 🚀 快速开始

### 1. 复制 Python 过滤器
将 `bouncer.py` 复制到 Open WebUI 的过滤器目录中。

### 2. 使用配置编辑器
在浏览器打开 `index.html`，使用友好的可视化编辑器配置 Bouncer。

### 3. 生成配置 JSON
编辑器会实时生成 JSON 配置，点击「⬇ 导出」或「⧉ 复制」获取配置文本。

### 4. 粘贴到 Open WebUI
在 Open WebUI 中，进入过滤器管理，找到 Bouncer 的 `config_json` 字段，粘贴生成的 JSON 配置。

### 5. 启用过滤器
启用 Bouncer，开始保护你的 LLM 应用！

## 📖 配置示例

```json
{
  "base": {
    "enabled": true,
    "admin_effective": false
  },
  "whitelist": {
    "enabled": true,
    "emails": ["user@company.com"]
  },
  "user_groups": [
    {
      "id": "vip",
      "name": "VIP Users",
      "priority": 10,
      "emails": ["vip@company.com"],
      "permissions": {
        "gpt_group": {
          "enabled": true,
          "rpm": 100,
          "rph": 1000,
          "clip": 0
        }
      }
    },
    {
      "id": "default",
      "name": "Default Users",
      "priority": 0,
      "emails": [],
      "default_permissions": {
        "enabled": true,
        "rpm": 10,
        "rph": 100
      }
    }
  ]
}
```

## 🎨 配置编辑器特性

- **多语言支持** - 中英文自由切换
- **实时预览** - 编辑时实时预览生成的 JSON
- **导入导出** - 支持加载、复制、导出配置
- **响应式设计** - 桌面和移动设备适配
- **注释支持** - JSONC 格式自动去注释

## 📚 关键概念

| 术语 | 说明 |
|-----|------|
| **RPM** | Requests Per Minute - 每分钟最多请求数 |
| **RPH** | Requests Per Hour - 每小时最多请求数 |
| **时间窗口** | 自定义窗口时长（分钟）和窗口内的最大请求数 |
| **优先级** | 用户匹配优先级，数值越高越优先 |
| **全局限流** | 跨所有模型组共享一个计数器 |
| **豁免用户** | 跳过所有检查：认证、白名单、限流、关键词过滤等 |

## ⚙️ 高级配置

### 邮箱域名限制
```json
"auth": {
  "enabled": true,
  "providers": ["gmail.com", "outlook.com", "company.com"],
  "deny_msg": "仅支持特定邮箱提供商"
}
```

### 自动降级策略
```json
"fallback": {
  "enabled": true,
  "model": "qwen2:0.5b",
  "notify": true,
  "notify_msg": "已降级至备用模型，将在 {resume_time} 恢复"
}
```

### 关键词过滤（全局）
```json
"keyword_filter": {
  "enabled": true,
  "mode": "mask",
  "keywords": ["敏感词1", "敏感词2"],
  "mask_mode": "hash",
  "scan_roles": ["user"]
}
```

## 🔍 日志输出示例

```
=== BOUNCER RUNNING ===
USER: user@example.com | MODEL: gpt-4o
🎯 匹配路线: [用户组: VIP Users] -> [模型组: OpenAI]
✅ 流控放行 [RPM:5 RPH:45 WIN:0] | Key: user_id::gpt_group
```

## 📄 许可证

本项目采用 MIT License 开源。详见 [LICENSE](LICENSE) 文件。

## 🙋 支持与反馈

如有问题或建议，欢迎提交 Issue 或 Pull Request。

- **项目地址** - [GitHub: OnyxAxisOwO/Bouncer](https://github.com/OnyxAxisOwO/Bouncer)
- **在线编辑器** - [bouncer-webui.pages.dev](https://bouncer-webui.pages.dev)

---

**Bouncer** © 2024 Open WebUI Community. Made with ❤️
