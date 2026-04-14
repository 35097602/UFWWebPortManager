# UFW Web Port Manager

一个用于 **Linux 服务器** 的 UFW Web 管理面板，支持通过网页安全地执行端口开放/关闭、查看规则、查看 UFW 实时状态，并支持一键开启/关闭 UFW。

> 适合小团队、个人运维、测试环境快速管理防火墙规则。

---

## 1. 功能特性

- 管理员登录（单账号密码，配置文件指定）
- 端口规则管理
  - 批量端口输入（例如 `22,80,443`）
  - 协议选择：`TCP` / `UDP` / `TCP+UDP`
  - 一键开放端口（`allow`）
  - 一键关闭端口（`delete allow`）
- UFW 状态管理
  - 实时显示 UFW 状态（`active/inactive`）
  - 页面按钮直接开启/关闭 UFW
- 规则列表能力
  - 表头展示（Port / Protocol / Policy / Direction）
  - 按端口号排序（ASC / DESC）
  - 协议筛选（All / TCP / UDP）
  - 端口号模糊搜索
- 审计日志（后端终端输出）
  - 记录每次执行的 UFW 命令
  - 输出命令耗时、成功/失败、stderr

---

## 2. 技术栈

- Backend: Go (`net/http` 标准库)
- Frontend: 原生 HTML + CSS + JavaScript
- Firewall: UFW

---

## 3. 项目结构

```text
backend/
  main.go                # 后端服务与 API
  go.mod
  config.example.json    # 管理员账号配置模板
  README.md
  static/
    index.html           # 前端页面
    style.css            # 样式
    app.js               # 前端逻辑
```

---

## 4. 运行要求

- Linux 系统（Debian/Ubuntu 推荐）
- 已安装 `ufw`
- 建议以 `root` 运行服务（或配置可执行 `ufw` 的 sudo 权限）
- Go 1.22+

安装 UFW（Ubuntu/Debian）：

```bash
sudo apt update
sudo apt install -y ufw
```

---

## 5. 快速开始

### 5.1 配置管理员账号

```bash
cd backend
cp config.example.json config.json
```

编辑 `config.json`：

```json
{
  "admin_user": "admin",
  "admin_password": "YourStrongPassword"
}
```

### 5.2 构建并运行

```bash
cd backend
go build -o ufw-web
./ufw-web
```

默认监听地址由 `PORT` 控制（当前代码默认 `:20002`）：

```bash
PORT=8080 ./ufw-web
```

打开浏览器：

```text
http://<server-ip>:8080
```

---

## 6. 配置项

### 6.1 环境变量

- `PORT`
  - 服务监听端口
  - 示例：`PORT=8080`
- `CONFIG_FILE`
  - 配置文件路径
  - 默认：`./config.json`
  - 示例：`CONFIG_FILE=/opt/ufwui/backend/config.json`

### 6.2 配置文件（JSON）

字段说明：

- `admin_user`：管理员用户名
- `admin_password`：管理员密码

---

## 7. API 文档

所有管理类接口都需要先登录（Cookie 会话）。

### 7.1 健康检查

- `GET /api/health`

返回示例：

```json
{ "ok": true, "message": "ok" }
```

### 7.2 登录

- `POST /api/login`

请求：

```json
{
  "username": "admin",
  "password": "YourStrongPassword"
}
```

### 7.3 登出

- `POST /api/logout`

### 7.4 当前会话

- `GET /api/me`

### 7.5 获取 UFW 状态与规则

- `GET /api/status`

返回关键字段：

- `data.ufw_status`：字符串状态（如 `active`）
- `data.ufw_active`：布尔状态
- `data.rules`：规则列表

### 7.6 开启/关闭 UFW

- `POST /api/ufw`

请求：

```json
{ "action": "enable" }
```

或

```json
{ "action": "disable" }
```

### 7.7 开放/关闭端口规则

- `POST /api/rules`

请求：

```json
{
  "ports": "22,80,443",
  "protocol": "both",
  "action": "open"
}
```

字段说明：

- `ports`: 端口列表（支持逗号、空格、分号分隔）
- `protocol`: `tcp` / `udp` / `both`
- `action`: `open` / `close`

---

## 8. systemd 部署示例

创建文件：`/etc/systemd/system/ufw-web.service`

```ini
[Unit]
Description=UFW Web Port Manager
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ufwui/backend
ExecStart=/opt/ufwui/backend/ufw-web
Environment=PORT=8080
Environment=CONFIG_FILE=/opt/ufwui/backend/config.json
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ufw-web
sudo systemctl status ufw-web
```

查看日志：

```bash
sudo journalctl -u ufw-web -f
```

---

## 9. 安全建议（生产环境必看）

- `config.json` 仅 root 可读：

```bash
chmod 600 /opt/ufwui/backend/config.json
```

- 强密码（至少 16 位，包含大小写/数字/符号）
- 服务仅内网访问，外网通过反向代理和访问控制
- 建议启用 HTTPS
- 建议在 Nginx 层再加一层认证（如 Basic Auth / SSO）
- 保留最小化开放端口策略，避免误开放

---

## 10. 常见问题

### Q1: 打开页面后规则为空

可能原因：
- UFW 当前没有规则
- 服务运行账户无权限执行 `ufw`

建议：
- 用 root 运行服务
- 在终端执行 `ufw status` 验证

### Q2: 关闭端口时提示失败

可能原因：
- 目标规则不存在
- 规则协议不匹配（tcp/udp）

建议：
- 先刷新规则列表确认实际存在的规则

### Q3: 页面乱码

- 请确认文件编码为 UTF-8
- 浏览器强制刷新缓存（`Ctrl+F5`）

---

## 11. 开发与发布建议

### 本地开发

```bash
cd backend
go build ./...
```

### 提交到 GitHub 前建议

- 补充 LICENSE
- 补充 `.gitignore`
- 将 `config.json` 加入忽略（避免泄露密码）
- 在 README 增加项目截图

示例 `.gitignore` 关键项：

```gitignore
config.json
ufw-web
*.exe
```

---

## 12. License

建议使用 MIT License（按你的仓库策略决定）。

---

## 13. 声明

本项目会直接操作服务器防火墙规则，请在测试环境充分验证后再用于生产环境。