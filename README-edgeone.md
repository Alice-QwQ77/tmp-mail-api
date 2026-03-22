# EdgeOne 部署说明

这个仓库已经新增了一个可直接部署到 EdgeOne Pages 的版本。

源码入口：

- `edgeone-src/index.ts`

构建产物入口：

- `edge-functions/[[default]].js`

## 架构调整

原项目是 Deno 多服务架构：

- `src/gateway/app.ts`
- `src/frontend/provider-front_end.ts`
- `src/providers/provider-*.ts`

为了适配 EdgeOne Pages，这一版做了以下收敛：

- 改为单个 Edge Function 入口
- 改用 JavaScript
- 改用 EdgeOne KV Storage
- 将文档页、管理页、API 统一到一个函数内

当前已迁移的 provider：

- `mailtm`
- `mailgw`
- `linshiyouxiang`

其中 `linshiyouxiang` 在 EdgeOne 版本里不再依赖 Deno DOM，而是改成了基于字符串与正则的 HTML 解析。

## 目录

新增目录：

```text
edgeone-src/
  index.ts

edge-functions/
  [[default]].js
```

本地构建命令：

```bash
npm install
npm run build:edgeone
```

## 部署前准备

1. 在 EdgeOne Pages 控制台启用 KV Storage
2. 创建一个 KV Namespace
3. 将这个 Namespace 绑定到当前项目
4. 绑定变量名必须设置为 `TMPMAIL_KV`

注意：

- EdgeOne KV 在代码里是全局变量，不在 `context.env`
- 这个项目当前就是按 `TMPMAIL_KV` 这个名字写的

## 必填环境变量

在 EdgeOne Pages 项目中配置：

```text
ADMIN_PASSWORD=你的后台密码
ADMIN_COOKIE_SECRET=一个足够长的随机字符串
ENABLED_PROVIDERS=mailtm,mailgw,linshiyouxiang
DEFAULT_PROVIDER=mailtm
```

可选变量：

```text
PROVIDER_MAILTM_BASE=https://api.mail.tm
PROVIDER_MAILGW_BASE=https://api.mail.gw
PROVIDER_LINSHI_BASE=https://www.linshiyouxiang.net
LINSHI_SESSION_TTL_MS=3000000
LINSHI_MAX_DETAIL_FETCH=0
```

## 路由

部署后主要路由如下：

- `/docs` 文档页
- `/admin/login` 后台登录
- `/admin` API Key 管理页
- `/api/generate-email`
- `/api/emails`
- `/api/email/:id`
- `/api/emails/clear`
- `/api/stats`
- `/healthz`

## 使用流程

1. 打开 `/admin/login`
2. 使用 `ADMIN_PASSWORD` 登录
3. 创建一个 API Key
4. 用该 API Key 请求 `/api/*`

## 示例

生成邮箱：

```bash
curl -X POST "$BASE_URL/api/generate-email" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider":"mailtm","prefix":"demo"}'
```

查询邮件列表：

```bash
curl "$BASE_URL/api/emails?email=demo@example.com" \
  -H "Authorization: Bearer $API_KEY"
```

## 当前限制

- 动态新增功能当前只支持“远程统一协议 provider URL”，不支持在后台直接编写脚本逻辑
- 当前统计能力仍以核心上游调用计数为主
- 因为运行时依赖 EdgeOne KV，全本地完整联调未在仓库内直接完成

## 已补回的后台能力

EdgeOne 版现在已经补齐这些 provider 管理能力：

- 新增远程 provider
- 编辑远程 provider
- 删除远程 provider
- 启用 / 禁用 provider
- 设置默认 provider
- 保存 / 删除 `PROVIDER_SECRET`
- 测试 provider 连通性

说明：

- 内置 provider 不能被删除
- 内置 provider 不能被远程 URL 覆盖
- 如果某个 provider 的禁用状态来自环境变量，则后台不能直接改
- 动态 provider 需要实现与原项目 provider 相同的统一接口

## 分支

按你的要求，JS 迁移是在新分支上完成的：

```text
feat/edgeone-js-port
```
