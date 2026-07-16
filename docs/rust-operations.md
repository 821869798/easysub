# Rust 版本部署与运维

本文适用于 `feat/rust-rewrite` 上的 `easysub-rs`。Rust 服务已经可用于开发、
shadow 和 canary 验证，但在 [RUST_PROGRESS.md](../RUST_PROGRESS.md) 的
cutover 项完成前，不应直接删除 Go 回滚路径。

## 构建与启动

项目要求 Rust 1.96.0 或更新版本；当前验证工具链为 1.96.0。

```powershell
rustc --version
cargo build --release
./target/release/easysub-rs.exe workdir/pref.toml
```

Linux/macOS 使用 `./target/release/easysub-rs`。配置文件按以下优先级选择：

1. 第一个命令行参数；
2. `EASYSUB_CONFIG` 环境变量；
3. 存在的 `workdir/pref.toml`；
4. `workdir/pref.example.toml`。

默认监听 `0.0.0.0:25500`。`advance.port_env` 指定端口环境变量名，默认是
`PORT`；环境变量存在时覆盖 `advance.default_port`。

启动后先检查：

```powershell
Invoke-WebRequest http://127.0.0.1:25500/healthz
```

`/healthz` 应返回 `204`。业务端点为 `/sub`、`/ruleset`，启用私有订阅后还有
`/p/*path`。

容器构建和启动：

```powershell
docker build -t easysub-rs .
docker run --rm -p 25500:25500 easysub-rs
```

镜像使用 Rust 1.96.0 构建，并以非 root 用户运行。自定义配置可以只读挂载：

```powershell
docker run --rm -p 25500:25500 `
  -v "${PWD}/workdir/pref.toml:/app/workdir/pref.toml:ro" `
  easysub-rs
```

## Rust 资源控制项

Rust 版本不沿用 Go 的全局并发 3 限制。普通请求由 Tokio 调度，同时通过以下
边界控制内存；这些配置写在 `[advance]` 下：

| 配置 | 默认值 | 用途 |
|---|---:|---|
| `max_download_bytes` | 32 MiB | 单个上游响应的流式硬上限；兼容旧名 `max_allowed_download_size` |
| `cache_capacity_bytes` | 128 MiB | 按正文和订阅元数据字节加权的共享缓存上限 |
| `max_allowed_rulesets` | 64 | 单次请求的订阅源/规则集数量上限 |
| `max_allowed_rules` | 1,000,000 | 生成规则数上限；`0` 表示不另设规则数限制 |
| `fetch_concurrency` | `CPU * 4`，限制在 8–64 | 单次请求并行下载数 |
| `heavy_task_concurrency` | `ceil(CPU / 2)` | MRS/zstd 等重型任务并发数 |
| `request_timeout_seconds` | 30 | 上游请求超时；HTTP 总超时会额外留 5 秒收尾 |

缓存 TTL 分别由 `cache_subscription`、`cache_config` 和 `cache_ruleset` 控制。
若部署环境内存紧张，优先降低 `cache_capacity_bytes` 和
`fetch_concurrency`，不要恢复覆盖所有请求的全局并发锁。

示例：

```toml
[advance]
max_download_bytes = 33554432
cache_capacity_bytes = 134217728
fetch_concurrency = 16
heavy_task_concurrency = 2
request_timeout_seconds = 30
```

## 路径与访问边界

- 相对的 base、外部配置、私有订阅和 file-share 路径以主配置文件目录为基准。
- `file://` 只允许访问 `advance.file_share_path` 下的规范相对路径，不能用 `..`
  越界。
- 开启 `common.api_mode` 后，默认订阅、本地文件、`env:` 和本地规则集需要
  `token` 与 `common.api_access_token` 匹配。
- 公网部署时应由反向代理提供 TLS，并限制不需要公开的管理入口。
- `node_pref.append_sub_userinfo=true` 时，服务只透传已校验的
  `subscription-userinfo`、`profile-web-page-url` 和
  `profile-update-interval` 三个上游响应头。

## 日志和错误

未设置 `RUST_LOG` 时使用 `advance.log_level`；`RUST_LOG` 存在时优先。例如：

```powershell
$env:RUST_LOG = "easysub_rs=debug,tower_http=info"
./target/release/easysub-rs.exe workdir/pref.toml
```

请求带 `x-request-id`，响应会回传同一 ID，便于关联 trace 日志。HTTP 错误使用
JSON `{"error":"..."}`：输入错误为 400，未授权为 401，大小/数量超限为
413，上游失败为 502，超时为 408。

## 停机与服务管理

Windows 的 Ctrl-C，以及 Unix 的 SIGINT/SIGTERM，都会触发 Axum 优雅停机。
反向代理或容器应给正在处理的请求保留至少
`request_timeout_seconds + 5` 秒，再强制结束进程。

systemd 示例：

```ini
[Unit]
Description=easysub Rust service
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/easysub
ExecStart=/opt/easysub/easysub-rs /opt/easysub/workdir/pref.toml
Environment=RUST_LOG=easysub_rs=info,tower_http=info
Restart=on-failure
RestartSec=2
TimeoutStopSec=40

[Install]
WantedBy=multi-user.target
```

## 升级、canary 与回滚

1. 用当前配置执行完整验证：

   ```powershell
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all-targets
   go test ./...
   go vet ./...
   cargo build --release
   ./scripts/measure-release.ps1 -Concurrency 16
   ```

2. 保留当前 Go 二进制和配置快照，以不同端口启动 Rust。
3. 对同一批真实 `/sub`、`/ruleset` 和私有订阅请求做 shadow 对比；YAML/JSON
   应按结构比较，MRS 应解压后比较语义，不按文本键顺序比较。
4. 先把少量无状态流量切到 Rust，观察 4xx/5xx、上游延迟、峰值工作集、缓存
   命中和输出差异，再逐步扩大。
5. 回滚只需要把反向代理流量切回仍在运行的 Go 服务。配置或输出不一致时不要
   删除旧二进制，也不要让两个版本共享可变的生成文件。

完成 canary 后，把实测版本、持续时间、请求数量、差异和资源峰值记录到
[RUST_PROGRESS.md](../RUST_PROGRESS.md) 的 `CUT-01`，再决定是否替换 Go。
