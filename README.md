
<div align="center">
  <h1><b>easysub</b></h1>
  <h5><i>基于 Rust 开发的 Clash 和 sing-box 订阅转换工具</i></h5>
</div>

> [!NOTE]
> Rust 是仓库根目录的当前实现。旧 Go 工程及其历史 workflow 已归档到
> [`legacy/`](legacy/)，仅作为兼容性参考和回滚来源。

### Rust 版本

```bash
cargo run --release -- workdir/pref.example.toml
```

默认提供 `/healthz`、`/sub` 和 `/ruleset`。部署、资源限制、日志、优雅停机
及升级回滚见
[Rust 版本部署与运维](docs/rust-operations.md)。

Clash 规则集兼容 `clashRSO`、`clashRSOH` 和 `clashGVR`：分别控制
rule-provider 聚合、回指 `/ruleset` 的 HTTP MRS provider，以及
GEOIP/GEOSITE 到远程 MRS 的转换。Stash 不支持 inline `payload`，调用时必须
显式设置 `clashRSOH=true`。反向代理部署应转发 `Host` 和 `X-Forwarded-Proto`；
也可设置 `SUB_FORCE_HTTPS=true` 强制 provider 使用 HTTPS。

## 🚀 快速开始
### 本地部署
- 从Release下载对应平台的工具包 [![GitHub release (latest by date)](https://img.shields.io/github/v/release/821869798/easysub)](https://github.com/821869798/easysub/releases)
- 解压打开，复制一份pref.example.toml为pref.toml
- 如果有需求，修改配置内容；如果需要私有化订阅，可以修改private_sub.toml，以及可以在file_share添加共享的文件
- 运行easysub可执行文件
- 调用api,例如 http://127.0.0.1:25500/sub?target=clash&url={替换为自己的节点用|分割多个}&config={替换为自己需要的配置}

### Docker部署
- 根目录 [Dockerfile](Dockerfile) 使用 Rust 1.96.0 多阶段构建：
  `docker build -t easysub-rs .`
- 启动示例：`docker run --rm -p 25500:25500 easysub-rs`
- 自定义配置可挂载到 `/app/workdir/pref.toml`。也可参考
  [docker_example目录](docs/docker_example)（使用
  `docker build -f docs/docker_example/Dockerfile .`），或交给 [railway](https://railway.com)、
  [render](https://render.com) 等容器平台构建。

### 发布

推送与 `Cargo.toml` 版本一致的 `v*` 标签后，Rust release workflow 会发布：

- Linux x86-64/ARM64 静态二进制；
- macOS x86-64/ARM64 二进制；
- Windows x86-64 二进制；
- 每个压缩包对应的 SHA-256；
- `ghcr.io/821869798/easysub` 多架构容器镜像。

正式版本标签（例如 `v0.2.0`）会发布 GitHub 正式版，并更新容器的 `0.2.0`、`0.2`、`0` 和
`latest` 标签。预发布标签（例如 `v0.2.0-rc.1`、`v0.2.0-beta.1`）会标记为 GitHub
Prerelease，容器会发布完整版本标签（例如 `0.2.0-rc.1`），不会覆盖稳定版的 `latest`。
每次正式或预发布都会更新 `edge`，它始终指向最后发布的版本。

### 作为 Rust 库使用

完整的订阅转换流程位于 `subscription` 模块，包括订阅和外部配置下载、内存缓存、节点解析、
远程 ruleset/base template 获取，以及 Clash YAML 或 sing-box JSON 生成。它不依赖 Axum；
其他 Rust 工程可以关闭默认的服务端 feature：

```toml
[dependencies]
easysub-rs = { git = "https://github.com/821869798/easysub", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use easysub_rs::{
    config::AppConfig,
    subscription::{
        SubscriptionInput, SubscriptionRequest, SubscriptionService, SubscriptionTarget,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load("workdir/pref.toml").await?;
    let service = SubscriptionService::new(config)?;
    let mut request = SubscriptionRequest::new(SubscriptionTarget::Clash);
    request.sources.push(SubscriptionInput::source(
        "https://example.com/subscription",
    ));
    let output = service.convert(request).await?;
    println!("{}", output.content);
    Ok(())
}
```

## ✨ 功能特点

### 支持协议
- ShadowSocks
- VMess
- VLESS
- Trojan

### 核心功能
- 兼容subconverter的sub api用法
- 自定义私有化订阅，对自建节点用户友好
- 支持`file:///`开头的本地共享文件，默认读取workdir/file_share。适合配合私有化订阅使用

### 客户端支持
- Sing-Box
- Clash

### 主要端点
- `/sub` - 生成订阅配置
- `/p` - 私有化订阅

### api示例
**sub** 普通订阅模式(跟subconverter用法一致)
```ini
# clash订阅
http://127.0.0.1:25500/sub?target=clash&url=trojan://password@zxc.123456.xyz:443?ws=1&peer=zxc.123456.xyz&sni=zxc.123456.xyz#zxc.123456.xyz_trojan&config=https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Mini_NoAuto.ini

#singbox订阅
http://127.0.0.1:25500/sub?target=singbox&url=trojan://password@zxc.123456.xyz:443?ws=1&peer=zxc.123456.xyz&sni=zxc.123456.xyz#zxc.123456.xyz_trojan&config=https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Mini_NoAuto.ini
```
**p** 私有化订阅方式

先配置和修改[private_sub.toml](workdir/private_sub.toml),可以参考本项目workdir下的文件，里面配置好了一些示例节点和url重写

调用api使用
```ini
# clash订阅，其中112233是随便配置的密钥
# 节点是配置在private_sub.toml中，相当于rewrite了请求url
http://127.0.0.1:25500/p/clash/112233

# singbox订阅，同上
http://127.0.0.1:25500/p/singbox/112233
```

## 🤝 贡献
欢迎提交 Issues 和 Pull Requests 来改进这个项目。
