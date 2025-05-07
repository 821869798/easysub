
<div align="center">
  <h1><b>easysub</b></h1>
  <h5><i>基于go开发的clash和singbox订阅转换工具</i></h5>
</div>

## 🚀 快速开始
### 本地部署
- 从Release下载对应平台的工具包 [![GitHub release (latest by date)](https://img.shields.io/github/v/release/821869798/easysub)](https://github.com/821869798/easysub/releases)
- 解压打开，复制一份pref.example.toml为pref.toml
- 如果有需求，修改配置内容；如果需要私有化订阅，可以修改private_sub.toml，以及可以在file_share添加共享的文件
- 运行easysub可执行文件
- 调用api,例如 http://127.0.0.1:25500/sub?target=clash&url={替换为自己的节点用|分割多个}&config={替换为自己需要的配置}

### Docker部署
- 编写自己的Dockerfile,可以参考[docker_example目录](docs/docker_example)
- 使用Docker构建该文件，或者放到github私有仓库中，使用容器服务商构建，例如[railway](https://railway.com)和[render](https://render.com)

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

先配置和修改private_sub.toml,可以参考本项目workdir下的

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
