# CloudMeet Prosody 源码基线

以官方原始 `stable-11248` 为准，不使用 `11248-1/-2/-3`，不使用 master/trunk。

## 三处来源

| 目录 | 来源 | 固定版本 |
|---|---|---|
| docker/ | jitsi/docker-jitsi-meet 的 base/、prosody/ 及原始 Makefile、LICENSE | stable-11248，276801c7fd4233f7288ba95bd132c219852c7ac7 |
| jitsi-plugins/upstream/ | jitsi/jitsi-meet 的 resources/prosody-plugins | jitsi-meet_11248，f765042bf280cbd7dcd4a9bbdb63b09e9e4d3259 |
| prosody/ | Prosody 官方发行源码 | 13.0.6 |

`sources.lock.json` 记录来源、提交、下载摘要及官方镜像身份；`sources.files.sha256.json` 记录导入文件的初始摘要。各目录保留上游许可证；不得删除版权说明。

## 版本依据与限制

通过 GHCR 只读检查官方 stable-11248 镜像索引及 amd64 镜像层中的 dpkg/status，确认其中 Prosody 软件包版本为 `13.0.6-1~trixie1`，因此导入本体源码13.0.6。没有连接任何部署服务器。

Jitsi插件选用同名11248发行标签，但尚未与镜像内插件逐文件比对，不能声称已完全复现官方镜像。Prosody目录是原始上游源码，不包含Debian软件包补丁；Dockerfile还会对安装的jid.lua执行调整。

## 当前构建边界（重要）

本次完成的是三处源码归档与版本记录，**没有构建或发布镜像**，也没有修改CloudMeet服务器。

`docker/prosody/Dockerfile` 保留官方原样：仍通过APT安装Prosody与Jitsi插件，不会使用旁边的 `prosody/` 和 `jitsi-plugins/`。其中还存在13.*、未固定的Jitsi软件包和动态contrib插件版本。当前目录不是全依赖离线包，也不是已完成的可复现源码构建链。

如仅测试官方Docker封装（会联网下载依赖，在仓库根执行）：

```bash
docker buildx build --platform linux/amd64 \
  --build-arg JITSI_REPO=ghcr.io/jitsi \
  --build-arg BASE_TAG=stable-11248 \
  --tag cloudmeet/prosody:11248-reference --load ./docker/prosody
```

保留的 `docker/Makefile` 是上游参考，包含其他未导入服务的目标，不要直接执行all/release/clean。

下一步若要让镜像真正使用本仓库三处源码，需要单独适配多阶段Dockerfile：从prosody/编译本体、从jitsi-plugins/复制会议插件、整合Docker模板与启动脚本，并锁定Lua模块、contrib、Matrix插件和基础镜像；之后完成角色/JWT/控制房间/会议兼容测试。不得把源码已下载等同构建链已完成。

## GitHub管理

根目录没有嵌套Git仓库，便于作为一个仓库上传。可在核对后执行git init、提交并关联自己的空GitHub仓库；本次没有提交或推送。

CloudMeet自定义主持人补丁尚未导入，避免污染官方基线。后续可放在jitsi-plugins/cloudmeet/，并明确是否替换现有deploy/patches/prosody/的维护职责，避免双份漂移。
