# 软件加密保护系统

面向独立开发者与小型软件团队的软件授权管理平台。通过 **授权码 + 设备绑定 + 服务端校验**，控制软件的授权范围与使用周期；同时提供 **EXE/APK/文件/视频/文件夹 五类保护壳**，把原始文件加密打包成必须输入授权码才能打开的受保护程序。支持账户余额计费，可直接商业化运营。   已上线：http://47.113.230.65:8080/

> **当前版本 v4.0.0** — 信封加密（密钥不进入产物）+ EXE/APK 双端加固，产物 `license-server-4.0.0.jar`。变更详情见 `docs/UPDATE-4.0.md`，部署步骤见 `DEPLOY.md`。

## 一、功能特性

### 保护类型

| 保护类型       | 上传内容                        | 产物                 | 运行行为                                          | 4.0 加固要点                                                 |
| -------------- | ------------------------------- | -------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| EXE 程序保护壳 | 单个 .exe                       | 受保护 exe           | 双击弹框要授权码→联网校验→解密运行原程序          | 密文以资源 `SoftLicense.Data.bin` 内嵌，产物不含任何密钥；反调试与解密交织（per-build salt） |
| APK 应用保护壳 | 单个 .apk                       | 重签名 APK           | apktool 反编译插桩授权校验 Activity，设备指纹绑定 | 业务 dex 加密进 `assets/sl.dex.dat`（SLDX 容器）→ 壳在运行时解密加载；替换 Application/入口 Activity；v1/v2/v3 签名绑定；Android 14+ DCL 合规 |
| 文件加密       | 任意单个文件（PDF/文档/图片等） | xxx.exe              | 校验通过后解密用默认程序打开                      | 服务端 `MASTER_KEY` → HKDF 派生内容密钥，RSA-OAEP 信封下发   |
| 视频加密       | 单个视频（.mp4 等）             | xxx_protected.exe    | 校验通过后解密调用播放器打开                      | 同上                                                         |
| 文件夹加密     | 整个文件夹                      | folder_protected.exe | 校验通过后解压打开资源管理器                      | 同上（壳内 `ZipFile.ExtractToDirectory` 解包，要求客户机 .NET ≥ 4.5） |

### 授权模式

- **在线激活**：联网校验授权码，绑定设备指纹
- **离线授权**：RSA 签名凭证，断网可本地验签
- **正式授权**：永久有效
- **试用授权**：1天/7天/15天/30天/90天
- 校验失败精确提示：授权码错误 / 已到期 / 设备数已满

### 计费体系（v1.0.1）

| 卡种   | 时长 | 价格                       |
| ------ | ---- | -------------------------- |
| 日卡   | 1天  | ¥1.9                       |
| 周卡   | 7天  | ¥6.9                       |
| 半月卡 | 15天 | ¥12.9                      |
| 月卡   | 30天 | ¥19.9（折合每天0.66元）    |
| 季卡   | 90天 | ¥45.9                      |
| 永久卡 | 永久 | ¥128（一次购买，终身使用） |

- 每个账户有余额，新注册用户默认赠送 ¥2
- 生成授权时按价格自动扣减余额，余额不足提示联系管理员充值
- 管理员可在用户管理中任意调整用户余额
- **余额流水**：记录每笔充值/消费（金额、变动后余额、时间、备注），管理员看全部用户，普通用户只看自己，只读不可改

### 防破解机制（v4.0 信封加密 + 双端加固）

**内容密钥模型彻底重构**：3.0 及以前把 AES 密钥包装后写进产物（`##H##/##K##/##I##` 三段），攻击者 dump 产物 + 改 IL 即可还原密钥。4.0 改为**密钥不进入产物**：

- **信封加密**：服务端根密钥 `MASTER_KEY`（Base64 的 32 字节）经 HKDF-SHA256 派生内容密钥 CK（32B AES + 32B HMAC）；CK 用 RSA-OAEP 包装后随会话下发，产物内只有密文
- **根密钥铁律**：`MASTER_KEY` 只从环境变量注入、绝不下发、绝不入库；变更会导致所有已签发凭证与信封失效，**必须原样迁移、不可在服务器重新生成**
- **Encrypt-then-MAC**：内容加密为 AES-256-CBC + HMAC-SHA256（`IV(16) ‖ ct ‖ HMAC(32)`），先验 MAC 再解密，篡改必然失败
- **会话临时密钥（前向保密）**：每次解密会话协商一次性密钥，历史会话被攻破不影响后续
- **短时效令牌 + 吊销**：HMAC 令牌默认 900 秒有效、60 秒时钟容差，服务端 Redis 可即时吊销（`sl:token:revoked:{licenseId}`）；Redis 故障时降级放行不阻断业务
- **防时钟回拨**：客户端以服务端 `serverTime` 为基线，本地时间回拨即判定失效
- **反调试 fail-closed**：检测到调试器/注入/Hook 即销毁会话密钥并静默退出（不弹窗、不暴露关键跳转）
- **反 Hook / 反注入**：检测 CLR Profiler 环境变量、已加载程序集（Harmony/EasyHook/Reloaded/Frida/dnSpy/de4dot）、native 注入模块、Frida 默认端口（27042/27043）
- **EXE native 反调试**：P/Invoke `IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`（ProcessDebugPort / ProcessDebugFlags）
- **APK 完整性自校验**：壳内校验签名证书 SHA-256、SLDX 容器版本与条目数；解密失败按原因分级提示
- **RSA-2048 凭证验签**：离线授权凭证服务端签名、本地验签防伪造
- **临时文件保护**：解密文件放在 Temp 下随机命名的隐藏目录（两层 Guid），24 小时后自动清理

### 用户与权限（RBAC）

- **管理员**：数据看板、软件管理、授权管理、余额流水、操作日志、设备监控、用户管理、工单管理、公告管理
- **普通用户**：数据看板、软件管理、授权管理、余额流水、我的工单（只能看到自己的数据）
- 注册需邮箱验证码（163 SMTP），一个邮箱只能注册一个账号
- 修改密码、退出登录（带确认）
- 管理员可管理普通用户（增删改查、重置密码、调余额）

### 保护处理体验

- 加密/加壳为深度处理（密钥派生 → 内容加密 → 保护壳编译 → 多重签名），大文件通常需 1–3 分钟
- 加载遮罩按真实处理阶段轮播提示，等待过程持续反馈，不会「看起来卡死」
- 局域网部署时服务端地址自动探测（排除 VMware/VirtualBox 等虚拟网卡），无需手改配置

### 其他功能

- 数据看板（软件数、授权数、设备数、今日激活数）
- 在线设备监控面板（活跃设备、设备指纹）
- 工单系统（右下角联系客服，支持上传最多3张图片到 MinIO，管理员可回复解决方案，用户可查看）
- 各列表支持单条删除 + 批量删除
- 系统公告（管理员可添加/修改）
- 移动端自适应（表格横向滚动）
- 登录页左右分栏 + 实时加密演示动画

## 二、技术栈

| 组成     | 技术                                                         |
| -------- | ------------------------------------------------------------ |
| 后端     | Spring Boot 3.3.5、MyBatis-Plus、MySQL 8（utf8mb4）、Redis   |
| 前端     | Vue 3、Vite 5、Element Plus、Vue Router                      |
| 保护壳   | Java AES-256-CBC + HMAC-SHA256 + C# (csc.exe) 编译授权解密器 |
| 密钥体系 | HKDF-SHA256 派生内容密钥 + RSA-2048 OAEP 信封                |
| APK 加壳 | apktool 反编译插桩 + d8 编译 + zipalign + apksigner（v1/v2/v3）签名 |
| 签名     | RSA-2048 + SHA256（离线授权凭证）                            |
| 对象存储 | MinIO（工单图片）                                            |
| 邮件     | 163 SMTP（注册验证码）                                       |
| 认证     | HmacSHA256 签名 token（默认 900 秒，服务端 Redis 可吊销）    |

## 三、快速开始

### 1. 环境要求

- JDK 17+
- Node 18+
- MySQL 8（utf8mb4）
- **Redis（4.0 起必需**：短时效令牌与吊销依赖 Redis；故障时降级放行不阻断）
- Windows + .NET Framework 4.0+（`csc.exe` 编译保护壳；文件夹加密的壳需 .NET ≥ 4.5）
- APK 加壳：优先用随包的 `tools/android-build-tools/`（自带 apksigner.jar + d8.jar，**无需安装 Android SDK**），否则回落到 `ANDROID_HOME`

### 2. 启动后端

```bash
mvn -DskipTests package
java -jar license-server/target/license-server-4.0.0.jar
```

- 端口 8080，启动自动建表（utf8mb4）
- **生产环境必须用环境变量 `MASTER_KEY` 注入根密钥**；留空时会自动生成到 `keys/master.key`（仅开发便利）

### 3. 启动前端

```bash
cd admin-web
npm install
npm run dev
```

访问 `http://localhost:5173`

### 4. 默认账号

- 管理员：admin / admin123

### 5. 后台运行（Windows 服务器）

```bash
start /b javaw -jar license-server/target/license-server-4.0.0.jar
```

## 四、业务流程

```
注册/登录（邮箱验证码）
  → 创建软件（选保护类型 + 上传文件）
  → 服务端派生内容密钥 CK → AES+HMAC 加密 + 编译授权壳（APK 走 dex 加密 + 重签名）
  → 生成授权码（按卡种扣余额）
  → 下载受保护文件，复制下载链接
  → 分发给客户
  → 客户双击输入授权码
  → 在线联网激活（领取短时效令牌）/ 离线验签 → 绑定设备指纹 → 解密运行
  → 管理员可撤销/删除授权、删除软件、查看流水
```

## 五、部署

详见 `DEPLOY.md`（含 4.0 完整部署步骤，见第十二部分）。开发环境与生产环境配置隔离。生产环境建议：

- 2核4G 服务器：单文件上传上限 500MB，JVM 堆 `-Xmx2g`
- MySQL/Redis 可使用独立服务器，通过环境变量覆盖配置
- **加壳只能部署在 Windows Server**（EXE 壳依赖 `csc.exe`、APK 壳依赖 `apksigner.bat` / `zipalign.exe`）；Docker/Linux 镜像仅适用于纯授权服务

### 关键环境变量

| 变量                             | 默认值                           | 说明                                            |
| -------------------------------- | -------------------------------- | ----------------------------------------------- |
| `MASTER_KEY`                     | 空（自动生成 `keys/master.key`） | **根信封密钥**，Base64 的 32 字节，生产必须注入 |
| `KEY_VERSION`                    | `1`                              | 内容密钥版本，递增即让旧内容密钥失效            |
| `TOKEN_TTL_SECONDS`              | `900`                            | 解密令牌有效期                                  |
| `TOKEN_CLOCK_SKEW_SECONDS`       | `60`                             | 允许的时钟偏差                                  |
| `SERVER_URL`                     | `http://47.113.230.65:8080`      | 壳内嵌的服务端地址                              |
| `STORAGE_DIR`                    | `./storage`                      | 原始件与产物目录                                |
| `KEY_DIR`                        | `./keys`                         | RSA 密钥对与根密钥目录                          |
| `DB_URL` / `DB_USER` / `DB_PASS` | 见 `application.yml`             | 数据库连接                                      |
| `REDIS_HOST` / `REDIS_PASSWORD`  | 见 `application.yml`             | Redis 连接                                      |

## 六、目录结构

```
SoftwareEncryption/
├── license-server/     # Spring Boot 后端
│   └── src/main/
│       ├── java/com/softlicense/server/
│       │   ├── entity/       # 实体（含 BalanceLog）
│       │   ├── mapper/       # MyBatis Mapper
│       │   ├── enums/        # 保护类型枚举
│       │   ├── protect/      # 各类保护处理器 + 壳构建器 + ContentCipher
│       │   ├── service/      # 业务服务（含 MasterKeyService）
│       │   ├── controller/   # API 接口
│       │   └── config/       # 拦截器/配置
│       └── resources/
│           ├── db/schema.sql        # 建表脚本（含 changelog）
│           └── smali-template/      # APK 加壳 smali 模板（19 个，打进 jar）
├── admin-web/          # Vue3 前端
├── verify/             # 验证套件（run.sh → V4Verify 76 项 / run-apk.sh → ApkE2E）
├── tools/              # apktool.jar、soft.keystore、android-build-tools、壳源码
├── storage/            # 运行时产物（original/ 原件、output/ 产物）
├── keys/               # RSA 密钥对 + master.key（.gitignore，需手动迁移）
├── docs/               # 版本文档（UPDATE-3.0 / UPDATE-4.0 / VERIFY-4.0）
├── DEPLOY.md
└── README.md
```

## 七、验证

```bash
bash verify/run.sh          # 单元/集成验证（V4Verify，当前 76/76 PASS）
bash verify/run-apk.sh      # APK 端到端加壳验证（ApkE2E）
```

EXE 端到端自验：

```bash
mvn -pl license-server -am test-compile
java -cp "license-server/target/classes;license-server/target/test-classes;$(cat license-server/target/verify-cp.txt)" com.softlicense.E2E
```

## 八、版本历史

- **v4.0.0（信封加密 + EXE/APK 双端加固）**：内容密钥 CK 改由服务端 `MASTER_KEY` 经 HKDF 派生、RSA-OAEP 信封下发（**密钥不再进入产物**）；会话临时密钥 + 短时效令牌 + 防时钟回拨 + Redis 即时吊销；EXE 侧反调试与解密交织（per-build salt）；APK 4.0 壳（业务 dex 加密进 `sl.dex.dat`、入口替换、签名 v1/v2/v3 绑定、Android 14+ DCL 合规、真 Application 转发）；Maven 工程版本号与产品版本对齐（`2.0.0` → `4.0.0`，产物 `license-server-4.0.0.jar`）。详见 `docs/UPDATE-4.0.md`
- **v3.0.0（native 加固）**：native 层解密器 `slcore.dll` + 反调试 + 反 Hook/反注入。详见 `docs/UPDATE-3.0.md`
- **v2.0.0（安全加固版）**：完整性自校验 + AES 密钥与完整性绑定、反 Hook/反注入、native 反调试、后台周期巡检、大文件流式加密
- **v1.0.1**：计费体系（余额、定价、流水）、APK 加壳完善、临时文件保护、校验精确提示
- **v1.0.0**：五类保护壳、RBAC 权限、工单系统、离线授权、防破解、移动端适配
