# IntentOS 内置能力参考手册（自动生成）

| 能力 ID | 类别 | 效应 | 风险标签 | 可撤销 | 摘要 |
|---|---|---|---|---|---|
| `app.launch` | applications | `ui` | R1 | — | 启动或聚焦已安装的桌面应用（支持中英文名、拼音、常用缩写如 vsc） |
| `app.quit` | applications | `ui` | R1 | — | 请求指定应用优雅关闭退出（绝不发送 SIGKILL 强杀，保护未保存文档） |
| `app.search` | applications | `observe` | R0 | — | 在本地应用索引中按名称、拼音、首字母或别名搜索桌面软件 |
| `appearance.accent_color.set` | system | `setting` | R1 | ✅ | 设置桌面强调色（blue/teal/green/yellow/orange/red/pink/purple/slate，同步 Yaru 变体，可撤销） |
| `appearance.animations.set` | system | `setting` | R1 | ✅ | 开启或关闭桌面窗口动画效果（enable-animations，可撤销） |
| `appearance.clock.set` | system | `setting` | R1 | ✅ | 设置顶栏时钟制式（24h/12h）、是否显示秒数与星期（可撤销） |
| `appearance.color_scheme.set` | system | `setting` | R1 | ✅ | 切换系统外观深浅色主题（深色模式 / 浅色模式 / 默认，同步 GNOME color-scheme 与 Yaru 主题） |
| `appearance.cursor_size.set` | system | `setting` | R1 | ✅ | 设置鼠标指针大小（24 / 32 / 48 / 64 / 96，可撤销） |
| `appearance.font.document.set` | system | `setting` | R1 | ✅ | 设置文档阅读字体族与字号（6–24 pt，校验 fc-list 已安装字体，可撤销） |
| `appearance.font.interface.set` | system | `setting` | R1 | ✅ | 设置系统界面字体族与字号（6–24 pt，校验 fc-list 已安装字体，可撤销） |
| `appearance.font.list` | system | `observe` | R0 | — | 查询系统已安装的字体族列表（缓存自 fc-list） |
| `appearance.font.monospace.set` | system | `setting` | R1 | ✅ | 设置终端与代码等宽字体及字号（6–24 pt，校验 fc-list 已安装字体，可撤销） |
| `appearance.text_scale.set` | system | `setting` | R1 | ✅ | 设置界面文字缩放比例（「字体大一点」「字体缩小」「文字放大到 125%」） |
| `appearance.wallpaper.set` | system | `setting` | R1 | ✅ | 将授权目录内的图片文件设为桌面壁纸（同步浅色/深色 picture-uri，可撤销） |
| `archive.create` | filesystem | `write.reversible` | R2 | ✅ | 将授权目录内的文件或目录打包为 .tar.gz 或 .zip 压缩包（支持一键撤销） |
| `archive.extract` | filesystem | `write.reversible` | R2 | ✅ | 将压缩包安全解压到授权目录下的独立新建子目录（防 Zip Slip，支持一键撤销） |
| `bluetooth.connect` | system | `setting` | R1 | — | 按名称模糊匹配连接已配对的蓝牙设备（如 AirPods/蓝牙耳机，未配对则打开蓝牙设置页） |
| `bluetooth.disconnect` | system | `setting` | R1 | — | 断开当前已连接的指定蓝牙设备 |
| `bluetooth.power` | system | `setting` | R1 | ✅ | 开启或关闭系统蓝牙适配器（bluetoothctl power on/off，可撤销） |
| `clipboard.copy` | filesystem | `setting` | R1 | — | 将文本、路径或链接复制到系统剪贴板并读回验证（Wayland wl-copy / 扩展桥接） |
| `disk.free` | devtools | `observe` | R0 | — | 查看本机文件系统磁盘空间剩余与使用率（df -h） |
| `disk.usage` | devtools | `observe` | R0 | — | 统计指定授权目录下各子目录或文件的磁盘占用体积排名 |
| `display.brightness.get` | system | `observe` | R0 | — | 查询当前屏幕背光亮度百分比 |
| `display.brightness.set` | system | `setting` | R1 | ✅ | 设置或相对调整屏幕亮度（1–100%，禁止设为 0 防止黑屏，步长 10%，连续调整合并撤销） |
| `display.idle_delay.set` | system | `setting` | R1 | ✅ | 设置屏幕空闲自动熄屏时间（0 表示从不熄屏，或 60–3600 秒，可撤销） |
| `display.night_light.set` | system | `setting` | R1 | ✅ | 开启或关闭屏幕夜灯护眼色温过滤（gsettings night-light-enabled，可撤销） |
| `display.night_light.temperature` | system | `setting` | R1 | ✅ | 设置或相对调整夜灯色温（1700–4700 K，步长 500 K，「暖一点/冷一点」，可撤销） |
| `file.copy` | filesystem | `write.reversible` | R2 | ✅ | 将文件安全复制到授权目录内的目标路径（原生 openat2，支持撤销） |
| `file.grep` | filesystem | `observe` | R0 | — | 在授权目录中使用 ripgrep 搜索包含指定文本内容的文件与行号 |
| `file.move` | filesystem | `write.reversible` | R2 | ✅ | 将文件或目录安全移动到授权目录内的另一位置（原生 openat2，支持一键撤销） |
| `file.open` | filesystem | `ui` | R1 | — | 使用系统默认关联程序打开授权目录内的文件或文件夹 |
| `file.open_with` | filesystem | `ui` | R1 | — | 使用指定应用程序打开授权目录内的文件（「用 WPS 打开周报」） |
| `file.recent` | filesystem | `observe` | R0 | — | 查询最近打开或最近修改的授权目录文件（GTK recently-used + IntentOS 记录） |
| `file.rename` | filesystem | `write.reversible` | R2 | ✅ | 在同一授权目录内安全重命名文件（原生 openat2 + RENAME_NOREPLACE，支持一键撤销） |
| `file.reveal` | filesystem | `ui` | R1 | — | 在系统文件管理器中打开文件所在目录并高亮选中（D-Bus FileManager1 / gio） |
| `file.search` | filesystem | `observe` | R0 | — | 在授权目录中按名称、拼音、扩展名/类型、修改时间、文件大小检索文件 |
| `file.trash` | filesystem | `write.reversible` | R2 | ✅ | 将授权目录内的文件移入系统回收站（不永久删除，支持从回收站撤销恢复） |
| `file.write` | filesystem | `write.reversible` | R2 | ✅ | 在授权目录内新建或受备份保护地覆盖文本文件（超出备份配额时自动升级为不可撤销审批） |
| `git.diff` | devtools | `observe` | R0 | — | 查看当前或指定 Git 仓库尚未提交的改动统计（git diff --stat） |
| `git.log` | devtools | `observe` | R0 | — | 查看当前或指定 Git 仓库最近提交记录（固定安全参数，无 Shell 拼接） |
| `git.status` | devtools | `observe` | R0 | — | 查看授权目录内 Git 仓库的分支与工作区状态 |
| `input.keyboard.repeat` | system | `setting` | R1 | ✅ | 设置键盘按键连发延迟与间隔（delay 150–1000 ms，interval 10–100 ms，可撤销） |
| `input.mouse.speed` | system | `setting` | R1 | ✅ | 设置或相对调整鼠标指针速度（-1.0 至 1.0，步长 0.2，读回验证并可撤销） |
| `input.source.switch` | system | `setting` | R1 | ✅ | 切换当前键盘输入源/中英文输入法（GNOME 扩展桥接） |
| `input.touchpad.natural_scroll` | system | `setting` | R1 | ✅ | 开启或关闭触控板自然滚动方向（natural-scroll，可撤销） |
| `input.touchpad.speed` | system | `setting` | R1 | ✅ | 设置或相对调整触控板指针速度（-1.0 至 1.0，步长 0.2，可撤销） |
| `input.touchpad.tap_to_click` | system | `setting` | R1 | ✅ | 开启或关闭触控板轻触点击（tap-to-click，可撤销） |
| `media.control` | system | `ui` | R1 | — | 控制系统媒体播放（播放、暂停、下一首、上一首、查询当前曲目，MPRIS / playerctl） |
| `network.airplane.set` | system | `process.control` | R3 | ✅ | 开启或关闭飞行模式（会断开全部无线连接，强制人工确认 confirm_each） |
| `network.ip` | devtools | `observe` | R0 | — | 查询本机局域网 IPv4/IPv6 地址与网卡列表（ip -j addr 结构化输出） |
| `network.status` | system | `observe` | R0 | — | 查看当前网络连接状态、活动网卡与网关信息 |
| `network.wifi.connect` | system | `setting` | R1 | — | 连接已保存的 Wi-Fi 网络；若为未保存新网络则绝不索要密码，自动打开系统 Wi-Fi 设置页 |
| `network.wifi.list` | system | `observe` | R0 | — | 扫描并列出周围可用的 Wi-Fi 无线网络信号（nmcli device wifi list） |
| `network.wifi.power` | system | `setting` | R1 | ✅ | 开启或关闭系统 Wi-Fi 无线网卡开关（nmcli radio wifi，可撤销） |
| `notify.dnd.set` | system | `setting` | R1 | ✅ | 开启或关闭系统勿扰模式（控制通知横幅弹出，支持读回与撤销） |
| `package.search` | devtools | `observe` | R0 | — | 查询已安装或软件源中的软件包信息（dpkg-query / apt-cache，只读零修改） |
| `port.inspect` | devtools | `observe` | R0 | — | 查询指定端口或全部监听端口对应的进程信息 |
| `power.battery.status` | system | `observe` | R0 | — | 查询电池剩余电量百分比、充放电状态与预计续航时间（UPower / sysfs） |
| `power.profile.get` | system | `observe` | R0 | — | 查询当前系统电源性能档位（省电 / 平衡 / 性能） |
| `power.profile.set` | system | `setting` | R1 | ✅ | 切换系统电源性能模式（power-saver 省电 / balanced 平衡 / performance 性能，可撤销） |
| `power.session` | system | `system.admin` | R3 | — | 执行休眠/挂起、重启、关机或注销会话（不可逆高影响操作，强制人工确认并提示保存工作） |
| `process.list` | devtools | `observe` | R0 | — | 列出当前占用内存或 CPU 最高的前 N 个进程（结构化采样） |
| `process.terminate` | devtools | `process.control` | R3 | — | 请求结束指定 PID 的用户态进程（先发 SIGTERM 并核实退出，强制人工确认，保护核心守护进程） |
| `project.open` | devtools | `ui` | R1 | — | 使用首选代码编辑器（如 VS Code）打开指定项目目录 |
| `scene.apply` | system | `setting` | R1 | ✅ | 一句话应用组合设置场景（内置护眼模式、演示模式、安静模式及用户保存的自定义场景，单变更集原子撤销） |
| `screen.autolock.set` | system | `setting` | R1 | ✅ | 开启或关闭屏幕空闲自动锁定（org.gnome.desktop.screensaver lock-enabled，可撤销） |
| `screen.lock` | system | `ui` | R1 | — | 立即锁定当前桌面会话屏幕（loginctl lock-session） |
| `screenshot.take` | system | `write.reversible` | R2 | ✅ | 调用 GNOME Shell / XDG Desktop Portal 执行全屏、当前窗口或区域截图 |
| `settings.open` | system | `ui` | R1 | — | 打开系统设置中心首页 |
| `settings.open_panel` | system | `ui` | R1 | — | 打开指定的系统设置面板（蓝牙、显示、声音、网络/Wi-Fi、电源、外观、通知、鼠标、键盘、关于等） |
| `settings.reset` | system | `setting` | R1 | ✅ | 将白名单内的某项系统设置恢复为系统默认值（支持撤销） |
| `sound.mic.mute.set` | system | `setting` | R1 | ✅ | 开启、关闭或切换麦克风静音状态（闭麦/开麦，读回验证并可撤销） |
| `sound.mic.volume.set` | system | `setting` | R1 | ✅ | 设置或相对调整麦克风输入音量（0–100%，步长 10%，读回验证并可撤销） |
| `sound.mute.set` | system | `setting` | R1 | ✅ | 开启、关闭或切换系统静音状态（读回验证并支持撤销） |
| `sound.output.list` | system | `observe` | R0 | — | 列出当前可用的音频输出设备（耳机、扬声器、HDMI/蓝牙音箱） |
| `sound.output.set` | system | `setting` | R1 | ✅ | 按设备名模糊匹配切换默认音频输出设备（如切到耳机/外放，可撤销） |
| `sound.volume.get` | system | `observe` | R0 | — | 查询当前默认音频输出设备的音量与静音状态 |
| `sound.volume.set` | system | `setting` | R1 | ✅ | 设置或相对调整系统输出音量（0–100%，步长 10%，读回验证并支持一键撤销） |
| `system.inspect` | devtools | `observe` | R0 | — | 采样当前系统负载、内存用量、运行时间与内核信息 |
| `terminal.handoff` | devtools | `ui` | R1 | — | 将建议的终端命令安全交接至用户输入框（变为 `$ ...`，必须由用户亲自回车才执行） |
| `terminal.open_at` | devtools | `ui` | R1 | — | 探测系统默认终端模拟器并在指定目录打开新窗口 |
| `web.open` | web | `ui` | R1 | — | 在默认浏览器中打开安全的 HTTP/HTTPS 网站或本地开发端口 |
| `web.resolve` | web | `observe` | R0 | — | 将站点名称、缩写或地址解析为安全的 HTTP/HTTPS URL |
| `web.search` | web | `ui` | R1 | — | 使用默认搜索引擎（Google）或指定搜索引擎检索关键词并在浏览器打开 |
| `web.search_site` | web | `ui` | R1 | — | 使用站内搜索模板（GitHub、B站、知乎、crates.io、docs.rs、Stack Overflow 等）搜索关键词 |
| `window.focus` | applications | `ui` | R1 | — | 将已运行的指定窗口或应用置于前台聚焦（GNOME Shell 扩展桥接） |
| `window.list` | applications | `observe` | R0 | — | 列出当前桌面会话打开的窗口列表（通过 GNOME Shell 扩展桥接，Wayland 原生） |
