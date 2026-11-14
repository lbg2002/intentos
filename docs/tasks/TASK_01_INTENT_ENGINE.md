# 实现任务书一（Agent-1）：柔性意图引擎、通用槽位解析与上下文动作模块 (`intent_engine`)

> **角色定位**：IntentOS 核心自然语言理解与路由架构师（Agent-1）  
> **参考设计方案**：`docs/IntentOS_设计方案_v0.3.md` §1.3、§3.1（UI-02/UI-05/UI-06/键盘约定）、§4.1–§4.7、§11.6  
> **解决核心痛点**：解决现有系统「太笨了、正则死板、换种说法就听不懂、候选列表杂乱无分组、缺乏 `Alt+Enter` 动作菜单与多轮指代理解」的问题。

---

## 1. 严格的文件读写边界（防冲突红线）

- ✅ **你唯一允许新建和修改的目录**：
  `crates/intentosd/src/intent_engine/`
- ❌ **严禁修改任何其他目录或文件**：
  严禁修改 `Cargo.toml`、`crates/protocol/`、`crates/intentosd/src/lib.rs`、`crates/intentosd/src/core.rs`、`crates/intentosd/src/router.rs` 等任何外部文件！（主干已在 `lib.rs` 和 `core.rs` 中挂载了 `pub mod intent_engine;` 并转发了 `domain = "intent_engine"` 的 `ModuleRpc` 请求）。

---

## 2. 模块内部文件规划（功能模块化拆分）

请在 `crates/intentosd/src/intent_engine/` 下按以下职责拆分子模块，并在 `mod.rs` 中组织导出：

```text
crates/intentosd/src/intent_engine/
├── mod.rs                # 模块入口、IntentEngine 核心结构体与 handle_module_rpc 分发器
├── pattern_compiler.rs   # 从 87+ 个 CapabilityDescriptor 的 aliases / l0_patterns 动态编译柔性匹配规则
├── fuzzy_scorer.rs       # 拼音全拼/首字母、中英同义词表、編輯距离（Levenshtein/Jaro）、频度（Frecency）多维打分器
├── slot_extractor.rs     # 通用 Schema 驱动槽位解析器（数值、百分比、相对增减、时间区间、文件大小、扩展名/MIME、目录名）
├── context_resolver.rs   # 多轮指代与桌面上下文消歧器（「它」「刚才那个文件」「这些文件」「当前窗口」「选中文本」）
├── grouped_candidates.rs # 分组候选构建器（按 应用 / 文件 / 网站 / 系统设置 / 技能工作流 / 命令直通 分组）与 Alt+Enter 动作菜单生成器
└── compound_splitter.rs  # 复合意图拆解与 L1 决策校准器（如「把周报转成 pdf 然后移到文档目录」拆解为有序步骤预览）
```

---

## 3. 核心功能实现要求

### 3.1 动态 Descriptor 语法与柔性口语匹配 (`pattern_compiler.rs` + `fuzzy_scorer.rs`)
1. **摒弃死板的全句正则**：启动或调用时读取 `core.broker.descriptors()`，根据每个 `CapabilityDescriptor` 的 `id`、`summary`、`aliases`、`l0_patterns`、`category` 自动构建口语意图索引。
2. **中英口语同义词与错别字容错**：
   - 内置丰富的动词/形容词口语映射（如：「搞大点/调高点/大声点/拉满/小一点/暗一点/亮一点/关掉/干掉/弄成/切到/查下/瞅瞅/在哪」）。
   - 支持拼音全拼、拼音首字母缩写（如 `hymoshi` / `hyms` → `护眼模式`，`wbbjq` → `文本编辑器`）及 1~2 个字符的常见输入容错。
   - 排序综合因子（§4.6）：`完全匹配 > 前缀匹配 > 别名/同义词 > 拼音匹配 > 模糊 bigram` × `Frecency 频度权重`。

### 3.2 通用 Schema 驱动槽位解析器 (`slot_extractor.rs`)
根据目标 `CapabilityDescriptor.input_schema` 的属性类型自动提取参数，而不是只硬编码几个能力：
1. **数值与相对调节**：识别 `30`、`30%`、`三十`、`+10%`、`调大 15`、`调小一点`（默认相对步长 `±10%` 或读取 `SettingMeta.step`）、`拉满`（`100`）、`最低`（`0` 或 `min`）。
2. **时间条件解析（§4.5）**：识别 `今天`、`昨天`、`前天`、`本周`、`上周`、`最近 N 天/小时`、`N 月`，转换为 `mtime` 起止秒数。
3. **文件大小与类型解析（§4.5）**：识别 `大于 1G`、`超过 500M`、`小于 100K`，以及 `PDF/Word/表格/图片/视频/压缩包/代码/md/rs/py` 映射为扩展名集合。
4. **位置与目录解析**：识别 `下载里`、`桌面上`、`文档里`、`当前目录`、`在 <项目名> 里`。

### 3.3 多轮上下文指代消歧 (`context_resolver.rs`)
1. 支持解析输入中的指代词：
   - 单数指代：「它」「这个文件」「刚才那个」「上一个结果」→ 绑定会话最近操作的文件/应用/URL。
   - 复数指代：「它们」「这些文件」「刚才搜出来的文件」→ 绑定上一轮 `file.search` / `file.recent` 返回的文件列表。
   - 桌面上下文引用：「当前窗口」「选中的文字」「剪贴板里的内容」→ 从 `payload.desktop_context` 或剪贴板状态注入。
2. 当指代不唯一时，生成结构化的澄清候选（`Clarify`），绝不盲猜误执行（误执行率 < 0.5%）。

### 3.4 分组即时候选与 `Alt+Enter` 上下文动作菜单 (`grouped_candidates.rs`)
1. **分组候选 (`query_grouped_candidates`)**：
   输入过程中返回除扁平 `items` 外的结构化分组 `groups`（§3.1 UI-02）：
   - `direct_intent`（L0 确定性意图直接执行，如设置调节、组合场景）
   - `apps`（应用：标注已运行/未运行）
   - `files`（文件：显示相对路径、修改时间、体积）
   - `web`（网站直达、书签、站内搜索模板、默认搜索引擎兜底）
   - `settings`（系统设置项与控制中心面板）
   - `skills`（匹配的技能、工作流或命令交接建议）
2. **上下文动作菜单 (`get_candidate_actions`，对应 §3.1 UI-06 `Alt+Enter`)**：
   针对任意候选或结果项，生成可直接执行的动作列表 `actions: Vec<CandidateAction>`：
   - **文件项动作**：
     1. `打开 (Enter)` → `file.open`
     2. `用指定应用打开…` → `file.open_with`
     3. `打开所在文件夹` → `file.reveal`
     4. `复制完整路径 (Ctrl+C)` → `clipboard.copy`
     5. `重命名…` → `file.rename`
     6. `移入回收站` → `file.trash`
   - **应用项动作**：
     1. `启动 / 聚焦窗口` → `app.launch` / `window.focus`
     2. `打开新窗口` → `app.launch` (`new_window: true`)
     3. `安全退出应用` → `app.quit`
   - **网站项动作**：
     1. `默认浏览器打开` → `web.open`
     2. `复制链接 (Ctrl+C)` → `clipboard.copy`
     3. `在此站点内搜索…` → `web.search_site`
   - **设置项动作**：
     1. `立即执行此设置`
     2. `恢复该设置默认值` → `settings.reset`
     3. `在系统控制中心打开对应面板` → `settings.open_panel`

### 3.5 复合意图拆解与智能预演 (`compound_splitter.rs`)
当用户输入包含连词（「把 X 复制到 Y 然后打开它」「先开启护眼模式再把音量调到 20」「找一下昨天下载的 zip 并解压到桌面」）时：
- 自动将其拆解为有序的子意图步骤列表 `Vec<PlannedStep>`，标注每一步映射的 `capability_id`、解析出的 `arguments`、预估效应 `Effect` 以及是否可撤销，供前端直接展示多步执行预览卡片或交由执行中心按序执行。

---

## 4. `ModuleRpc` 接口契约（必须在 `mod.rs` 的 `handle_module_rpc` 中实现）

前端与其他模块将通过 `domain: "intent_engine"` 调用以下 `action`：

| `action` 名称 | 输入 `payload` | 返回 `Value` 结构 |
|---|---|---|
| `"ping"` | `{}` | `{ "module": "intent_engine", "status": "ready", ... }` |
| `"query_grouped_candidates"` | `{ "query": "打开周报", "category_filter": null, "session_id": "..." }` | `{ "query": "...", "elapsed_us": 1200, "l0_direct_match": true, "groups": [ { "group_id": "files", "title": "文件", "items": [...] }, ... ], "items": [...] }`（每个 item 含 `actions: [...]` 和 `completion_text`） |
| `"get_candidate_actions"` | `{ "candidate_id": "...", "kind": "file", "target": "/path/to/file" }` | `{ "actions": [ { "id": "open", "label": "打开", "shortcut": "Enter", "capability_id": "file.open", "arguments": {...} }, ... ] }` |
| `"analyze_intent"` | `{ "text": "把音量调小一点然后进入护眼模式", "session_id": "...", "desktop_context": {...} }` | `{ "resolved_text": "...", "route": "L0 | L1 | L2", "is_compound": true, "steps": [...], "confidence": 0.94, "clarification": null }` |
| `"execute_compound"` | `{ "text": "...", "steps": [...], "session_id": "...", "incognito": false }` | 按序调用 `core.broker.dispatch` 执行拆解后的多步确定性操作，汇总返回结果与 `changeset_ids` |
| `"record_candidate_feedback"` | `{ "query": "...", "selected_id": "..." }` | 记录用户选择到 `index_db` Frecency 权重与 L1 决策校准表，越用越聪明 |

---

## 5. 验收与自测标准

1. 所有代码必须包含 `#![forbid(unsafe_code)]`，无 `unwrap()` 导致的未受控崩溃。
2. 在 `crates/intentosd/src/intent_engine/` 内编写完整的 `#[cfg(test)] mod tests`，覆盖：
   - 口语/拼音/同义词匹配测试（如 `hyms` → 护眼模式，`声音小点` → `sound.volume.set`）；
   - 通用槽位提取测试（时间、文件大小、百分比、相对步长）；
   - 分组候选与 `Alt+Enter` 动作菜单生成测试；
   - 复合意图拆解测试（「静音并开启勿扰模式」→ 2 个有序步骤）。
3. 运行 `cargo test -p intentosd intent_engine` 与 `cargo clippy -p intentosd -- -D warnings` 必须 100% 通过且零警告。
