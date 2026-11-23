# ebpf-xdp-tail-call-budget-validator

纯静态的 XDP tail call 验证器：给定程序图、跳转边、tail call 预算、prog map 更新、返回码与目标接口，
计算所有合法路径与递归风险，报告最大深度、危险边和需要合并的程序。

## 重要说明：不加载真实 eBPF

本工具**不加载、不挂载、不运行任何 eBPF/XDP 程序**，不访问内核、bpf 系统调用或真实网卡。
它只对调用方以 JSON 提供的程序图做图分析，模拟 tail call 在预算耗尽、map 未命中、目标缺失和
递归跳转时的语义。适合在设计评审、CI 和配置审计阶段使用，不能替代真实内核中的 verifier。

## 环境与运行

- Node.js `24.16.0`（`engines` 要求 `>=24`），无第三方依赖，使用内置 `node:test`。
- 执行测试：`node --test`（或 `npm test`）。
- CLI：`node bin/xdp-validator.js examples/self-loop.json`，存在危险路径时退出码为 `1`，输入/结构错误为 `2`。

## 输入格式

```json
{
  "maxTailCalls": 3,
  "entry": "p0",
  "interfaces": ["eth0"],
  "programs": [
    { "id": "p0", "returnCode": "XDP_DROP" },
    { "id": "p1", "returnCode": "XDP_REDIRECT", "interface": "eth0" }
  ],
  "mapUpdates": [
    { "map": "jump_map", "key": 0, "targetProgram": "p1" },
    { "map": "jump_map", "key": 5, "targetProgram": "ghost", "insertFails": true }
  ],
  "edges": [
    { "from": "p0", "map": "jump_map", "key": 0 },
    { "from": "p0", "map": "jump_map", "key": 9, "to": "p1" }
  ]
}
```

- `programs`：程序节点。`returnCode` 取 `XDP_ABORTED | XDP_DROP | XDP_PASS | XDP_TX | XDP_REDIRECT`；
  `XDP_REDIRECT` 可声明 `interface`，声明了 `interfaces` 但接口不存在会产生 `missing-interface` 告警。
- `edges`：tail call 边。`to` 可省略，此时按 `map` + `key` 从 map 更新结果解析目标；
  也可直接写 `to` 表示静态目标。
- `mapUpdates`：按顺序模拟 prog map 更新。`insertFails: true`（或 `failed: true`）表示插入失败，
  map 保持旧内容，并产生 `map-insert-failed` 告警；同一 `map`/`key` 的后续成功更新覆盖旧目标，可用于版本切换。
- `maxTailCalls`：允许的最大 tail call 次数（非负整数）。

## 分析语义

- **递归/自循环**：Tarjan SCC 找出所有环（包括程序跳转到自身的自环）；
  DFS 遇到回边时终止该路径，标记危险边原因 `self-loop` 或 `recursion-back-edge`，
  并把环内程序列入合并候选。
- **预算耗尽**：第 `maxTailCalls + 1` 次跳转不会发生，数据包在当前程序 fallthrough；
  对应边标记 `budget-exceeded`，路径终端为 `budget-exceeded`。
- **缺失目标 / map 未命中**：map 查无此项记 `map-miss`；解析出的程序 id 不存在记 `missing-target`。
  tail call 不发生，包停留在源程序：源程序有返回码时走兜底合法路径（`viaFallback: true`），
  没有返回码时记危险 `fallthrough` 路径。
- **最坏跳转次数**：每条路径都给出 `worstCaseJumps`。普通终止路径等于实际跳数；
  递归与超预算路径按“最多能跳多少次”计为 `max(预算, 当前跳数)`。
- `maxDepth` 是所有路径 `worstCaseJumps` 的最大值；`unreachablePrograms` 列出从入口不可达的程序。

## 输出字段

- `legalPaths` / `dangerousPaths`：路径列表，含 `nodes`、`edges`、`jumps`、`worstCaseJumps` 和 `terminal`。
- `maxDepth`：最坏情况下的最大 tail call 深度。
- `dangerousEdges`：危险边及原因集合（`self-loop`、`recursion-back-edge`、`map-miss`、
  `missing-target`、`budget-exceeded`）。
- `recursion.cycles` / `recursion.selfLoops`：递归环与自环。
- `mergeCandidates`：需要合并的程序组，`recursion-cycle` 表示消除递归环，
  `budget-exceeded` 表示沿该路径合并以压回预算内。
- `warnings`：map 插入失败、接口缺失、未知返回码、无返回码程序等非致命问题。

## 测试覆盖

`test/validator.test.js` 使用 `node:test`，覆盖：

1. 自循环：自环危险边、递归路径、合并候选与最坏跳数。
2. 长链超预算：`budget-exceeded` 路径、fallthrough 程序、map 插入失败与 map-miss 兜底。
3. 目标丢失：`missing-target` 危险边与源程序兜底路径。
4. 版本切换：同一 map 键在不同更新序列下解析到 `v1`/`v2`，插入失败时保留旧目标。
5. 目标接口与无返回码 fallthrough、不可达程序。
