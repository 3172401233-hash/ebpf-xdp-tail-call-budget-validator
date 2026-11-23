import { test } from 'node:test';
import assert from 'node:assert/strict';

import { validateXdpGraph, XDP_RETURN_CODES } from '../src/validator.js';

test('自循环：程序 tail call 自身被标记为递归危险边并建议合并', () => {
  const result = validateXdpGraph({
    maxTailCalls: 3,
    entry: 'p0',
    programs: [
      { id: 'p0', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'p1', returnCode: XDP_RETURN_CODES.XDP_PASS },
    ],
    edges: [
      { from: 'p0', map: 'jm', key: 0, to: 'p1' },
      { from: 'p1', map: 'jm', key: 1, to: 'p1' },
    ],
  });

  assert.equal(result.recursion.hasCycle, true);
  assert.deepEqual(result.recursion.selfLoops, [
    { program: 'p1', map: 'jm', key: 1 },
  ]);

  const selfLoopEdge = result.dangerousEdges.find((edge) => edge.from === 'p1' && edge.to === 'p1');
  assert.ok(selfLoopEdge);
  assert.deepEqual(selfLoopEdge.reasons, ['self-loop']);

  const recursionPath = result.dangerousPaths.find(
    (path) => path.terminal.type === 'recursion',
  );
  assert.ok(recursionPath);
  assert.equal(recursionPath.worstCaseJumps, 3);
  assert.equal(result.maxDepth, 3);

  assert.ok(
    result.mergeCandidates.some(
      (candidate) =>
        candidate.reason === 'recursion-cycle' &&
        JSON.stringify(candidate.programs) === JSON.stringify(['p1']),
    ),
  );

  const legal = result.legalPaths.find((path) => path.terminal.returnCode === 'XDP_PASS');
  assert.ok(legal);
  assert.deepEqual(legal.nodes, ['p0', 'p1']);
  assert.equal(legal.worstCaseJumps, 1);
});

test('长链：无环但超过 tail call 预算时报告超预算路径与最坏跳转次数', () => {
  const result = validateXdpGraph({
    maxTailCalls: 3,
    entry: 'p0',
    programs: [
      { id: 'p0', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'p1', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'p2', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'p3', returnCode: XDP_RETURN_CODES.XDP_PASS },
      { id: 'p4', returnCode: XDP_RETURN_CODES.XDP_PASS },
    ],
    mapUpdates: [
      { map: 'jm', key: 9, targetProgram: 'pX', insertFails: true },
    ],
    edges: [
      { from: 'p0', map: 'jm', key: 0, to: 'p1' },
      { from: 'p1', map: 'jm', key: 1, to: 'p2' },
      { from: 'p2', map: 'jm', key: 2, to: 'p3' },
      { from: 'p3', map: 'jm', key: 3, to: 'p4' },
      { from: 'p2', map: 'jm', key: 4, to: 'p4' },
      { from: 'p4', map: 'jm', key: 9 },
    ],
  });

  const exceeded = result.dangerousPaths.find(
    (path) => path.terminal.type === 'budget-exceeded',
  );
  assert.ok(exceeded);
  assert.equal(exceeded.jumps, 3);
  assert.equal(exceeded.worstCaseJumps, 3);
  assert.equal(exceeded.terminal.fallthroughProgram, 'p3');
  assert.equal(result.maxDepth, 3);

  const budgetEdge = result.dangerousEdges.find((edge) =>
    edge.reasons.includes('budget-exceeded'),
  );
  assert.deepEqual([budgetEdge.from, budgetEdge.to], ['p3', 'p4']);

  const legal = result.legalPaths.find((path) => path.terminal.type === 'return');
  assert.deepEqual(legal.nodes, ['p0', 'p1', 'p2', 'p3']);
  assert.equal(legal.jumps, 3);

  const mapMiss = result.dangerousEdges.find((edge) => edge.reasons.includes('map-miss'));
  assert.ok(mapMiss);
  assert.equal(mapMiss.from, 'p4');

  const fallback = result.legalPaths.find((path) => path.terminal.viaFallback === true);
  assert.ok(fallback);
  assert.equal(fallback.terminal.unresolvedEdge.reason, 'map-miss');
  assert.equal(fallback.terminal.program, 'p4');
  assert.equal(fallback.jumps, 3);

  assert.ok(
    result.warnings.some(
      (warning) =>
        warning.code === 'map-insert-failed' &&
        warning.map === 'jm' &&
        warning.key === 9,
    ),
  );

  assert.equal(result.recursion.hasCycle, false);
  assert.ok(
    result.mergeCandidates.some((candidate) => candidate.reason === 'budget-exceeded'),
  );
});

test('目标丢失：map 指向不存在的程序时标记 missing-target 并在源程序兜底', () => {
  const result = validateXdpGraph({
    maxTailCalls: 4,
    entry: 'p0',
    programs: [
      { id: 'p0', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'p1', returnCode: XDP_RETURN_CODES.XDP_PASS },
    ],
    mapUpdates: [
      { map: 'jm', key: 0, targetProgram: 'ghost' },
      { map: 'jm', key: 1, targetProgram: 'p1' },
    ],
    edges: [
      { from: 'p0', map: 'jm', key: 0 },
      { from: 'p0', map: 'jm', key: 1 },
    ],
  });

  const missing = result.dangerousEdges.find((edge) =>
    edge.reasons.includes('missing-target'),
  );
  assert.ok(missing);
  assert.equal(missing.from, 'p0');
  assert.equal(missing.to, 'ghost');

  const fallback = result.legalPaths.find((path) => path.terminal.viaFallback === true);
  assert.ok(fallback);
  assert.equal(fallback.terminal.unresolvedEdge.reason, 'missing-target');
  assert.equal(fallback.terminal.returnCode, 'XDP_DROP');

  const reachable = result.legalPaths.find((path) =>
    path.nodes.includes('p1'),
  );
  assert.ok(reachable);
  assert.equal(reachable.jumps, 1);
});

test('版本切换：同一边按 map 更新解析到不同目标，失败版本保留旧目标', () => {
  const programs = [
    { id: 'p0', returnCode: XDP_RETURN_CODES.XDP_DROP },
    { id: 'v1', returnCode: XDP_RETURN_CODES.XDP_DROP },
    { id: 'v2', returnCode: XDP_RETURN_CODES.XDP_PASS },
  ];
  const edges = [{ from: 'p0', map: 'jm', key: 7 }];

  const v1 = validateXdpGraph({
    maxTailCalls: 2,
    entry: 'p0',
    programs,
    mapUpdates: [{ map: 'jm', key: 7, targetProgram: 'v1' }],
    edges,
  });
  assert.deepEqual(
    v1.legalPaths.find((path) => path.jumps === 1).nodes,
    ['p0', 'v1'],
  );
  assert.equal(v1.dangerousEdges.length, 0);

  const switched = validateXdpGraph({
    maxTailCalls: 2,
    entry: 'p0',
    programs,
    mapUpdates: [
      { map: 'jm', key: 7, targetProgram: 'v1' },
      { map: 'jm', key: 7, targetProgram: 'v2' },
    ],
    edges,
  });
  assert.deepEqual(
    switched.legalPaths.find((path) => path.jumps === 1).nodes,
    ['p0', 'v2'],
  );

  const failedSwitch = validateXdpGraph({
    maxTailCalls: 2,
    entry: 'p0',
    programs,
    mapUpdates: [
      { map: 'jm', key: 7, targetProgram: 'v1' },
      { map: 'jm', key: 7, targetProgram: 'v2', insertFails: true },
    ],
    edges,
  });
  assert.deepEqual(
    failedSwitch.legalPaths.find((path) => path.jumps === 1).nodes,
    ['p0', 'v1'],
  );
  assert.ok(
    failedSwitch.warnings.some(
      (warning) => warning.code === 'map-insert-failed' && warning.key === 7,
    ),
  );
});

test('目标接口：XDP_REDIRECT 缺少已声明接口时给出告警，XDP_TX 不需要接口', () => {
  const result = validateXdpGraph({
    maxTailCalls: 1,
    entry: 'p0',
    interfaces: ['eth0'],
    programs: [
      { id: 'p0', returnCode: XDP_RETURN_CODES.XDP_TX },
      { id: 'p1', returnCode: XDP_RETURN_CODES.XDP_REDIRECT, interface: 'eth9' },
      { id: 'p2', returnCode: XDP_RETURN_CODES.XDP_REDIRECT, interface: 'eth0' },
    ],
    edges: [
      { from: 'p0', to: 'p1', map: 'jm', key: 0 },
      { from: 'p0', to: 'p2', map: 'jm', key: 1 },
    ],
  });

  const missingInterface = result.warnings.find(
    (warning) => warning.code === 'missing-interface' && warning.program === 'p1',
  );
  assert.ok(missingInterface);
  assert.equal(
    result.warnings.some(
      (warning) => warning.code === 'missing-interface' && warning.program === 'p0',
    ),
    false,
  );
  assert.equal(
    result.warnings.some(
      (warning) => warning.code === 'missing-interface' && warning.program === 'p2',
    ),
    false,
  );
});

test('无返回码程序在末端 fallthrough 且不可达程序被列出', () => {
  const result = validateXdpGraph({
    maxTailCalls: 3,
    entry: 'p0',
    programs: [
      { id: 'p0', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'p1' },
      { id: 'orphan', returnCode: XDP_RETURN_CODES.XDP_PASS },
    ],
    edges: [{ from: 'p0', to: 'p1', map: 'jm', key: 0 }],
  });

  const fallthrough = result.dangerousPaths.find(
    (path) => path.terminal.type === 'fallthrough',
  );
  assert.ok(fallthrough);
  assert.equal(fallthrough.terminal.program, 'p1');
  assert.deepEqual(result.unreachablePrograms, ['orphan']);
});

test('多节点环：Tarjan SCC 识别 b-c 环并标记回边与合并候选', () => {
  const result = validateXdpGraph({
    maxTailCalls: 5,
    entry: 'a',
    programs: [
      { id: 'a', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'b', returnCode: XDP_RETURN_CODES.XDP_DROP },
      { id: 'c', returnCode: XDP_RETURN_CODES.XDP_DROP },
    ],
    edges: [
      { from: 'a', to: 'b', map: 'jm', key: 0 },
      { from: 'b', to: 'c', map: 'jm', key: 1 },
      { from: 'c', to: 'b', map: 'jm', key: 2 },
    ],
  });

  assert.equal(result.recursion.hasCycle, true);
  assert.deepEqual(result.recursion.cycles, [['b', 'c']]);
  assert.deepEqual(result.recursion.selfLoops, []);

  const backEdge = result.dangerousEdges.find((edge) =>
    edge.reasons.includes('recursion-back-edge'),
  );
  assert.deepEqual([backEdge.from, backEdge.to], ['c', 'b']);

  const recursionPath = result.dangerousPaths.find(
    (path) => path.terminal.type === 'recursion',
  );
  assert.deepEqual(recursionPath.terminal.cyclePrograms, ['b', 'c']);
  assert.equal(recursionPath.worstCaseJumps, 5);
  assert.equal(result.maxDepth, 5);

  assert.ok(
    result.mergeCandidates.some(
      (candidate) =>
        candidate.reason === 'recursion-cycle' &&
        JSON.stringify(candidate.programs) === JSON.stringify(['b', 'c']),
    ),
  );
});
