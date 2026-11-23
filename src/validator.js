// 纯静态 XDP tail call 预算验证器。
// 不加载、不挂载任何真实 eBPF 程序，只对调用方提供的程序图做图分析。

export const XDP_RETURN_CODES = Object.freeze({
  XDP_ABORTED: 'XDP_ABORTED',
  XDP_DROP: 'XDP_DROP',
  XDP_PASS: 'XDP_PASS',
  XDP_TX: 'XDP_TX',
  XDP_REDIRECT: 'XDP_REDIRECT',
});

const TERMINAL = Object.freeze({
  RETURN: 'return',
  RECURSION: 'recursion',
  BUDGET_EXCEEDED: 'budget-exceeded',
  FALLTHROUGH: 'fallthrough',
});

const EDGE_REASON = Object.freeze({
  SELF_LOOP: 'self-loop',
  RECURSION_BACK_EDGE: 'recursion-back-edge',
  MISSING_TARGET: 'missing-target',
  MAP_MISS: 'map-miss',
  BUDGET_EXCEEDED: 'budget-exceeded',
});

function edgeKey(edge) {
  return `${edge.from}->${edge.to ?? '*'}#${edge.map}/${edge.key}`;
}

function buildMapState(mapUpdates, warnings) {
  // 按顺序模拟 prog map 更新；insertFails 的更新不会改变 map 内容。
  const state = new Map();
  for (const update of mapUpdates ?? []) {
    const key = `${update.map}::${update.key}`;
    if (update.insertFails || update.failed) {
      warnings.push({
        code: 'map-insert-failed',
        map: update.map,
        key: update.key,
        targetProgram: update.targetProgram ?? null,
      });
      continue;
    }
    state.set(key, {
      targetProgram: update.targetProgram,
      interface: update.interface ?? null,
    });
  }
  return state;
}

function resolveEdges(edges, programs, mapState, addDangerousEdge) {
  const programIds = new Set(programs.map((program) => program.id));
  const resolved = [];
  for (const edge of edges) {
    const record = {
      from: edge.from,
      map: edge.map ?? null,
      key: edge.key ?? null,
      to: edge.to ?? null,
      problem: null,
    };
    if (!programIds.has(record.from)) {
      throw new TypeError(`边的源程序不存在: ${record.from}`);
    }
    if (record.to == null && record.map != null && record.key != null) {
      const lookup = mapState.get(`${record.map}::${record.key}`);
      if (!lookup) {
        record.problem = EDGE_REASON.MAP_MISS;
      } else {
        record.to = lookup.targetProgram;
        record.resolvedInterface = lookup.interface;
      }
    }
    if (record.problem == null && !programIds.has(record.to)) {
      record.problem = EDGE_REASON.MISSING_TARGET;
    }
    if (record.problem) {
      addDangerousEdge(record, record.problem);
    }
    resolved.push(record);
  }
  return resolved;
}

// Tarjan SCC：尺寸大于 1 的强连通分量即递归环；单点自环单独报告。
function findSccs(adjacency) {
  let index = 0;
  const stack = [];
  const onStack = new Set();
  const indices = new Map();
  const lowLinks = new Map();
  const components = [];

  function strongConnect(node) {
    indices.set(node, index);
    lowLinks.set(node, index);
    index += 1;
    stack.push(node);
    onStack.add(node);

    for (const edge of adjacency.get(node) ?? []) {
      if (edge.problem != null) {
        continue;
      }
      const neighbor = edge.to;
      if (!indices.has(neighbor)) {
        strongConnect(neighbor);
        lowLinks.set(node, Math.min(lowLinks.get(node), lowLinks.get(neighbor)));
      } else if (onStack.has(neighbor)) {
        lowLinks.set(node, Math.min(lowLinks.get(node), indices.get(neighbor)));
      }
    }

    if (lowLinks.get(node) === indices.get(node)) {
      const component = [];
      let current;
      do {
        current = stack.pop();
        onStack.delete(current);
        component.push(current);
      } while (current !== node);
      components.push(component);
    }
  }

  for (const node of adjacency.keys()) {
    if (!indices.has(node)) {
      strongConnect(node);
    }
  }
  return components;
}

function makeDangerousEdgeStore() {
  const edges = new Map();
  return {
    add(record, reason) {
      const key = edgeKey(record);
      if (!edges.has(key)) {
        edges.set(key, {
          from: record.from,
          to: record.to ?? null,
          map: record.map,
          key: record.key,
          reasons: [],
        });
      }
      const stored = edges.get(key);
      if (!stored.reasons.includes(reason)) {
        stored.reasons.push(reason);
      }
    },
    list() {
      return [...edges.values()];
    },
  };
}

function validatePrograms(programs, interfaces, warnings) {
  const byId = new Map();
  for (const program of programs) {
    if (byId.has(program.id)) {
      throw new TypeError(`程序 id 重复: ${program.id}`);
    }
    byId.set(program.id, program);
  }
  for (const program of programs) {
    const code = program.returnCode;
    if (code != null && !Object.values(XDP_RETURN_CODES).includes(code)) {
      warnings.push({
        code: 'unknown-return-code',
        program: program.id,
        returnCode: code,
      });
    }
    if (
      code === XDP_RETURN_CODES.XDP_REDIRECT &&
      Array.isArray(interfaces) &&
      interfaces.length > 0 &&
      (program.interface == null || !interfaces.includes(program.interface))
    ) {
      warnings.push({
        code: 'missing-interface',
        program: program.id,
        interface: program.interface ?? null,
      });
    }
  }
  return byId;
}

export function validateXdpGraph(input) {
  const warnings = [];
  const programs = input.programs ?? [];
  const programById = validatePrograms(programs, input.interfaces, warnings);
  const entry = input.entry ?? programs[0]?.id;
  if (entry == null || !programById.has(entry)) {
    throw new TypeError(`入口程序不存在: ${entry}`);
  }
  const budget = Number(input.maxTailCalls);
  if (!Number.isInteger(budget) || budget < 0) {
    throw new TypeError(`maxTailCalls 必须是非负整数，收到: ${input.maxTailCalls}`);
  }

  const mapState = buildMapState(input.mapUpdates, warnings);
  const dangerousStore = makeDangerousEdgeStore();
  const resolvedEdges = resolveEdges(
    input.edges ?? [],
    programs,
    mapState,
    dangerousStore.add.bind(dangerousStore),
  );

  const adjacency = new Map(programs.map((program) => [program.id, []]));
  for (const edge of resolvedEdges) {
    adjacency.get(edge.from).push(edge);
  }

  // 递归结构分析（覆盖不可达环，配合 unreachablePrograms 报告）。
  const components = findSccs(adjacency);
  const cycleOf = new Map();
  const cycles = [];
  const selfLoops = [];
  components.forEach((component) => {
    const sorted = [...component].sort();
    if (component.length > 1) {
      cycles.push(sorted);
      sorted.forEach((id) => cycleOf.set(id, sorted));
    } else {
      const node = component[0];
      const loopEdge = (adjacency.get(node) ?? []).find((edge) => edge.problem == null && edge.to === node);
      if (loopEdge) {
        cycles.push(sorted);
        cycleOf.set(node, sorted);
        selfLoops.push({
          program: node,
          map: loopEdge.map,
          key: loopEdge.key,
        });
      }
    }
  });

  const paths = [];
  const reachable = new Set();
  let pathSequence = 0;
  let maxDepth = 0;

  function recordPath(frame, status, terminal) {
    const worstCaseJumps =
      terminal.type === TERMINAL.RECURSION || terminal.type === TERMINAL.BUDGET_EXCEEDED
        ? Math.max(budget, frame.jumps)
        : frame.jumps;
    const path = {
      id: `path-${++pathSequence}`,
      status,
      nodes: [...frame.nodes],
      edges: frame.edgeTrail.map((edge) => ({
        from: edge.from,
        to: edge.to,
        map: edge.map,
        key: edge.key,
      })),
      jumps: frame.jumps,
      worstCaseJumps,
      terminal,
    };
    paths.push(path);
    maxDepth = Math.max(maxDepth, worstCaseJumps);
    return path;
  }

  // 预算受限的迭代式 DFS：预算本身保证枚举必然终止，onStack 负责拦截环。
  const root = {
    node: entry,
    next: 0,
    nodes: [entry],
    edgeTrail: [],
    jumps: 0,
    onStack: new Set([entry]),
  };
  const dfsStack = [root];
  const mergeKeys = new Set();
  const mergeCandidates = [];

  function addMergeCandidate(reason, candidatePrograms, pathId) {
    const ordered = [...candidatePrograms].sort();
    const key = `${reason}|${ordered.join(',')}`;
    if (mergeKeys.has(key)) {
      return;
    }
    mergeKeys.add(key);
    mergeCandidates.push({ reason, programs: ordered, pathId: pathId ?? null });
  }

  while (dfsStack.length > 0) {
    const frame = dfsStack[dfsStack.length - 1];
    reachable.add(frame.node);
    const outgoing = adjacency.get(frame.node) ?? [];

    if (frame.next >= outgoing.length) {
      const program = programById.get(frame.node);
      if (program.returnCode != null) {
        recordPath(frame, 'legal', {
          type: TERMINAL.RETURN,
          program: frame.node,
          returnCode: program.returnCode,
        });
      } else if (program.returnCode == null) {
        warnings.push({ code: 'no-return-program', program: frame.node });
        recordPath(frame, 'dangerous', {
          type: TERMINAL.FALLTHROUGH,
          program: frame.node,
        });
      }
      dfsStack.pop();
      continue;
    }

    const edge = outgoing[frame.next++];

    // map 未命中 / 目标缺失：tail call 不发生，包停留在源程序，按其返回码兜底。
    if (edge.problem != null) {
      const sourceProgram = programById.get(frame.node);
      const unresolvedEdge = { map: edge.map, key: edge.key, reason: edge.problem };
      if (sourceProgram.returnCode != null) {
        recordPath(frame, 'legal', {
          type: TERMINAL.RETURN,
          program: frame.node,
          returnCode: sourceProgram.returnCode,
          viaFallback: true,
          unresolvedEdge,
        });
      } else {
        recordPath(frame, 'dangerous', {
          type: TERMINAL.FALLTHROUGH,
          program: frame.node,
          unresolvedEdge,
        });
      }
      continue;
    }

    if (frame.onStack.has(edge.to)) {
      const reason =
        edge.to === frame.node ? EDGE_REASON.SELF_LOOP : EDGE_REASON.RECURSION_BACK_EDGE;
      dangerousStore.add(edge, reason);
      const path = recordPath(frame, 'dangerous', {
        type: TERMINAL.RECURSION,
        atProgram: frame.node,
        targetProgram: edge.to,
        cyclePrograms: cycleOf.get(edge.to) ?? [edge.to],
      });
      addMergeCandidate(
        'recursion-cycle',
        cycleOf.get(edge.to) ?? [edge.to],
        path.id,
      );
      continue;
    }

    if (frame.jumps + 1 > budget) {
      dangerousStore.add(edge, EDGE_REASON.BUDGET_EXCEEDED);
      const path = recordPath(frame, 'dangerous', {
        type: TERMINAL.BUDGET_EXCEEDED,
        atProgram: frame.node,
        attemptedTarget: edge.to,
        fallthroughProgram: frame.node,
      });
      addMergeCandidate('budget-exceeded', frame.nodes, path.id);
      continue;
    }

    dfsStack.push({
      node: edge.to,
      next: 0,
      nodes: [...frame.nodes, edge.to],
      edgeTrail: [...frame.edgeTrail, edge],
      jumps: frame.jumps + 1,
      onStack: new Set(frame.onStack).add(edge.to),
    });
  }

  for (const component of cycles) {
    addMergeCandidate('recursion-cycle', component, null);
  }

  const legalPaths = paths.filter((path) => path.status === 'legal');
  const dangerousPaths = paths.filter((path) => path.status === 'dangerous');

  return {
    entry,
    budget,
    legalPaths,
    dangerousPaths,
    maxDepth,
    dangerousEdges: dangerousStore.list(),
    recursion: {
      hasCycle: cycles.length > 0,
      cycles,
      selfLoops,
    },
    mergeCandidates,
    unreachablePrograms: programs.map((program) => program.id).filter((id) => !reachable.has(id)),
    warnings,
  };
}

export default validateXdpGraph;
