#!/usr/bin/env node
// 用法: node bin/xdp-validator.js <输入 JSON 路径>
// 纯静态分析：不加载、不挂载任何 eBPF/XDP 程序。

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { validateXdpGraph } from '../src/validator.js';

const inputPath = process.argv[2];
if (!inputPath) {
  console.error('用法: node bin/xdp-validator.js <输入 JSON 路径>');
  process.exit(2);
}

let input;
try {
  input = JSON.parse(readFileSync(resolve(inputPath), 'utf8'));
} catch (error) {
  console.error(`无法读取输入文件: ${error.message}`);
  process.exit(2);
}

try {
  const report = validateXdpGraph(input);
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.dangerousPaths.length > 0 ? 1 : 0);
} catch (error) {
  console.error(`验证失败: ${error.message}`);
  process.exit(2);
}
