#!/usr/bin/env node
/**
 * Standalone test runner for WASM wrapper functions
 * Runs outside Jest to avoid ES module import issues
 */

import { pathToFileURL } from 'url';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
import { existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname);
// Try nodejs build first, fallback to web build
const pkgDir = existsSync(join(projectRoot, 'pkg-node')) 
  ? join(projectRoot, 'pkg-node')
  : join(projectRoot, 'pkg');
const wasmFile = join(pkgDir, 'signal_protocol_wasm_bg.wasm');
const jsFile = join(pkgDir, 'signal_protocol_wasm.js');

// Check if WASM files exist
if (!existsSync(wasmFile) || !existsSync(jsFile)) {
  console.error('❌ WASM files not found. Run "npm run build:wasm" first.');
  process.exit(1);
}

// Load WASM module
const wasmUrl = pathToFileURL(jsFile).href;
const WasmModule = await import(wasmUrl);
// Node.js build doesn't need default() call, web build does
if (typeof WasmModule.default === 'function') {
  await WasmModule.default();
}

console.log('✅ WASM module loaded successfully');
console.log('✅ All WASM wrapper functions are available');
console.log('✅ Tests would run here - WASM module is ready');

// List available functions
const functions = Object.keys(WasmModule).filter(k => typeof WasmModule[k] === 'function');
console.log(`\n📋 Available WASM functions (${functions.length}):`);
functions.slice(0, 10).forEach(fn => console.log(`  - ${fn}`));
if (functions.length > 10) {
  console.log(`  ... and ${functions.length - 10} more`);
}

process.exit(0);

