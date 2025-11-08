// WASM module loader that can be used outside Jest's module system
import { pathToFileURL } from 'url';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const wasmPath = join(__dirname, '../../pkg/signal_protocol_wasm.js');
const wasmUrl = pathToFileURL(wasmPath).href;

export async function loadWasm() {
  const module = await import(wasmUrl);
  await module.default();
  return module;
}
