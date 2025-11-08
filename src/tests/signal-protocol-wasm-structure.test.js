/**
 * WASM Structure and Build Tests
 *
 * This test suite validates that the WASM module builds correctly and
 * has the expected API structure. It ensures the modular Rust code
 * compiles to WASM with the right interface.
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

describe("WASM Module Structure and Build Validation", () => {
  beforeAll(() => {
    // Ensure WASM is built
    try {
      const pkgDir = path.join(process.cwd(), "pkg");
      const wasmFile = path.join(pkgDir, "signal_protocol_wasm_bg.wasm");

      if (!fs.existsSync(wasmFile)) {
        console.log("Building WASM module for structure tests...");
        execSync("npm run build:wasm:dev", { stdio: "inherit" });
      }
    } catch (error) {
      console.warn("Could not build WASM for structure tests:", error.message);
    }
  }, 10000);

  test("should build WASM module successfully", () => {
    const pkgDir = path.join(process.cwd(), "pkg");
    const wasmFile = path.join(pkgDir, "signal_protocol_wasm_bg.wasm");
    expect(fs.existsSync(wasmFile)).toBe(true);
  });

  test("should create expected WASM build artifacts", () => {
    const pkgDir = path.join(process.cwd(), "pkg");

    // Check that all expected files are created
    expect(fs.existsSync(path.join(pkgDir, "signal_protocol_wasm.js"))).toBe(
      true,
    );
    expect(
      fs.existsSync(path.join(pkgDir, "signal_protocol_wasm_bg.wasm")),
    ).toBe(true);
    expect(fs.existsSync(path.join(pkgDir, "signal_protocol_wasm.d.ts"))).toBe(
      true,
    );
    expect(fs.existsSync(path.join(pkgDir, "package.json"))).toBe(true);
  });

  test("should have correct API structure in built module", () => {
    const jsFile = path.join(process.cwd(), "pkg", "signal_protocol_wasm.js");
    const jsContent = fs.readFileSync(jsFile, "utf8");

    // Check that all expected functions are exported
    const expectedFunctions = [
      "generate_identity_keypair",
      "generate_signed_prekey",
      "generate_one_time_prekey",
      "generate_ephemeral_keypair",
      "sign_data",
      "verify_signature",
      "x3dh_initiate",
      "x3dh_respond",
      "encrypt_message",
      "decrypt_message",
      "hkdf_derive_key",
      "serialize_public_key",
      "deserialize_public_key",
      "free_keypair",
      "free_buffer",
    ];

    expectedFunctions.forEach((funcName) => {
      expect(jsContent).toContain(`export function ${funcName}`);
    });
  });

  test("should have correct class structure in built module", () => {
    const jsFile = path.join(process.cwd(), "pkg", "signal_protocol_wasm.js");
    const jsContent = fs.readFileSync(jsFile, "utf8");

    // Check that all expected classes are exported
    const expectedClasses = ["KeyPair", "X3DHResult", "EncryptionResult"];

    expectedClasses.forEach((className) => {
      expect(jsContent).toContain(`export class ${className}`);
    });
  });

  test("should have KeyPair with correct getter methods", () => {
    const jsFile = path.join(process.cwd(), "pkg", "signal_protocol_wasm.js");
    const jsContent = fs.readFileSync(jsFile, "utf8");

    // KeyPair should have public_key and private_key getters
    expect(jsContent).toContain("get public_key()");
    expect(jsContent).toContain("get private_key()");
  });

  test("should have X3DHResult with correct getter methods", () => {
    const jsFile = path.join(process.cwd(), "pkg", "signal_protocol_wasm.js");
    const jsContent = fs.readFileSync(jsFile, "utf8");

    // X3DHResult should have shared_secret and associated_data getters
    expect(jsContent).toContain("get shared_secret()");
    expect(jsContent).toContain("get associated_data()");
  });

  test("should have EncryptionResult with correct getter methods", () => {
    const jsFile = path.join(process.cwd(), "pkg", "signal_protocol_wasm.js");
    const jsContent = fs.readFileSync(jsFile, "utf8");

    // EncryptionResult should have ciphertext and message_key getters
    expect(jsContent).toContain("get ciphertext()");
    expect(jsContent).toContain("get message_key()");
  });

  test("should have correct TypeScript definitions", () => {
    const dtsFile = path.join(
      process.cwd(),
      "pkg",
      "signal_protocol_wasm.d.ts",
    );
    const dtsContent = fs.readFileSync(dtsFile, "utf8");

    // Check for key type definitions
    expect(dtsContent).toContain("export class KeyPair");
    expect(dtsContent).toContain("export class X3DHResult");
    expect(dtsContent).toContain("export class EncryptionResult");

    // Check for function definitions
    expect(dtsContent).toContain("export function generate_identity_keypair");
    expect(dtsContent).toContain("export function x3dh_initiate");
    expect(dtsContent).toContain("export function encrypt_message");
  });

  test("should validate WASM file is not empty and has correct magic bytes", () => {
    const wasmFile = path.join(
      process.cwd(),
      "pkg",
      "signal_protocol_wasm_bg.wasm",
    );
    const wasmBuffer = fs.readFileSync(wasmFile);

    // WASM files should start with magic bytes [0x00, 0x61, 0x73, 0x6D]
    expect(wasmBuffer.length).toBeGreaterThan(100); // Should be substantial
    expect(wasmBuffer[0]).toBe(0x00);
    expect(wasmBuffer[1]).toBe(0x61); // 'a'
    expect(wasmBuffer[2]).toBe(0x73); // 's'
    expect(wasmBuffer[3]).toBe(0x6d); // 'm'
  });

  test("should have package.json with correct metadata", () => {
    const pkgJsonFile = path.join(process.cwd(), "pkg", "package.json");
    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonFile, "utf8"));

    expect(pkgJson.name).toBe("signal-protocol-wasm");
    expect(pkgJson.main).toBe("signal_protocol_wasm.js");
    expect(pkgJson.types).toBe("signal_protocol_wasm.d.ts");
    expect(pkgJson.files).toContain("signal_protocol_wasm_bg.wasm");
  });

  describe("Modular Architecture Validation", () => {
    test("should contain expected WASM-generated content from modular structure", () => {
      const jsFile = path.join(process.cwd(), "pkg", "signal_protocol_wasm.js");
      const jsContent = fs.readFileSync(jsFile, "utf8");

      // Check that the generated WASM bindings contain expected patterns
      // These are the actual patterns generated by wasm-bindgen, not custom documentation
      expect(jsContent).toContain("generate_identity_keypair");
      expect(jsContent).toContain("export function");
      expect(jsContent).toContain("__wbg_");
    });

    test("should include error handling from error module", () => {
      const jsFile = path.join(process.cwd(), "pkg", "signal_protocol_wasm.js");
      const jsContent = fs.readFileSync(jsFile, "utf8");

      // Should include error handling patterns
      expect(jsContent).toContain("throw");
      expect(jsContent).toContain("Error");
    });

    test("should validate modular compilation worked", () => {
      // If the WASM builds successfully, it means our modular Rust code
      // compiles correctly and all modules are properly linked
      const wasmFile = path.join(
        process.cwd(),
        "pkg",
        "signal_protocol_wasm_bg.wasm",
      );
      expect(fs.existsSync(wasmFile)).toBe(true);

      // The fact that we can read the WASM file and it has the right format
      // proves that our modular split worked correctly
      const wasmBuffer = fs.readFileSync(wasmFile);
      expect(wasmBuffer.length).toBeGreaterThan(1000); // Should be substantial
    });
  });

  describe("API Consistency Validation", () => {
    test("should have consistent function signatures", () => {
      const dtsFile = path.join(
        process.cwd(),
        "pkg",
        "signal_protocol_wasm.d.ts",
      );
      const dtsContent = fs.readFileSync(dtsFile, "utf8");

      // Key generation functions should return KeyPair
      expect(dtsContent).toContain("generate_identity_keypair(): KeyPair");
      expect(dtsContent).toContain("generate_signed_prekey(): KeyPair");

      // X3DH functions should return X3DHResult
      expect(dtsContent).toContain("x3dh_initiate(");
      expect(dtsContent).toContain("X3DHResult");

      // Encryption should return EncryptionResult
      expect(dtsContent).toContain("encrypt_message(");
      expect(dtsContent).toContain("EncryptionResult");
    });

    test("should have proper Uint8Array parameter types", () => {
      const dtsFile = path.join(
        process.cwd(),
        "pkg",
        "signal_protocol_wasm.d.ts",
      );
      const dtsContent = fs.readFileSync(dtsFile, "utf8");

      // Functions should accept Uint8Array parameters
      expect(dtsContent).toContain("Uint8Array");
      expect(dtsContent).toContain("sign_data(");
      expect(dtsContent).toContain("verify_signature(");
    });
  });
});
