module.exports = {
  testEnvironment: "jest-environment-jsdom",
  setupFilesAfterEnv: ["<rootDir>/src/setupTests.js"],
  globals: {
    crypto: true,
    "ts-jest": {
      useESM: true,
    },
  },
  // Enable experimental ESM support for WASM modules
  extensionsToTreatAsEsm: [".ts", ".tsx"],
  moduleNameMapper: {
    "\\.(css|less|scss)$": "identity-obj-proxy",
    // MLS mock used because ts-mls is an ES module incompatible with Jest
    // Real implementation is tested in Storybook (browser environment)
    "^.*/crypto/MLS/MLSManager\\.tsx$":
      "<rootDir>/src/__mocks__/crypto/MLS/MLSManager.tsx",
    "^.*/crypto/SFrame/SFrameManager\\.tsx$":
      "<rootDir>/src/__mocks__/crypto/SFrame/SFrameManager.tsx",
    // WASM files should not be mocked - they are a key output of this repo
  },
  collectCoverage: true,
  coverageReporters: ["lcov", "text"],
  transform: {
    "^.+\\.(ts|tsx|js|jsx)$": "babel-jest",
  },
  testPathIgnorePatterns: [
    "/node_modules/",
    "/Frontend/",
    "/hax/",
    "/hax-upstream/",
    "src/tests/mls-protocol.test.js", // Requires ts-mls ES modules
    "src/tests/signal-protocol-javascript.test.js", // Missing Cryptography component - TODO: fix or create component
    "src/tests/wasm-wrappers-coverage.test.js", // WASM tests - use 'npm run test:wasm:wrappers' instead
  ],
  collectCoverageFrom: [
    "src/**/*.{js,jsx,ts,tsx}",
    "!src/**/*.stories.{js,jsx,ts,tsx}",
    "!src/**/*.test.{js,jsx,ts,tsx}",
    "!src/setupTests.js",
    "!src/index.ts",
    "src/tests/wasm-test-loader.js",
    // Include WASM bindings for coverage
    "src/wasm-bindings.js",
    // Note: MLS/SFrame real implementations are excluded from Jest coverage
    // because they use Web Crypto API and ES modules incompatible with Jest.
    // Real implementations are tested in Storybook (browser environment).
    // Jest tests use mocks from src/__mocks__/ which verify API contracts.
    "!src/crypto/MLS/**",
    "!src/crypto/SFrame/**",
  ],
  // Configure module handling for WASM and ES modules
  // Exclude WASM module from transformation - it's an ES module that should be imported dynamically
  transformIgnorePatterns: [
    "/pkg/", // Don't transform anything in pkg directory - WASM modules are ES modules
    "node_modules/(?!(@?(?:signal_protocol_wasm|pkg|ts-mls|hpke|noble|mlkem)))",
    "Frontend/pkg/(?!.*\\.js$)",
  ],
  // Increase timeout for WASM compilation tests
  testTimeout: 60000,
};
