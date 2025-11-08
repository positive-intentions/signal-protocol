"use strict";
/*
 * ATTENTION: The "eval" devtool has been used (maybe by default in mode: "development").
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
(self["webpackChunksignal_protocol"] = self["webpackChunksignal_protocol"] || []).push([["src_stories_components_SignalProtocolDemo_tsx-webpack_sharing_consume_default_react-dom_react-dom"],{

/***/ "./src/stories/components/SignalProtocolDemo.tsx":
/*!*******************************************************!*\
  !*** ./src/stories/components/SignalProtocolDemo.tsx ***!
  \*******************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

eval("{\n\nObject.defineProperty(exports, \"__esModule\", ({\n  value: true\n}));\nexports[\"default\"] = void 0;\nvar _react = _interopRequireDefault(__webpack_require__(/*! react */ \"webpack/sharing/consume/default/react/react\"));\nvar _material = __webpack_require__(/*! @mui/material */ \"./node_modules/@mui/material/index.js\");\nvar _Security = _interopRequireDefault(__webpack_require__(/*! @mui/icons-material/Security */ \"./node_modules/@mui/icons-material/Security.js\"));\nfunction _interopRequireDefault(e) { return e && e.__esModule ? e : { \"default\": e }; }\n/**\n * Simple Signal Protocol demo component for bootstrap entry point\n * Used for module federation\n */\nvar SignalProtocolDemo = function SignalProtocolDemo(_ref) {\n  var children = _ref.children;\n  return /*#__PURE__*/_react[\"default\"].createElement(_material.Card, {\n    sx: {\n      maxWidth: 800,\n      mx: \"auto\",\n      mt: 4,\n      p: 2\n    }\n  }, /*#__PURE__*/_react[\"default\"].createElement(_material.CardContent, null, /*#__PURE__*/_react[\"default\"].createElement(_material.Box, {\n    sx: {\n      display: \"flex\",\n      alignItems: \"center\",\n      mb: 2\n    }\n  }, /*#__PURE__*/_react[\"default\"].createElement(_Security[\"default\"], {\n    sx: {\n      mr: 1\n    }\n  }), /*#__PURE__*/_react[\"default\"].createElement(_material.Typography, {\n    variant: \"h5\",\n    component: \"h2\"\n  }, \"Signal Protocol WASM\")), /*#__PURE__*/_react[\"default\"].createElement(_material.Typography, {\n    variant: \"body1\",\n    paragraph: true\n  }, \"Signal Protocol implementation in Rust compiled to WebAssembly.\"), children && /*#__PURE__*/_react[\"default\"].createElement(_material.Box, {\n    sx: {\n      mt: 2\n    }\n  }, children)));\n};\nvar _default = exports[\"default\"] = SignalProtocolDemo;\n\n//# sourceURL=webpack://signal-protocol/./src/stories/components/SignalProtocolDemo.tsx?\n}");

/***/ })

}]);