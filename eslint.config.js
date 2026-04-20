/**
 * Canonical ESLint config — used by both local dev (`npx eslint .`) and CI.
 *
 * Previously this lived in two places (tests/eslint.config.js + an inline
 * heredoc in .github/workflows/ci.yml) which silently drifted. Some rules
 * were active in CI only, so developers running lint locally saw a false
 * "all clean" signal for rules that would fail CI. This single file is the
 * source of truth.
 *
 * When editing: every rule here runs in CI. If a rule produces false
 * positives for the codebase, turn it off here — don't add per-line
 * disable-comments.
 */
var security = require("eslint-plugin-security");

module.exports = [
  {
    ignores: [
      "node_modules/**",
      "tests/**",
      "public/js/**",
      "lib/vendor/**",
      "template/**",
      "scripts/**",
      "deploy/**",
    ],
  },
  {
    files: ["**/*.js"],
    plugins: { security: security },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        require: "readonly",
        module: "readonly",
        exports: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        setInterval: "readonly",
        setImmediate: "readonly",
        clearTimeout: "readonly",
        clearInterval: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        global: "readonly",
        crypto: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
      },
    },
    rules: {
      // Promoted to error: these accumulated silently across two refactor
      // passes (v1.8.14 auth-gate consolidation, v1.8.15 resolveLocalPath
      // extraction) because "warn" only surfaced as CI annotations that
      // noone bounced on. Prefix intentionally unused vars with `_` to
      // skip the check (argsIgnorePattern + caughtErrorsIgnorePattern).
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" }],
      "no-console": "off",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-self-compare": "error",
      "no-constructor-return": "error",
      "no-new-wrappers": "error",
      "no-throw-literal": "error",

      "security/detect-eval-with-expression": "error",
      "security/detect-child-process": "warn",
      "security/detect-unsafe-regex": "error",
      "security/detect-buffer-noassert": "error",
      "security/detect-new-buffer": "error",
      "security/detect-possible-timing-attacks": "warn",
      "security/detect-pseudoRandomBytes": "warn",
      "security/detect-object-injection": "off",
      "security/detect-non-literal-fs-filename": "off",
      "security/detect-non-literal-require": "off",
      "security/detect-non-literal-regexp": "off",
    },
  },
];
