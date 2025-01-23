import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";


/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ["**/*.{js,mjs,cjs,ts}"],
    languageOptions: {
      globals: {
        ...globals.node,  // Add Node.js globals
        require: true,    // Allow require
        process: true     // Allow process
      }
    }
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.js"],  // Only for JavaScript files
    rules: {
      "@typescript-eslint/no-require-imports": "off"  // Allow require in JS files
    }
  }
];
