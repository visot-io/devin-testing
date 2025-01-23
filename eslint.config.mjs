import globals from 'globals';
import * as parser from '@typescript-eslint/parser';
import * as plugin from '@typescript-eslint/eslint-plugin';

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ['**/*.{js,mjs,cjs,ts}'],
    languageOptions: {
      globals: {
        ...globals.node,
        require: true,
        process: true
      },
      parser: parser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': plugin,
    },
    rules: {
      ...plugin.configs.recommended.rules,
      "@typescript-eslint/no-require-imports": "off"  // Allow require in JS files
    },
  },
];
