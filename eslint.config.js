module.exports = [
  {
    ignores: ['node_modules/**', 'web/data/**', 'output/**', 'logs/**']
  },
  {
    files: ['src/**/*.js', 'tests/**/*.js', 'web/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs'
    },
    rules: {}
  }
];
