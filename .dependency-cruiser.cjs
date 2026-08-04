/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    {
      name: 'no-circular-dependencies',
      severity: 'error',
      comment: 'Circular dependencies make module extraction and boot ordering unsafe.',
      from: {},
      to: { circular: true },
    },
    {
      name: 'no-cross-module-deep-imports',
      severity: 'error',
      comment: 'Direct deep imports between different NestJS modules are forbidden. Use common interfaces or event boundaries.',
      from: {
        path: '^src/modules/([^/]+)',
        pathNot: '(^src/modules/ecommerce/|^src/modules/outbox/|\\.spec\\.ts$|/tests/)'
      },
      to: {
        path: '^src/modules/([^/]+)',
        pathNot: '(^src/modules/$1|^src/modules/outbox/)'
      }
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    tsConfig: { fileName: 'tsconfig.json' },
  },
};
