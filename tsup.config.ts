// Build config — esbuild via tsup, matching the billing-kit family.
//
// tsc cannot emit this source: it imports with explicit `.ts` extensions, which
// tsc only accepts under `allowImportingTsExtensions` + `noEmit`. esbuild
// rewrites those specifiers to the emitted files, so the style is fine in src/.
import { defineConfig, type Options } from 'tsup';

const shared: Options = {
  sourcemap: true,
  splitting: false,
  bundle: true,
  // @node-rs/argon2 is a native module; keep it external, and pg is an optional
  // peer loaded by the host. Neither is bundled.
  external: ['pg', '@node-rs/argon2'],
  skipNodeModulesBundle: true,
  target: 'es2022',
  platform: 'node',
  removeNodeProtocol: false,
  outExtension: ({ format }) => ({ js: format === 'esm' ? '.mjs' : '.cjs' }),
};

export default defineConfig([
  {
    ...shared,
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
  },
]);
