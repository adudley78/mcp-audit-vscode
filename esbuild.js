// @ts-check
const esbuild = require('esbuild');

const production = process.argv.includes('--production');
const watch = process.argv.includes('--watch');

/** @type {import('esbuild').BuildOptions} */
const buildOptions = {
  entryPoints: ['src/extension.ts'],
  bundle: true,
  outfile: 'dist/extension.js',
  external: ['vscode'],
  format: 'cjs',
  platform: 'node',
  target: 'node18',
  sourcemap: !production,
  minify: production,
  // prefer ESM builds so jsonc-parser is fully inlined (its UMD main
  // leaves a dynamic require('./impl/format') esbuild can't follow)
  mainFields: ['module', 'main'],
};

async function main() {
  if (watch) {
    const ctx = await esbuild.context(buildOptions);
    await ctx.watch();
    console.log('[esbuild] watching...');
  } else {
    await esbuild.build(buildOptions);
    console.log(
      `[esbuild] build complete (${production ? 'production' : 'development'})`
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
