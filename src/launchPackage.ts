/**
 * Find the package that a server entry installs when it starts.
 *
 * `credenzo vet` takes a package name, not the server key of a config file.
 * This module reads `command` and `args` and gives the package for the launch
 * shapes that it can read with certainty. It follows `launch_package` in
 * `src/mcp_audit/analyzers/supply_chain.py` of Credenzo.
 *
 * Rule: this module can decline (return null), but it must never give a
 * package that Credenzo does not give. The contract test
 * (`scripts/contract-test.mjs`) compares both on a table of launch commands.
 *
 * No `vscode` import: the contract test runs this file in plain Node.
 */

export interface LaunchPackage {
  ecosystem: 'npm' | 'pypi';
  /** Bare name: lowercase for npm, PEP 503 form for PyPI. */
  name: string;
  /** An exact version when the entry pins one, else null. */
  version: string | null;
}

const LAUNCHER_SUFFIXES = ['.cmd', '.exe', '.bat', '.ps1'];
const NPX_LIKE = new Set(['npx', 'bunx', 'pnpx']);

/** npx flags that change which package runs. The module declines on them. */
const NPX_DECLINE = new Set(['-p', '--package', '-c', '--call']);

/** uvx / pipx flags whose next argument is a value, not a package. */
const UVX_FLAGS_WITH_VALUE = new Set([
  '--python',
  '--with',
  '--index-url',
  '--extra-index-url',
  '--default-index',
  '--override-index',
]);

const PIPX_SUBCOMMANDS = new Set([
  'run',
  'install',
  'inject',
  'upgrade',
  'upgrade-all',
  'uninstall',
]);

const NPM_NAME_RE = /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/;
const NPM_EXACT_VERSION_RE =
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PYPI_NAME_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const PYPI_EXACT_VERSION_RE = /^\d+(?:\.\d+)*(?:[a-z0-9.+!-]*[a-z0-9])?$/i;
const PYPI_NAME_END_RE = /[=<>!~;[@\s]/;

const MAX_ARGS = 64;
const MAX_ARG_LENGTH = 512;

/** `/usr/local/bin/npx`, `C:\nodejs\npx.cmd` and `NPX.CMD` all give `npx`. */
function launcherBasename(command: string): string {
  const trimmed = command.trim();
  const afterSlash = trimmed.slice(trimmed.lastIndexOf('/') + 1);
  const base = afterSlash.slice(afterSlash.lastIndexOf('\\') + 1).toLowerCase();
  for (const suffix of LAUNCHER_SUFFIXES) {
    if (base.endsWith(suffix) && base.length > suffix.length) {
      return base.slice(0, -suffix.length);
    }
  }
  return base;
}

function npmPackage(args: string[]): LaunchPackage | null {
  let token: string | null = null;
  for (const arg of args) {
    if (NPX_DECLINE.has(arg) || arg.startsWith('--package=') || arg.startsWith('--call=')) {
      return null;
    }
    if (arg.startsWith('-')) continue;
    // The first argument that is not a flag is what npx runs. A path or a URL
    // is not a registry package.
    token = arg;
    break;
  }
  if (token === null || token === '') return null;
  if (/^(\/|\.|https?:\/\/|file:)/.test(token)) return null;

  const lowered = token.toLowerCase();
  // The version is after the second "@" of a scoped name, after the first of
  // an unscoped name.
  const at = lowered.lastIndexOf('@');
  const hasVersion = lowered.startsWith('@')
    ? at > lowered.indexOf('/') && lowered.includes('/')
    : at > 0;
  const name = hasVersion ? lowered.slice(0, at) : lowered;
  // Not lowercase: a version can have capital letters (1.0.0-RC1).
  const suffix = hasVersion ? token.slice(at + 1) : '';
  if (!NPM_NAME_RE.test(name)) return null;
  return {
    ecosystem: 'npm',
    name,
    version: NPM_EXACT_VERSION_RE.test(suffix) ? suffix : null,
  };
}

function pypiToken(token: string): LaunchPackage | null {
  const end = token.search(PYPI_NAME_END_RE);
  const rawName = end === -1 ? token : token.slice(0, end);
  const name = rawName.replace(/[-_.]+/g, '-').toLowerCase();
  if (!PYPI_NAME_RE.test(name)) return null;

  let version: string | null = null;
  if (end !== -1) {
    const rest = token.slice(end);
    const pinned = rest.startsWith('==')
      ? rest.slice(2)
      : rest.startsWith('@')
        ? rest.slice(1)
        : '';
    if (pinned && PYPI_EXACT_VERSION_RE.test(pinned)) version = pinned;
  }
  return { ecosystem: 'pypi', name, version };
}

function pypiPackage(launcher: string, args: string[]): LaunchPackage | null {
  let effective = args;
  if (launcher === 'pipx') {
    if (args.length > 0 && PIPX_SUBCOMMANDS.has(args[0])) effective = args.slice(1);
  }

  // `--from <pkg> <executable>` names the package.
  for (let i = 0; i < effective.length; i++) {
    if ((effective[i] === '--from' || effective[i] === '-f') && i + 1 < effective.length) {
      return pypiToken(effective[i + 1]);
    }
    if (effective[i].startsWith('--from=')) return null;
  }

  let skipNext = false;
  for (const arg of effective) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (UVX_FLAGS_WITH_VALUE.has(arg)) {
      skipNext = true;
      continue;
    }
    if (arg.startsWith('-')) continue;
    if (/^(\/|\.|https?:\/\/|file:|git\+)/.test(arg)) return null;
    return pypiToken(arg);
  }
  return null;
}

/**
 * Give the package that `command` + `args` install, or null when this module
 * can not read the launch with certainty (a `cmd /c` wrapper, `python -m`, a
 * local path, a URL, `npx -p`, a value that is not a string).
 */
export function launchPackage(command: unknown, args: unknown): LaunchPackage | null {
  if (typeof command !== 'string' || command.length > MAX_ARG_LENGTH) return null;
  const list = args === undefined || args === null ? [] : args;
  if (!Array.isArray(list) || list.length > MAX_ARGS) return null;
  for (const item of list) {
    if (typeof item !== 'string' || item.length > MAX_ARG_LENGTH) return null;
  }
  let rest = list as string[];

  let launcher = launcherBasename(command);
  if (launcher === 'yarn') {
    if (rest.length === 0 || rest[0] !== 'dlx') return null;
    launcher = 'npx';
    rest = rest.slice(1);
  }
  if (NPX_LIKE.has(launcher)) return npmPackage(rest);
  if (launcher === 'uvx' || launcher === 'pipx') return pypiPackage(launcher, rest);
  return null;
}

/** The argument for `credenzo vet`: `name`, `name@1.2.3` (npm) or `name==1.2.3` (PyPI). */
export function vetSpec(pkg: LaunchPackage): string {
  if (pkg.version === null) return pkg.name;
  return pkg.ecosystem === 'npm' ? `${pkg.name}@${pkg.version}` : `${pkg.name}==${pkg.version}`;
}

/** The key of one package in the session cache. */
export function packageKey(pkg: LaunchPackage): string {
  return `${pkg.ecosystem}:${vetSpec(pkg)}`;
}
