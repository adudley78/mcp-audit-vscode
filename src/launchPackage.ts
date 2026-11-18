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

/**
 * The only npx flags that the module reads past. Each other flag declines:
 * it can take a value (`--node-options x`) or change which package runs
 * (`-p`, `--package`, `-c`).
 */
const NPX_PLAIN_FLAGS = new Set(['-y', '--yes', '-q', '--quiet']);

/** uvx / pipx flags with no value that the module reads past. */
const UVX_PLAIN_FLAGS = new Set(['-q', '--quiet', '--offline', '--no-cache', '--isolated']);

/**
 * uvx flags whose next argument is a value. Each other flag declines: `-p`
 * takes a value, and an index flag means that the public registry name can be
 * a different package.
 */
const UVX_FLAGS_WITH_VALUE = new Set(['--python', '--with']);

const NPM_NAME_RE = /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/;
const NPM_EXACT_VERSION_RE =
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PYPI_NAME_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const PYPI_EXACT_VERSION_RE = /^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*$/;
const PYPI_NAME_END_RE = /[=<>!~;[@]/;

/** Printable ASCII with no space and no control character. Each other text declines. */
const PLAIN_ASCII_RE = /^[\x21-\x7e]+$/;

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
    if (arg.startsWith('-')) {
      if (!NPX_PLAIN_FLAGS.has(arg)) return null;
      continue;
    }
    // The first argument that is not a flag is what npx runs. A path or a URL
    // is not a registry package.
    token = arg;
    break;
  }
  if (token === null || !PLAIN_ASCII_RE.test(token)) return null;
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
  if (!PLAIN_ASCII_RE.test(token)) return null;
  const end = token.search(PYPI_NAME_END_RE);
  const rawName = end === -1 ? token : token.slice(0, end);
  const name = rawName.replace(/[-_.]+/g, '-').toLowerCase();
  if (!PYPI_NAME_RE.test(name)) return null;

  let version: string | null = null;
  if (end !== -1) {
    // `pkg==1.2`, `pkg@1.2`, and the same after extras: `pkg[cli]==1.2`.
    const m = /^(?:\[[A-Za-z0-9,._-]*\])?(?:==|@)(.+)$/.exec(token.slice(end));
    if (m && PYPI_EXACT_VERSION_RE.test(m[1])) version = m[1];
  }
  return { ecosystem: 'pypi', name, version };
}

function pypiPackage(launcher: string, args: string[]): LaunchPackage | null {
  let effective = args;
  if (launcher === 'pipx') {
    // Only `pipx run <pkg>` starts a package from the registry.
    if (args.length === 0 || args[0] !== 'run') return null;
    effective = args.slice(1);
  }

  // Credenzo looks for `--from` / `-f` at each position before it reads
  // anything else. This module reads one `--from` in the launcher options,
  // and declines when a second one, or one in a different place, exists.
  const fromCount = effective.filter((a) => a === '--from' || a === '-f').length;
  if (fromCount > 1) return null;

  let fromToken: string | null = null;
  let positional: string | null = null;
  for (let i = 0; i < effective.length; i++) {
    const arg = effective[i];
    if (arg === '--from') {
      // `--from <pkg> <executable>` names the package.
      if (fromToken !== null || i + 1 >= effective.length) return null;
      fromToken = effective[i + 1];
      i += 1;
      continue;
    }
    if (UVX_FLAGS_WITH_VALUE.has(arg)) {
      // A value that looks like a flag: the two programs can read it in two ways.
      if (i + 1 >= effective.length || effective[i + 1].startsWith('-')) return null;
      i += 1;
      continue;
    }
    if (arg.startsWith('-')) {
      if (!UVX_PLAIN_FLAGS.has(arg)) return null;
      continue;
    }
    // The arguments after the program belong to the server.
    positional = arg;
    break;
  }

  // Each `--from` / `-f` that exists must be the one that was read above.
  if (fromCount !== (fromToken === null ? 0 : 1)) return null;
  const token = fromToken ?? positional;
  if (token === null || token.startsWith('-')) return null;
  if (/^(\/|\.|https?:\/\/|file:|git\+)/.test(token)) return null;
  return pypiToken(token);
}

/**
 * Give the package that `command` + `args` install, or null when this module
 * can not read the launch with certainty (a `cmd /c` wrapper, `python -m`, a
 * local path, a URL, a flag that it does not know, text that is not plain
 * ASCII, a value that is not a string).
 */
export function launchPackage(command: unknown, args: unknown): LaunchPackage | null {
  if (typeof command !== 'string' || command.length > MAX_ARG_LENGTH) return null;
  const list = args === undefined || args === null ? [] : args;
  if (!Array.isArray(list) || list.length > MAX_ARGS) return null;
  for (const item of list) {
    if (typeof item !== 'string' || item.length > MAX_ARG_LENGTH) return null;
  }
  let rest = list as string[];

  // Text that is not printable ASCII (a space in the command, a zero-width
  // character, a letter from a different script) declines: two programs can
  // read such text in two ways. A command path with a space gets no badge.
  if (!PLAIN_ASCII_RE.test(command)) return null;

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
