// 用 uv 的隔离环境和缓存承担 Python 下载、依赖解析与多进程锁，避免自造安装器。
import {spawn} from 'node:child_process';
import {createHash, randomUUID} from 'node:crypto';
import {readFile, writeFile, mkdir, mkdtemp, rename, rm, chmod, stat, readdir} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const packageRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(await readFile(new URL('./uv-artifacts.json', import.meta.url), 'utf8'));
const probe = "import sys,json,importlib.metadata as m; import bashlex,send2trash; "
  + "assert sys.version_info >= (3,10); assert m.version('bashlex') == '0.18'; "
  + "exec('from win32com.shell import shell' if sys.platform == 'win32' else ''); print(json.dumps(sys.executable))";

// PyPI 有稳定的国内镜像；按顺序尝试，全部失败才回退到官方源。
// uv 本体和托管 Python 仍从 GitHub 官方发布下载，避免使用无法验证来源的第三方代理。
export const DEFAULT_PYPI_INDEXES = Object.freeze([
  'https://pypi.tuna.tsinghua.edu.cn/simple',
  'https://mirrors.aliyun.com/pypi/simple',
  'https://mirrors.cloud.tencent.com/pypi/simple',
  'https://pypi.org/simple',
]);

function validHttpsUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password;
  } catch { return false; }
}

export function pypiIndexes(config = {}, env = process.env) {
  const configured = config.pypiIndex ?? env.AGENT_RECYCLE_GUARD_PYPI_INDEX;
  if (configured !== undefined && (!validHttpsUrl(configured) || !configured.replace(/\/$/, '').endsWith('/simple'))) {
    throw new Error('PyPI 镜像必须是 HTTPS 的 simple 索引地址。');
  }
  return [...new Set([configured, ...DEFAULT_PYPI_INDEXES].filter(Boolean).map(value => value.replace(/\/$/, '')))];
}

export function selectArtifact(platform = process.platform, arch = process.arch, musl = false) {
  const cpu = {x64: 'x86_64', arm64: 'aarch64'}[arch];
  const target = {win32: 'pc-windows-msvc', darwin: 'apple-darwin', linux: 'unknown-linux-' + (musl ? 'musl' : 'gnu')}[platform];
  const name = `uv-${cpu}-${target}.${platform === 'win32' ? 'zip' : 'tar.gz'}`;
  if (!manifest.sha256[name]) throw new Error('自动运行环境暂不支持此平台或架构。');
  return {name, sha256: manifest.sha256[name], version: manifest.version,
    entry: platform === 'win32' ? 'uv.exe' : `uv-${cpu}-${target}/uv`};
}

export async function checkedDownload(url, expected, fetcher = fetch) {
  const response = await fetcher(url, {signal: AbortSignal.timeout(120000)});
  if (!response.ok) throw new Error(`下载运行环境失败（HTTP ${response.status}）。`);
  const limit = 64 * 1024 * 1024;
  if (Number(response.headers.get('content-length')) > limit) throw new Error('运行环境下载超过大小上限。');
  const chunks = [];
  let length = 0;
  for await (const value of response.body) {
    length += value.length;
    if (length > limit) throw new Error('运行环境下载超过大小上限。');
    chunks.push(Buffer.from(value));
  }
  const bytes = Buffer.concat(chunks);
  if (createHash('sha256').update(bytes).digest('hex') !== expected) throw new Error('运行环境校验失败，已停止安装。');
  return bytes;
}

export function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], ...options});
    let output = '', errorOutput = '', failure;
  const timer = setTimeout(() => {failure = new Error('自动准备运行环境超时，请检查网络后重试。' + errorOutput.trim()); child.kill();}, options.timeout ?? 900000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', value => {
      output += value;
      if (output.length > 262144) {failure = new Error('运行环境返回内容超过上限。'); child.kill();}
    });
    // 只保留有限诊断文本，避免安装器输出无限累积。
    child.stderr.on('data', value => {errorOutput = (errorOutput + value).slice(-4096);});
    child.on('error', error => {clearTimeout(timer); reject(error);});
    child.on('close', code => {
      clearTimeout(timer);
      if (failure) reject(failure);
      else if (code !== 0) reject(new Error(`运行环境准备失败（退出码 ${code}）：${errorOutput.trim()}`));
      else resolve(output.trim());
    });
  });
}

async function installUv(cacheDir, run) {
  const musl = process.platform === 'linux' && !process.report.getReport().header.glibcVersionRuntime;
  const artifact = selectArtifact(process.platform, process.arch, musl);
  const folder = path.join(cacheDir, 'uv-' + artifact.version);
  const binary = path.join(folder, process.platform === 'win32' ? 'uv.exe' : 'uv');
  try {
    if ((await run(binary, ['--version'], {timeout: 10000})).startsWith(`uv ${artifact.version}`)) return binary;
  } catch { /* 缺失或损坏时重新下载；不因此放行命令。 */ }
  await mkdir(folder, {recursive: true});
  const staging = await mkdtemp(path.join(folder, 'download-'));
  try {
    const archive = path.join(staging, artifact.name);
    const url = `https://github.com/astral-sh/uv/releases/download/${artifact.version}/${artifact.name}`;
    const curl = process.platform === 'win32' ? 'curl.exe' : 'curl';
    try {
      // curl 会自动读取 HTTPS_PROXY/HTTP_PROXY，Windows 与 Unix 统一走这一条路径。
      await run(curl, ['--fail', '--location', '--silent', '--show-error', '--max-time', '120',
        '--max-filesize', String(64 * 1024 * 1024), '--output', archive, url], {timeout: 130000});
      const bytes = await readFile(archive);
      if (bytes.length > 64 * 1024 * 1024 || createHash('sha256').update(bytes).digest('hex') !== artifact.sha256) {
        throw new Error('运行环境下载校验失败，已停止安装。');
      }
    } catch (error) {
      await rm(archive, {force: true});
      if (error.message.includes('校验')) throw error;
      try {
        // curl 不可用时 Windows 退回系统 PowerShell；显式传入代理，因为其不会读取 HTTPS_PROXY。
        if (process.platform === 'win32') {
          const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy ?? '';
          const ps = `& { $params = @{UseBasicParsing=$true; TimeoutSec=120; Uri=$args[0]; OutFile=$args[1]}; if ($args[2]) { $params.Proxy=$args[2] }; Invoke-WebRequest @params } ${quotePowerShell(url)} ${quotePowerShell(archive)} ${quotePowerShell(proxy)}`;
          await run(process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe') : 'powershell.exe',
            ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', ps], {timeout: 130000});
          const bytes = await readFile(archive);
          if (createHash('sha256').update(bytes).digest('hex') !== artifact.sha256) throw new Error('运行环境下载校验失败，已停止安装。');
        } else {
          await writeFile(archive, await checkedDownload(url, artifact.sha256));
        }
      } catch (fallbackError) {
        await rm(archive, {force: true});
        throw fallbackError;
      }
    }
    // 只提取固定的可执行文件，不执行远程安装脚本；Windows 10+ 内置 tar 支持 ZIP。
    const tar = process.platform === 'win32' ? path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe') : '/usr/bin/tar';
    await run(tar, ['-xf', archive, '-C', staging, artifact.entry], {timeout: 30000});
    const staged = path.join(staging, artifact.entry);
    if (process.platform !== 'win32') await chmod(staged, 0o700);
    if (!(await run(staged, ['--version'], {timeout: 10000})).startsWith(`uv ${artifact.version}`)) throw new Error('下载的运行环境版本不符。');
    try { await rename(staged, binary); }
    catch (error) {
      // 多个 DSH 会话可同时首次启动；另一个已完成相同版本即可复用。
      if (!(await run(binary, ['--version'], {timeout: 10000})).startsWith(`uv ${artifact.version}`)) throw error;
    }
    return binary;
  } finally {
    // 只清理由本次 mkdtemp 创建的下载目录，不触碰已有 Python 环境或用户文件。
    await rm(staging, {recursive: true, force: true});
  }
}

function quotePowerShell(value) { return "'" + value.replaceAll("'", "''") + "'"; }

function environment(cacheDir) {
  const env = {...process.env};
  // 用户项目的 UV_*/PIP_*、虚拟环境和 PYTHONPATH 不应改变防护器的隔离环境。
  for (const key of Object.keys(env)) if (/^(UV_|PIP_|PYTHON|VIRTUAL_ENV$|CONDA_PREFIX$)/i.test(key)) delete env[key];
  return {...env, UV_CACHE_DIR: path.join(cacheDir, 'uv-cache'), UV_PYTHON_INSTALL_DIR: path.join(cacheDir, 'python'),
    // 使用操作系统证书库，兼容系统信任的企业代理；仍保持完整 TLS 校验。
    UV_PYTHON_DOWNLOADS: 'automatic', UV_PYTHON_INSTALL_MIRROR: 'https://github.com/astral-sh/python-build-standalone/releases/download',
    UV_SYSTEM_CERTS: 'true', PYTHONNOUSERSITE: '1'};
}

const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

// DSH 宿主自带托管 Python（~/.dsh/dsh-runtimes/*/dependencies/python），自带 pip 与 venv。
// 优先复用它创建隔离 venv，只从 PyPI 镜像补装缺失依赖，避免下载 uv 本体和托管 Python。
const DSH_BASE_PROBE = "import sys, json; import pip; print(json.dumps(list(sys.version_info[:3])))";

export async function dshPythonCandidates(homeDir = os.homedir()) {
  const runtimesRoot = path.join(homeDir, '.dsh', 'dsh-runtimes');
  let entries;
  try { entries = await readdir(runtimesRoot, {withFileTypes: true}); }
  catch { return []; }
  const candidates = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const base = path.join(runtimesRoot, entry.name, 'dependencies', 'python');
    const executables = process.platform === 'win32'
      ? [path.join(base, 'python.exe')]
      : [path.join(base, 'bin', 'python3'), path.join(base, 'bin', 'python')];
    for (const exe of executables) {
      try { if ((await stat(exe)).isFile()) { candidates.push(exe); break; } } catch { /* 布局不符时跳过该候选。 */ }
    }
  }
  return candidates;
}

/** 逐元素比较版本三元组；数组直接做关系运算会退化为字符串比较，"3,9" > "3,10"。 */
function compareVersion(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const left = a[i] ?? 0, right = b[i] ?? 0;
    if (left !== right) return left < right ? -1 : 1;
  }
  return 0;
}

/** 探测候选内置 Python，返回版本最高且 pip 可用、不低于 3.10 的一个；不可用返回 null。 */
export async function probeDshPython(candidates, run = runProcess) {
  let best = null;
  for (const exe of candidates) {
    let version;
    try { version = JSON.parse(await run(exe, ['-I', '-X', 'utf8', '-c', DSH_BASE_PROBE], {timeout: 15000})); }
    catch { continue; }
    if (!Array.isArray(version) || version.length < 2 || typeof version[0] !== 'number' || typeof version[1] !== 'number'
      || compareVersion(version, [3, 10]) < 0) continue;
    if (!best || compareVersion(version, best.version) > 0) best = {exe, version};
  }
  return best;
}

async function withBootstrapLock(lockPath, callback) {
  const deadline = Date.now() + 960000;
  let owned = false;
  while (!owned) {
    try {
      await mkdir(lockPath);
      await writeFile(path.join(lockPath, 'owner.json'), JSON.stringify({pid: process.pid, started: Date.now()}), {mode: 0o600});
      owned = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try {
        const owner = JSON.parse(await readFile(path.join(lockPath, 'owner.json'), 'utf8'));
        if (Date.now() - owner.started > 960000) {
          try { process.kill(owner.pid, 0); }
          catch { await rm(lockPath, {recursive: true, force: true}); continue; }
        }
      } catch (readError) {
        if (readError.code === 'ENOENT') {
          try { if (Date.now() - (await stat(lockPath)).mtimeMs > 30000) await rm(lockPath, {recursive: true, force: true}); }
          catch { /* 锁正被其他启动进程创建或释放。 */ }
        }
      }
      if (Date.now() >= deadline) throw new Error('等待其他会话准备运行环境超时。');
      await delay(250);
    }
  }
  try { return await callback(); }
  finally { if (owned) await rm(lockPath, {recursive: true, force: true}); }
}

export function createRuntime(options = {}) {
  const root = options.packageRoot ?? packageRoot;
  const cacheDir = options.cacheDir ?? path.join(os.homedir(), '.cache', 'dsh-agent-recycle-guard');
  const run = options.run ?? runProcess;
  const prepareUv = options.installUv ?? installUv;
  const notify = options.notify ?? (message => console.error(message));
  // 真实环境下探测结果进程内缓存；测试通过注入候选列表绕开。
  const dshPythons = options.dshPythons ?? dshPythonCandidates;
  const probeDsh = options.probeDshPython ?? probeDshPython;
  let dshBasePromise = null;
  const resolveDshBase = async () => {
    if (!dshBasePromise) dshBasePromise = probeDsh(await dshPythons(), run).catch(() => null);
    return dshBasePromise;
  };
  const pending = new Map();
  return async (config = {}) => {
    if (config.python !== undefined && (typeof config.python !== 'string' || !config.python || !path.isAbsolute(config.python))) {
      throw new Error('可选 Python 配置必须是解释器的绝对路径；默认无需配置。');
    }
    const requirements = path.join(root, 'requirements.txt');
    const indexes = pypiIndexes(config);
    // 运行时来源进摘要：DSH 升级替换内置 Python 后旧 venv 自动失效重建。
    const dshBase = config.python ? null : await resolveDshBase();
    const baseKey = config.python ? 'user:' + config.python : dshBase ? 'dsh:' + dshBase.exe + ':' + dshBase.version.join('.') : 'uv:managed-3.12';
    const digest = createHash('sha256').update(await readFile(requirements)).update(baseKey)
      .update(indexes.join('\n'))
      .update(process.platform + process.arch + manifest.version).digest('hex');
    if (pending.has(digest)) return pending.get(digest);
    const task = (async () => {
      await mkdir(cacheDir, {recursive: true});
      const env = environment(cacheDir);
      const ready = path.join(cacheDir, digest + '.json');
      const verify = async python => {
        if (typeof python !== 'string' || !path.isAbsolute(python) || !(await stat(python)).isFile()) throw new Error('缓存解释器路径无效。');
        if (JSON.parse(await run(python, ['-I', '-X', 'utf8', '-c', probe], {cwd: cacheDir, env, timeout: 15000})) !== python) throw new Error('缓存解释器检查失败。');
        return python;
      };
      try { return await verify(JSON.parse(await readFile(ready, 'utf8')).python); }
      catch { /* 缓存缺失或依赖失效时自动修复，失败不影响下次重试。 */ }
      notify('删除防护：正在自动准备隔离运行环境，首次使用需要联网；准备完成后继续执行检查。');
      return withBootstrapLock(path.join(cacheDir, digest + '.lock'), async () => {
        // 另一进程可能在等待期间已完成准备；先读回并重新验证，不覆盖其环境。
        try { return await verify(JSON.parse(await readFile(ready, 'utf8')).python); }
        catch { /* 缓存仍缺失或损坏，由持锁进程修复。 */ }
        // DSH 宿主内置 Python 优先：只建 venv 并从镜像补装依赖，不下载 uv 与托管 Python。
        if (dshBase) {
          try {
          const envRoot = path.join(cacheDir, 'environments', digest);
          const venv = path.join(envRoot, '.venv');
          // 摘要未变但 venv 损坏时整体重建，避免半成品环境。
          await rm(envRoot, {recursive: true, force: true});
          await mkdir(envRoot, {recursive: true});
          await run(dshBase.exe, ['-m', 'venv', venv], {cwd: cacheDir, env});
          const python = path.join(venv, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
          let lastError;
          for (const index of indexes) {
            try {
              await run(python, ['-m', 'pip', 'install', '--no-input', '--disable-pip-version-check',
                '--requirement', requirements, '--index-url', index], {cwd: cacheDir, env});
              lastError = undefined;
              break;
            } catch (error) { lastError = error; }
          }
          if (lastError) throw new Error('国内镜像和官方 PyPI 均无法安装依赖：' + lastError.message);
          await verify(python);
          const temporary = ready + '.' + randomUUID() + '.tmp';
          await writeFile(temporary, JSON.stringify({python}), {mode: 0o600});
          await rename(temporary, ready);
          return python;
          } catch (error) {
            // 内置 Python 的 venv 或镜像安装失败时继续尝试 uv；两条路线都失败才阻止命令。
            notify('删除防护：DSH 内置 Python 准备失败，尝试备用运行环境：' + error.message);
            await rm(path.join(cacheDir, 'environments', digest), {recursive: true, force: true});
          }
        }
        const uv = await prepareUv(cacheDir, run);
        const envRoot = path.join(cacheDir, 'environments', digest);
        const venv = path.join(envRoot, '.venv');
        await rm(envRoot, {recursive: true, force: true});
        await mkdir(envRoot, {recursive: true});
        await run(uv, ['venv', '--no-config', '--python', config.python ?? '3.12',
          ...(config.python ? [] : ['--managed-python']), venv], {cwd: cacheDir, env});
        const python = path.join(venv, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
        let lastError;
        for (const index of indexes) {
          try {
            await run(uv, ['pip', 'install', '--no-config', '--python', python, '--requirement', requirements,
              '--default-index', index], {cwd: cacheDir, env});
            lastError = undefined;
            break;
          } catch (error) { lastError = error; }
        }
        if (lastError) throw new Error('国内镜像和官方 PyPI 均无法安装依赖：' + lastError.message);
        await verify(python);
        const temporary = ready + '.' + randomUUID() + '.tmp';
        await writeFile(temporary, JSON.stringify({python}), {mode: 0o600});
        await rename(temporary, ready);
        return python;
      });
    })();
    pending.set(digest, task);
    try { return await task; }
    catch (error) {pending.delete(digest); throw new Error('删除防护自动准备失败，命令已阻止：' + error.message);}
  };
}

export const ensureRuntime = createRuntime();
