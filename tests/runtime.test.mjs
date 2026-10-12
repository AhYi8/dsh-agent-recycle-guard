// 自动准备环境必须覆盖首次启动、缓存复用、失败重试与并发，不能依赖本机预装 Python。
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {test} from 'node:test';
import {createRuntime, selectArtifact, checkedDownload, runProcess, pypiIndexes, DEFAULT_PYPI_INDEXES,
  dshPythonCandidates, probeDshPython} from '../lib/runtime.js';

async function fixture(overrides = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-recycle-bootstrap-'));
  const packageRoot = path.join(root, 'package');
  await mkdir(packageRoot);
  await writeFile(path.join(packageRoot, 'requirements.txt'), 'bashlex==0.18\n');
  let prepares = 0;
  let python;
  const run = async (command, args) => {
    if (command === python) return JSON.stringify(python);
    assert.equal(command, '/test/uv');
    assert.ok(args.includes('--no-config'));
    if (args[0] === 'venv') {
      assert.ok(args.includes('--managed-python'));
      const venv = args.at(-1);
      python = path.join(venv, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
      prepares++;
      await mkdir(path.dirname(python), {recursive: true});
      await writeFile(python, '测试用路径标记');
      return '';
    }
    assert.equal(args[0], 'pip');
    assert.ok(args.includes('--python'));
    assert.ok(args.includes('--requirement'));
    return '';
  };
  const options = {packageRoot, cacheDir: path.join(root, 'cache'), run,
    installUv: async () => '/test/uv', notify: () => {}, dshPythons: async () => [], ...overrides};
  return {root, get python() {return python;}, options, count: () => prepares, runtime: createRuntime(options)};
}

test('没有 Python 的首次运行自动创建环境，同进程并发只准备一次', async () => {
  const f = await fixture();
  const results = await Promise.all(Array.from({length: 8}, () => f.runtime()));
  assert.ok(results.every(value => value === f.python));
  assert.equal(f.count(), 1);
});

test('新会话复用已核对依赖的缓存，不再联网准备', async () => {
  const f = await fixture();
  await f.runtime();
  assert.equal(await createRuntime({...f.options, installUv: () => {throw Error('不应下载');}})(), f.python);
  assert.equal(f.count(), 1);
});

test('依赖清单变更后自动准备新环境', async () => {
  const f = await fixture();
  await f.runtime();
  await writeFile(path.join(f.options.packageRoot, 'requirements.txt'), 'bashlex==0.18\nsend2trash==1.8.3\n');
  await createRuntime(f.options)();
  assert.equal(f.count(), 2);
});

test('缓存解释器失效时重新准备，不放行原始删除', async () => {
  const f = await fixture();
  await f.runtime();
  let probes = 0;
  const run = async (command, args, options) => {
    // 缓存先在加锁前、再在锁内复核，两次都模拟损坏后才触发重建。
    if (command === f.python && ++probes <= 2) throw Error('缓存损坏');
    return f.options.run(command, args, options);
  };
  assert.equal(await createRuntime({...f.options, run})(), f.python);
  assert.equal(f.count(), 2);
});

test('准备失败后拒绝并允许下次重试，不缓存失败 Promise', async () => {
  let attempts = 0;
  const f = await fixture({installUv: async () => {if (++attempts === 1) throw Error('网络不可用'); return '/test/uv';}});
  await assert.rejects(f.runtime(), /自动准备.*网络不可用/);
  assert.equal(await f.runtime(), f.python);
});

test('用户可选 Python 路径非法时拒绝，默认调用无需配置', async () => {
  const f = await fixture();
  await assert.rejects(f.runtime({python: ['python']}), /Python.*路径/);
  assert.equal(await f.runtime(), f.python);
});

test('不支持的平台或架构明确报错', () => {
  assert.throws(() => selectArtifact('win32', 'ia32'), /不支持/);
  assert.throws(() => selectArtifact('freebsd', 'x64'), /不支持/);
  for (const platform of ['win32', 'linux', 'darwin']) {
    for (const arch of ['x64', 'arm64']) {
      assert.match(selectArtifact(platform, arch).sha256, /^[a-f0-9]{64}$/);
    }
  }
  assert.match(selectArtifact('linux', 'x64', true).name, /musl/);
});

test('下载必须匹配固定校验值，失败和超限均拒绝', async () => {
  const payload = Buffer.from('abc');
  const valid = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  const fetcher = async () => new Response(payload);
  assert.deepEqual(await checkedDownload('https://example.com/file', valid, fetcher), payload);
  await assert.rejects(checkedDownload('https://example.com/file', '0'.repeat(64), fetcher), /校验/);
  await assert.rejects(checkedDownload('https://example.com/file', valid, async () => new Response('', {status: 503})), /503/);
  await assert.rejects(checkedDownload('https://example.com/file', valid, async () => new Response('', {headers: {'content-length': '999999999'}})), /上限/);
});

test('国内 PyPI 镜像优先，失败后依序回退且只接受 HTTPS simple 索引', () => {
  assert.deepEqual(pypiIndexes(), [...DEFAULT_PYPI_INDEXES]);
  assert.equal(pypiIndexes({pypiIndex: 'https://mirror.example/simple/'})[0], 'https://mirror.example/simple');
  assert.throws(() => pypiIndexes({pypiIndex: 'http://mirror.example/simple'}), /HTTPS/);
  assert.throws(() => pypiIndexes({pypiIndex: 'https://mirror.example/packages'}), /simple/);
});

test('依赖安装逐个尝试国内镜像，最终可回退到官方 PyPI', async () => {
  const f = await fixture();
  const indexes = [];
  const run = async (command, args, options) => {
    const indexAt = args.indexOf('--default-index');
    if (indexAt >= 0) {
      const index = args[indexAt + 1];
      indexes.push(index);
      if (index !== DEFAULT_PYPI_INDEXES.at(-1)) throw new Error('镜像暂不可用');
    }
    return f.options.run(command, args, options);
  };
  await createRuntime({...f.options, run})();
  assert.deepEqual(indexes, [...DEFAULT_PYPI_INDEXES]);
});

test('准备子进程成功、失败、启动失败和超时都有明确结果', async () => {
  assert.equal(await runProcess(process.execPath, ['-e', 'console.log("准备完成")']), '准备完成');
  await assert.rejects(runProcess(process.execPath, ['-e', 'console.error("失败原因"); process.exit(2)']), /退出码 2.*失败原因/);
  await assert.rejects(runProcess('/不存在的解释器', []));
  await assert.rejects(runProcess(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {timeout: 50}), /超时/);
  await assert.rejects(runProcess(process.execPath, ['-e', 'console.log("x".repeat(300000));setInterval(()=>{},1000)']), /上限/);
});

// —— DSH 内置 Python 路线：优先复用宿主 Python，只从镜像补装依赖，不下载 uv。 ——

async function dshFixture(overrides = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-recycle-dsh-'));
  const packageRoot = path.join(root, 'package');
  await mkdir(packageRoot);
  await writeFile(path.join(packageRoot, 'requirements.txt'), 'bashlex==0.18\n');
  let prepares = 0;
  let python;
  const run = async (command, args) => {
    if (command === '/test/dsh-python') {
      // 内置 Python 基座探测：返回版本三元组。
      if (args.at(-1)?.includes('version_info')) return JSON.stringify([3, 12, 14]);
      assert.deepEqual(args.slice(0, 2), ['-m', 'venv']);
      const venv = args.at(-1);
      python = path.join(venv, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
      prepares++;
      await mkdir(path.dirname(python), {recursive: true});
      await writeFile(python, '测试用路径标记');
      return '';
    }
    if (command === python) {
      // venv 内 pip 安装依赖；其余为依赖核对探测。
      if (args.includes('pip')) return '';
      return JSON.stringify(python);
    }
    throw Error('不应调用 uv 或其他程序：' + command);
  };
  const options = {packageRoot, cacheDir: path.join(root, 'cache'), run,
    installUv: async () => {throw Error('存在 DSH Python 时不应下载 uv');},
    dshPythons: async () => ['/test/dsh-python'], notify: () => {}, ...overrides};
  return {root, get python() {return python;}, options, count: () => prepares, runtime: createRuntime(options)};
}

test('存在 DSH 内置 Python 时直接建 venv 装依赖，不下载 uv', async () => {
  const f = await dshFixture();
  const results = await Promise.all(Array.from({length: 4}, () => f.runtime()));
  assert.ok(results.every(value => value === f.python));
  assert.equal(f.count(), 1);
  assert.ok(f.python.startsWith(f.options.cacheDir));
});

test('DSH 路线同样复用缓存，且 venv 失效时整体重建', async () => {
  const f = await dshFixture();
  await f.runtime();
  assert.equal(await createRuntime({...f.options})(), f.python);
  assert.equal(f.count(), 1);
  let probes = 0;
  const run = async (command, args, options) => {
    if (command === f.python && !args.includes('pip') && !args.includes('venv') && ++probes <= 2) throw Error('venv 损坏');
    return f.options.run(command, args, options);
  };
  assert.equal(await createRuntime({...f.options, run})(), f.python);
  assert.equal(f.count(), 2);
});

test('DSH 路线依赖安装逐个尝试镜像，最终回退官方源', async () => {
  const f = await dshFixture();
  const indexes = [];
  const run = async (command, args, options) => {
    const indexAt = args.indexOf('--index-url');
    if (indexAt >= 0) {
      const index = args[indexAt + 1];
      indexes.push(index);
      if (index !== DEFAULT_PYPI_INDEXES.at(-1)) throw new Error('镜像暂不可用');
    }
    return f.options.run(command, args, options);
  };
  await createRuntime({...f.options, run})();
  assert.deepEqual(indexes, [...DEFAULT_PYPI_INDEXES]);
});

test('内置 Python 版本过低或无 pip 时回退 uv 路线', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-recycle-fallback-'));
  const packageRoot = path.join(root, 'package');
  await mkdir(packageRoot);
  await writeFile(path.join(packageRoot, 'requirements.txt'), 'bashlex==0.18\n');
  let python;
  const run = async (command, args) => {
    if (command === '/test/dsh-python') return JSON.stringify([3, 9, 13]);
    if (command === '/test/uv') {
      if (args[0] === 'venv') {
        python = path.join(args.at(-1), process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
        await mkdir(path.dirname(python), {recursive: true});
        await writeFile(python, '测试用路径标记');
      }
      return '';
    }
    if (command === python) return JSON.stringify(python);
    throw Error('不应调用：' + command);
  };
  const options = {packageRoot, cacheDir: path.join(root, 'cache'), run,
    installUv: async () => '/test/uv', dshPythons: async () => ['/test/dsh-python'], notify: () => {}};
  assert.equal(await createRuntime(options)(), python);
});

test('DSH 内置 Python 准备失败时继续走 uv 兜底', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-recycle-dsh-fallback-'));
  const packageRoot = path.join(root, 'package');
  await mkdir(packageRoot);
  await writeFile(path.join(packageRoot, 'requirements.txt'), 'bashlex==0.18\n');
  let python;
  const run = async (command, args) => {
    if (command === '/test/dsh-python') {
      if (args.at(-1)?.includes('version_info')) return JSON.stringify([3, 12, 14]);
      await mkdir(path.join(args.at(-1), '.venv'), {recursive: true});
      throw Error('DSH venv 创建失败');
    }
    if (command === '/test/uv') {
      if (args[0] === 'venv') {
        python = path.join(args.at(-1), process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
        await mkdir(path.dirname(python), {recursive: true});
        await writeFile(python, '测试用路径标记');
      }
      return '';
    }
    if (command === python) return JSON.stringify(python);
    throw Error('不应调用：' + command);
  };
  const options = {packageRoot, cacheDir: path.join(root, 'cache'), run,
    installUv: async () => '/test/uv', dshPythons: async () => ['/test/dsh-python'], notify: () => {}};
  assert.equal(await createRuntime(options)(), python);
});

test('dshPythonCandidates 按固定布局发现内置 Python', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'agent-recycle-layout-'));
  const exe = path.join(root, '.dsh', 'dsh-runtimes', 'dsh-primary-runtime', 'dependencies', 'python',
    process.platform === 'win32' ? 'python.exe' : 'bin/python3');
  await mkdir(path.dirname(exe), {recursive: true});
  await writeFile(exe, '标记');
  assert.deepEqual(await dshPythonCandidates(root), [exe]);
  assert.deepEqual(await dshPythonCandidates(path.join(root, '不存在')), []);
});

test('probeDshPython 只接受不低于 3.10 且探测成功的候选', async () => {
  const run = async exe => exe === '/ok' ? JSON.stringify([3, 12, 14]) : Promise.reject(Error('探测失败'));
  const best = await probeDshPython(['/old', '/ok', '/bad'], run);
  assert.equal(best.exe, '/ok');
  assert.deepEqual(best.version, [3, 12, 14]);
  // 版本不达标时整体放弃，进入 uv 兜底。
  assert.equal(await probeDshPython(['/old'], async () => JSON.stringify([3, 9, 13])), null);
});

test('可选冷启动集成：空缓存、无系统 Python、自动依赖和新会话复用',
  {skip: process.env.GUARD_BOOTSTRAP_TEST !== '1', timeout: 360000}, async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'agent-recycle-cold-'));
    const priorPath = process.env.PATH;
    // Windows 留下系统 PowerShell 与 tar；Python 必须由 uv 自动准备。
    process.env.PATH = process.platform === 'win32'
      ? `${process.env.SystemRoot}\\System32;${process.env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0` : '/usr/bin:/bin';
    try {
      const options = {cacheDir: root};
      const runtime = createRuntime(options);
      const [python, concurrent] = await Promise.all([runtime(), runtime()]);
      assert.equal(python, concurrent);
      assert.ok(python.startsWith(root));
      assert.equal(await createRuntime({...options, installUv: () => {throw Error('不应下载');}})(), python);
    } finally {process.env.PATH = priorPath;}
  });
