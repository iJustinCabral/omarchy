#!/bin/bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

run_node_test <<'JS'
const fs = require('fs')
const os = require('os')
const cp = require('child_process')
const script = fs.readFileSync(path.join(root, 'bin/omarchy-setup-t2-hibernate'), 'utf8')
const header = script.split('\n').slice(0, 10).join('\n')
assert(header.includes('# omarchy:hidden=true'), 'command stays out of the default listing')
assert(header.includes('# omarchy:summary='), 'command declares its summary')
assert(!/stage-hibernation|build-hibernation|efibootmgr|systemctl|HibernateWithFlags|\/boot\b/.test(script), 'wrapper never builds, stages or powers')
assert(script.includes('boot_policy_native.py'), 'wrapper drives the reviewed native transition')

// Every path, privilege and interpreter is rewritten in an isolated copy; the
// native transition and privilege helpers are logging stubs, never live calls.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omarchy-setup-t2-hibernate-'))
try {
  const model = path.join(dir, 'model')
  const log = path.join(dir, 'calls')
  const commands = path.join(dir, 'commands')
  const state = path.join(dir, 'state')
  fs.mkdirSync(commands)
  for (const command of ['sudo', 'pkexec']) {
    fs.writeFileSync(path.join(commands, command), `#!/bin/bash\nprintf '%s\\n' "${command} $*" >> "$TEST_LOG"\nexec "$@"\n`, {mode: 0o755})
  }
  fs.writeFileSync(path.join(commands, 'native'), '#!/bin/bash\nprintf "%s\\n" "native $*" >> "$TEST_LOG"\nexit "${TEST_STATUS:-0}"\n', {mode: 0o755})
  fs.writeFileSync(path.join(commands, 'uname'), '#!/bin/bash\necho 7.2.6-test\n', {mode: 0o755})
  const python = path.join(commands, 'native')
  function run({machine = 'MacBookAir9,1', args = ['status'], role = 'desktop', terminal = false, status = 0, deployed = false, lock = false} = {}) {
    if (fs.existsSync(state)) fs.chmodSync(state, 0o700)
    fs.rmSync(state, {recursive: true, force: true})
    if (deployed) {
      fs.mkdirSync(path.join(state, 'runtime/packages/t2-suspend/hibernate'), {recursive: true})
      fs.writeFileSync(path.join(state, 'runtime/packages/t2-suspend/hibernate/boot_policy_native.py'), '')
    }
    if (lock) fs.chmodSync(state, 0o000)
    fs.writeFileSync(model, machine + '\n')
    fs.writeFileSync(log, '')
    const copy = script
      .replace('MODEL="/sys/class/dmi/id/product_name"', `MODEL="${model}"`)
      .replace('PYTHON="/usr/bin/python3"', `PYTHON="${python}"`)
      .replace('OPT_IN="/etc/omarchy/t2-hibernate-product.enabled"', `OPT_IN="${path.join(dir, 'enabled')}"`)
      .replace('STATE="/var/lib/omarchy/t2-hibernate-product"', `STATE="${state}"`)
      .replace('DROPIN="/etc/systemd/system/systemd-hibernate.service.d/omarchy-t2.conf"', `DROPIN="${path.join(dir, 'dropin')}"`)
      .replace('GUARD_HOOK="/etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook"', `GUARD_HOOK="${path.join(dir, 'hook')}"`)
      .replace('(( EUID == 0 ))', role === 'root' ? 'true' : 'false')
      .replace('[[ -t 0 ]]', terminal ? 'true' : 'false')
    const fixture = path.join(dir, 'setup')
    fs.writeFileSync(fixture, copy)
    const result = cp.spawnSync('/bin/bash', [fixture, ...args], {env: {...process.env, PATH: `${commands}:/usr/bin:/bin`, TEST_LOG: log, TEST_STATUS: String(status)}, encoding: 'utf8'})
    return {status: result.status, stdout: result.stdout, stderr: result.stderr, calls: fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean)}
  }
  const native = action => `native -I -B ${path.join(state, 'runtime/packages/t2-suspend/hibernate/boot_policy_native.py')} ${action}`

  // status is read-only and unprivileged
  const status = run()
  assertEqual(status.status, 0, 'status succeeds')
  assertDeepEqual(status.calls, [], 'status makes no privileged or native calls')
  assert(status.stdout.includes('Model:            MacBookAir9,1') && status.stdout.includes('Opt-in marker:    absent') && status.stdout.includes('Runtime snapshot: not deployed'), 'status reports model, marker and runtime')
  assert(run({deployed: true}).stdout.includes('Runtime snapshot: deployed'), 'status detects the deployed runtime')
  const unreadable = run({deployed: true, lock: true})
  assertEqual(unreadable.status, 0, 'status tolerates a root-private runtime')
  assert(unreadable.stdout.includes('root-private'), 'status says the runtime needs root to inspect')

  // every action reaches the fixed native adapter with the right privilege route
  for (const action of ['assess', 'maintenance', 'reactivate', 'rebind', 'activation', 'deactivation']) {
    assertDeepEqual(run({args: [action], role: 'root'}).calls, [native(action)], `${action} as root runs the native transition directly`)
    assertDeepEqual(run({args: [action], terminal: true}).calls, [`sudo ${native(action).replace('native ', path.join(commands, 'native') + ' ')}`, native(action)], `${action} from a terminal uses sudo`)
    assertDeepEqual(run({args: [action]}).calls, [`pkexec ${native(action).replace('native ', path.join(commands, 'native') + ' ')}`, native(action)], `${action} without a terminal uses pkexec`)
  }
  assertEqual(run({args: ['assess'], role: 'root', status: 17}).status, 17, 'native failure is propagated')

  // fail closed: wrong model, bad usage
  for (const options of [{machine: 'MacBookPro16,1'}, {machine: 'MacBookAir9,1x'}, {machine: 'MacBookPro16,1', args: ['assess']}]) {
    const result = run(options)
    assert(result.status === 1 && result.calls.length === 0, 'off-model machines are refused without any call')
  }
  for (const args of [[], ['status', 'extra'], ['assess', '--force'], ['stage'], ['build']]) {
    const result = run({args})
    assert(result.status === 2 && result.calls.length === 0, 'unknown or extra arguments fail without any call')
  }
  assertEqual(run({args: ['--help']}).status, 0, 'help exits successfully')
} finally {
  fs.rmSync(dir, {recursive: true, force: true})
}
JS
