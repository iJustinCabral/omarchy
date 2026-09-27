#!/bin/bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

run_node_test <<'JS'
const fs = require('fs')
const os = require('os')
const cp = require('child_process')
const script = fs.readFileSync(path.join(root, 'bin/omarchy-system-hibernate'), 'utf8')
const unit = fs.readFileSync(path.join(root, 'packages/t2-suspend/hibernate/omarchy-t2-hibernate-product.service'), 'utf8')
const menu = requireFromRoot('shell/plugins/menu/MenuModel.js')
const items = menu.parseMenuJsonc(fs.readFileSync(path.join(root, 'default/omarchy/omarchy-menu.jsonc'), 'utf8'))
assertEqual(items.find(item => item.id === 'system.hibernate').action, 'omarchy-system-hibernate', 'Hibernate menu uses the safe dispatcher')
assert(unit.includes('ExecStart=/usr/bin/python3 -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/product.py hibernate'), 'service executes only the fixed root-owned snapshot')
assert(unit.includes('Type=oneshot') && unit.includes('TimeoutStartSec=infinity') && unit.includes('Restart=no'), 'service waits through S4 without automatic retry')
assert(!/^(RemainAfterExit|Condition\w+|WantedBy|RequiredBy|Also)=/m.test(unit) && !unit.includes('[Install]'), 'service cannot silently skip, auto-enable or suppress a second cycle')
assert(script.includes('(( EUID == 0 ))') && script.includes('[[ -t 0 && -t 2 ]]'), 'production privilege branches distinguish root, terminal and desktop')

// All paths and privilege branches are rewritten in an isolated script copy;
// every command that could affect power is a logging stub, never a live call.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'omarchy-hibernate-dispatch-'))
try {
  const marker = path.join(dir, 'enabled')
  const model = path.join(dir, 'model')
  const log = path.join(dir, 'calls')
  const commands = path.join(dir, 'commands')
  fs.mkdirSync(commands)
  for (const command of ['systemctl', 'sudo', 'pkexec']) {
    fs.writeFileSync(path.join(commands, command), `#!/bin/bash\nprintf '%s\\n' "${command} $*" >> "$TEST_LOG"\nexit "\${TEST_STATUS:-0}"\n`, {mode: 0o755})
  }
  fs.writeFileSync(path.join(commands, 'omarchy-hw-t2'), '#!/bin/bash\nexit "$TEST_T2"\n', {mode: 0o755})
  fs.writeFileSync(path.join(commands, 'stat'), '#!/bin/bash\nprintf "%s\\n" "$TEST_STAT"\n', {mode: 0o755})
  function run({t2 = true, present = true, stat = '0:0:644:0', machine = 'MacBookAir9,1', role = 'desktop', status = 0, symlink = false, args = []} = {}) {
    if (fs.existsSync(marker) || (() => { try { fs.lstatSync(marker); return true } catch { return false } })()) fs.unlinkSync(marker)
    if (present) {
      if (symlink) fs.symlinkSync(path.join(dir, 'missing'), marker)
      else fs.writeFileSync(marker, '')
    }
    fs.writeFileSync(model, machine + '\n')
    fs.writeFileSync(log, '')
    const copy = script.replace('OPT_IN="/etc/omarchy/t2-hibernate-product.enabled"', `OPT_IN="${marker}"`)
      .replace('MODEL="/sys/class/dmi/id/product_name"', `MODEL="${model}"`)
      .replace('SYSTEMCTL="/usr/bin/systemctl"', `SYSTEMCTL="${commands}/systemctl"`)
      .replace('(( EUID == 0 ))', role === 'root' ? 'true' : 'false')
      .replace('[[ -t 0 && -t 2 ]]', role === 'terminal' ? 'true' : 'false')
    const fixture = path.join(dir, 'dispatch')
    fs.writeFileSync(fixture, copy)
    const result = cp.spawnSync('/bin/bash', [fixture, ...args], {env: {...process.env, PATH: `${commands}:/usr/bin:/bin`, TEST_LOG: log, TEST_T2: t2 ? '0' : '1', TEST_STAT: stat, TEST_STATUS: String(status)}, encoding: 'utf8'})
    return {status: result.status, calls: fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean)}
  }
  assertDeepEqual(run({present: false}), {status: 0, calls: ['systemctl hibernate']}, 'non-opted-in T2 retains stock hibernate')
  assertDeepEqual(run({t2: false, present: false}), {status: 0, calls: ['systemctl hibernate']}, 'non-opted-in non-T2 retains stock hibernate')
  for (const role of ['root', 'terminal', 'desktop']) {
    const result = run({role})
    const prefix = role === 'root' ? 'systemctl' : `${role === 'terminal' ? 'sudo' : 'pkexec'} ${commands}/systemctl`
    assertDeepEqual(result, {status: 0, calls: [`${prefix} start omarchy-t2-hibernate-product.service`]}, `${role} starts only the fixed product unit`)
  }
  assertEqual(run({status: 17}).status, 17, 'product/service failure is propagated')
  assertEqual(run({status: 17}).calls.length, 1, 'failed opted-in start never falls back')
  for (const options of [{stat: '1000:0:644:0'}, {stat: '0:0:666:0'}, {stat: '0:0:644:1'}, {symlink: true}, {machine: 'MacBookPro16,1'}, {t2: false}, {args: ['--force']}]) {
    const result = run(options)
    assert(result.status !== 0 && result.calls.length === 0, 'invalid marker/model/arguments fail closed without power calls')
  }
} finally {
  fs.rmSync(dir, {recursive: true, force: true})
}
JS
