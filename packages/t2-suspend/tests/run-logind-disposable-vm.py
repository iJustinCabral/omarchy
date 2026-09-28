#!/usr/bin/python3
"""Real logind lifecycle proof in a disposable, networkless QEMU guest.

Copies only installed public executables/libraries; no host configuration,
private initramfs, EFI, modules or power interfaces are changed. The guest
hibernate body records entry and exits; it cannot invoke systemd-sleep.
Guest logind alone bypasses its swap-space check to admit the stub body.
This tests notifications and inhibitor lifecycle, not hardware hibernation.
"""
import os
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import sysconfig

GUEST_TEST = r'''
#include <systemd/sd-bus.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
static int started, finished;
static int signal_cb(sd_bus_message *m, void *userdata, sd_bus_error *error) {
  int active;
  (void)userdata; (void)error;
  if (sd_bus_message_read(m, "b", &active) < 0) return -1;
  printf("SIGNAL %s\n", active ? "true" : "false"); fflush(stdout);
  if (active) {
    if (started != finished) exit(13);
    started++;
  } else {
    if (started != finished + 1) exit(14);
    finished++;
  }
  return 0;
}
static void pump(sd_bus *bus, int seconds) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  double end = now.tv_sec + now.tv_nsec / 1e9 + seconds;
  do {
    while (sd_bus_process(bus, NULL) > 0) {}
    sd_bus_wait(bus, 100000);
    clock_gettime(CLOCK_MONOTONIC, &now);
  } while (now.tv_sec + now.tv_nsec / 1e9 < end);
}
static int inhibit(sd_bus *bus, const char *mode) {
  sd_bus_message *reply = NULL;
  int fd, r = sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
    "org.freedesktop.login1.Manager", "Inhibit", NULL, &reply, "ssss", "sleep", "vm-test", "test", mode);
  if (r < 0 || sd_bus_message_read(reply, "h", &fd) < 0) exit(10);
  fd = dup(fd); sd_bus_message_unref(reply); return fd;
}
static int request(sd_bus *bus) {
  sd_bus_error e = SD_BUS_ERROR_NULL;
  int r = sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
    "org.freedesktop.login1.Manager", "HibernateWithFlags", &e, NULL, "t", (uint64_t)1);
  printf("REQUEST %d %s\n", r, e.name ? e.name : "ok"); fflush(stdout);
  if (r < 0 && (!e.name || strcmp(e.name, "org.freedesktop.login1.BlockedByInhibitorLock"))) exit(15);
  sd_bus_error_free(&e); return r;
}
int main(void) {
  sd_bus *bus = NULL; int fd, r;
  setbuf(stdout, NULL);
  if (sd_bus_open_system(&bus) < 0) return 11;
  if (sd_bus_add_match(bus, NULL, "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'", signal_cb, NULL) < 0) return 12;
  printf("CASE block\n"); fd = inhibit(bus, "block"); r = request(bus); pump(bus, 1);
  if (r >= 0 || started || finished || access("/run/body", F_OK) == 0) return 20;
  close(fd); pump(bus, 1);
  printf("CASE delay-release\n"); fd = inhibit(bus, "delay"); r = request(bus); pump(bus, 1);
  if (r < 0 || started != 1 || finished || access("/run/body", F_OK) == 0) return 21;
  close(fd); pump(bus, 2);
  if (finished != 1 || access("/run/body", F_OK) != 0) return 22;
  unlink("/run/body");
  printf("CASE delay-timeout\n"); fd = inhibit(bus, "delay"); r = request(bus); pump(bus, 1);
  if (r < 0 || started != 2 || finished != 1 || access("/run/body", F_OK) == 0) return 25;
  pump(bus, 3);
  if (r < 0 || started != 2 || finished != 2 || access("/run/body", F_OK) != 0) return 23;
  close(fd); unlink("/run/body"); pump(bus, 1);
  printf("CASE body-failure\n"); close(open("/run/fail", O_CREAT|O_WRONLY, 0600)); r = request(bus); pump(bus, 2);
  if (r < 0 || started != 3 || finished != 3 || access("/run/body", F_OK) != 0) return 24;
  char *result = NULL;
  if (sd_bus_get_property_string(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/systemd_2dhibernate_2eservice", "org.freedesktop.systemd1.Service", "Result", NULL, &result) < 0 || strcmp(result, "exit-code")) return 26;
  free(result);
  printf("LOGIND_VM_PASS\n"); sd_bus_unref(bus); return 0;
}
'''


def run(*args, **kwargs):
  return subprocess.run(args, check=True, **kwargs)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  modes = parser.add_mutually_exclusive_group()
  modes.add_argument("--native-inhibitor", action="store_true", help="Prove the unchanged native adapter's read-only exclusion guard with real guest logind; no native CLI/transition")
  modes.add_argument("--maintenance-launcher", action="store_true", help="Prove the unchanged source-only launcher privilege drop, held readiness and descriptor inheritance using guest-only stub commands")
  modes.add_argument("--maintenance-handoff", action="store_true", help="Prove an authenticated nonroot-to-root original update-lock handoff inside the guest; no package or native admission")
  modes.add_argument("--maintenance-entry", action="store_true", help="Trace real guest sudo/inhibitor ancestry and original-client lock handoff with and without sudo PTY; no native admission or password proof")
  modes.add_argument("--maintenance-scope", action="store_true", help="Test real transient scope placement/draining of held user stub descendants; no package command or native admission")
  modes.add_argument("--maintenance-recovery", action="store_true", help="Join fixture maintenance coordinator, real user scopes and retained veto recovery under real logind exclusion; no package/native admission")
  modes.add_argument("--maintenance-owner", action="store_true", help="Prove actual owner-held logind FD and latched stop signals survive original inhibitor-parent death in the guest; no package/native admission")
  modes.add_argument("--maintenance-alpm", action="store_true", help="Test a real tiny disposable pacman transaction and fixture maintenance hook under an owner-held inhibitor; no host packages or native admission")
  args = parser.parse_args()
  work = Path(tempfile.mkdtemp(prefix="mba-logind-vm-"))
  root = work / "root"
  root.mkdir()
  print(f"Disposable guest evidence: {work}", flush=True)
  python_guest = args.native_inhibitor or args.maintenance_launcher or args.maintenance_handoff or args.maintenance_entry or args.maintenance_scope or args.maintenance_recovery or args.maintenance_owner or args.maintenance_alpm
  if not python_guest:
    source = work / "test.c"
    source.write_text(GUEST_TEST)
    run("cc", "-Wall", "-Wextra", "-Werror", "-o", str(work / "test"), str(source), "-lsystemd")
  copied = set()

  def copy_binary(path, target=None):
    path = Path(path)
    target = target or str(path)
    if target.startswith("/usr/lib64/"):
      target = target.replace("/usr/lib64/", "/usr/lib/", 1)
    if target in copied:
      return
    copied.add(target)
    destination = root / target.lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path.resolve(), destination)
    result = subprocess.run(["ldd", str(path)], capture_output=True, text=True)
    for library in re.findall(r"(?:=> )?(/\S+) \(", result.stdout):
      copy_binary(library)

  for binary in ("/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-executor", "/usr/lib/systemd/systemd-shutdown", "/usr/lib/systemd/systemd-logind", "/usr/bin/dbus-daemon",
                 "/usr/bin/bash", "/usr/bin/mount", "/usr/bin/mkdir", "/usr/bin/sleep", "/usr/bin/touch",
                 "/usr/bin/systemctl"):
    copy_binary(binary)
  if python_guest:
    binaries = ("/usr/bin/python3", "/usr/bin/systemd-inhibit", "/usr/bin/busctl") if args.native_inhibitor or args.maintenance_entry or args.maintenance_scope or args.maintenance_recovery or args.maintenance_owner or args.maintenance_alpm else ("/usr/bin/python3",)
    for binary in binaries:
      copy_binary(binary)
    if args.maintenance_owner or args.maintenance_alpm:
      copy_binary("/usr/lib/libsystemd.so.0")
    if args.maintenance_alpm:
      copy_binary("/usr/bin/pacman")
    # Only public installed stdlib source/data and extension modules. Never
    # traverse site packages, host configuration, home directories or caches.
    stdlib = Path(sysconfig.get_path("stdlib"))
    if stdlib.parent != Path("/usr/lib") or not re.fullmatch(r"python3\.\d+", stdlib.name):
      raise ValueError("Expected public system Python stdlib under /usr/lib")
    for path in sorted(stdlib.rglob("*")):
      relative = path.relative_to(stdlib)
      if any(part in ("site-packages", "dist-packages", "__pycache__", "test", "tests", "ensurepip", "idlelib", "tkinter", "turtledemo", "Tools") or part.startswith("config-") for part in relative.parts):
        continue
      if path.is_symlink():
        raise ValueError("Unexpected symlink in public stdlib: " + str(path))
      if path.is_file():
        if path.suffix == ".so":
          copy_binary(path)
        elif path.suffix in (".py", ".json", ".txt"):
          destination = root / str(path).lstrip("/")
          destination.parent.mkdir(parents=True, exist_ok=True)
          shutil.copy2(path, destination)
    if args.maintenance_entry:
      for binary in ("/usr/bin/sudo", "/usr/lib/sudo/sudoers.so", "/usr/lib/security/pam_permit.so"):
        copy_binary(binary)
      # This is ONLY the disposable image copy; never chmod the host binary.
      (root / "usr/bin/sudo").chmod(0o4755)
  else:
    copy_binary(work / "test", "/test")
  for directory in ("proc", "sys", "dev", "run", "tmp", "etc/systemd/system", "etc/dbus-1", "var/lib/systemd/linger"):
    (root / directory).mkdir(parents=True, exist_ok=True)
  (root / "bin").symlink_to("usr/bin")
  (root / "lib").symlink_to("usr/lib")
  (root / "lib64").symlink_to("usr/lib")
  (root / "usr/lib64").symlink_to("lib")

  def write(name, text, executable=False):
    path = root / name.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
      path.chmod(0o755)

  write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
  write("/etc/group", "root:x:0:\n")
  if args.maintenance_launcher or args.maintenance_handoff or args.maintenance_entry or args.maintenance_scope or args.maintenance_recovery:
    write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nworker:x:1000:1000:Guest worker:/home/worker:/bin/bash\n")
    write("/etc/group", "root:x:0:\nworker:x:1000:\nfixture-extra:x:1001:worker\n")
    (root / "home/worker").mkdir(parents=True)
  write("/etc/nsswitch.conf", "passwd: files\ngroup: files\n")
  write("/etc/os-release", "ID=arch\nNAME=Disposable-logind-test\n")
  write("/etc/machine-id", "1f0bb75b22c4490b968b906528b141b4\n")
  write("/etc/dbus-1/system.conf", '<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>\n')
  write("/etc/systemd/logind.conf", "[Login]\nInhibitDelayMaxSec=3\nHandlePowerKey=ignore\nHandleSuspendKey=ignore\nHandleHibernateKey=ignore\nHandleLidSwitch=ignore\n")
  write("/init", "#!/bin/bash\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\nmkdir -p /run/dbus\nexec /usr/lib/systemd/systemd --system\n", True)
  if args.maintenance_entry:
    write("/etc/sudo.conf", "Plugin sudoers_policy /usr/lib/sudo/sudoers.so\nPlugin sudoers_io /usr/lib/sudo/sudoers.so\nPlugin sudoers_audit /usr/lib/sudo/sudoers.so\n")
    write("/etc/pam.d/sudo", "auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n")
    write("/init", "#!/bin/bash\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\nmkdir -p /dev/pts /run/dbus\nmount -t devpts devpts /dev/pts\nexec /usr/lib/systemd/systemd --system\n", True)
  write("/body", '#!/bin/bash\necho "BODY ENTER" >/dev/console\ntouch /run/body\nif [[ -e /run/fail ]]; then exit 1; fi\nexit 0\n', True)
  if args.maintenance_owner:
    tests = Path(__file__).resolve().parent
    source_hashes = {}
    destination = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/"
    for name in ("maintenance_inhibitor.py", "boot_policy_native.py", "maintenance_peer.py"):
      raw = (tests.parent / "hibernate" / name).read_bytes()
      write(destination + name, raw.decode())
      target = root / (destination + name).lstrip("/")
      target.chmod(0o600)
      if target.read_bytes() != raw:
        raise ValueError("Guest owner dependencies must preserve exact public source bytes")
      source_hashes[name] = hashlib.sha256(raw).hexdigest()
    raw = (tests / "maintenance-owner-guest.py").read_bytes()
    write("/maintenance-owner-test.py", raw.decode())
    source_hashes["maintenance-owner-guest.py"] = hashlib.sha256(raw).hexdigest()
    manifest = "".join(value + "  " + name + "\n" for name, value in sorted(source_hashes.items()))
    (work / "maintenance-owner.sha256").write_text(manifest)
    print("Exact public owner manifest: " + str(work / "maintenance-owner.sha256") + " (SHA-256 " + hashlib.sha256(manifest.encode()).hexdigest() + ")", flush=True)
    print("Exact owner guest SHA-256: " + hashlib.sha256(raw).hexdigest(), flush=True)
    marker = "MAINTENANCE_OWNER_VM"
    test_command = "/usr/bin/python3 -I -B /maintenance-owner-test.py"
  elif args.maintenance_recovery or args.maintenance_alpm:
    tests = Path(__file__).resolve().parent
    source_hashes = {}
    mode = "maintenance-alpm" if args.maintenance_alpm else "maintenance-recovery"
    destination = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/"
    extensionless = {"experiments/0008-wifi-hibernate-isolation/omarchy-t2-hibernate-wifi"}
    # Only public repository Python/hook bytes, never installed private state,
    # home directories, qualification assets or a host boot image.
    for path in sorted(tests.parent.rglob("*")):
      if path.suffix not in (".py", ".hook") and path.relative_to(tests.parent).as_posix() not in extensionless: continue
      if path.is_symlink() or not path.is_file(): raise ValueError("Regular public repository fixture dependency required")
      relative = path.relative_to(tests.parent).as_posix()
      raw = path.read_bytes()
      write(destination + relative, raw.decode())
      if relative == "hibernate/maintenance_inhibitor.py":
        (root / (destination + relative).lstrip("/")).chmod(0o600)
      if (root / (destination + relative).lstrip("/")).read_bytes() != raw:
        raise ValueError("Guest fixture dependencies must preserve exact repository bytes")
      source_hashes[relative] = hashlib.sha256(raw).hexdigest()
    raw = (tests / (mode + "-guest.py")).read_bytes()
    write("/" + mode + "-test.py", raw.decode())
    source_hashes[mode + "-guest.py"] = hashlib.sha256(raw).hexdigest()
    manifest = "".join(value + "  " + name + "\n" for name, value in sorted(source_hashes.items()))
    (work / (mode + ".sha256")).write_text(manifest)
    print("Exact public dependency manifest: " + str(work / (mode + ".sha256")) + " (" + str(len(source_hashes)) + " entries, SHA-256 " + hashlib.sha256(manifest.encode()).hexdigest() + ")", flush=True)
    print("Exact " + mode + " guest SHA-256: " + hashlib.sha256(raw).hexdigest(), flush=True)
    marker = "MAINTENANCE_ALPM_VM" if args.maintenance_alpm else "MAINTENANCE_RECOVERY_VM"
    test_command = "/usr/bin/python3 -I -B /" + mode + "-test.py"
  elif args.maintenance_scope:
    tests = Path(__file__).resolve().parent
    source_hashes = {}
    for name in ("maintenance_scope.py", "maintenance_launcher.py", "maintenance_peer.py"):
      raw = (tests.parent / "hibernate" / name).read_bytes()
      target = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/" + name
      write(target, raw.decode())
      if (root / target.lstrip("/")).read_bytes() != raw:
        raise ValueError("Guest scope dependencies must preserve exact repository bytes")
      source_hashes[name] = hashlib.sha256(raw).hexdigest()
    raw = (tests / "maintenance-scope-guest.py").read_bytes()
    write("/maintenance-scope-test.py", raw.decode())
    source_hashes["maintenance-scope-guest.py"] = hashlib.sha256(raw).hexdigest()
    (work / "maintenance-scope.sha256").write_text("".join(value + "  " + name + "\n" for name, value in sorted(source_hashes.items())))
    for name, value in sorted(source_hashes.items()):
      print("Exact repository source SHA-256: " + value + "  " + name, flush=True)
    marker = "MAINTENANCE_SCOPE_VM"
    test_command = "/usr/bin/python3 -I -B /maintenance-scope-test.py"
  elif args.maintenance_entry:
    tests = Path(__file__).resolve().parent
    source_hashes = {}
    for name in ("maintenance_handoff.py", "maintenance_launcher.py", "maintenance_peer.py"):
      raw = (tests.parent / "hibernate" / name).read_bytes()
      target = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/" + name
      write(target, raw.decode())
      if (root / target.lstrip("/")).read_bytes() != raw:
        raise ValueError("Guest entry dependencies must preserve exact repository bytes")
      source_hashes[name] = hashlib.sha256(raw).hexdigest()
    raw = (tests.parent / "hibernate/boot_policy_native.py").read_bytes()
    write("/native-adapter.py", raw.decode())
    if (root / "native-adapter.py").read_bytes() != raw:
      raise ValueError("Guest exclusion adapter must preserve exact repository bytes")
    source_hashes["boot_policy_native.py"] = hashlib.sha256(raw).hexdigest()
    raw = (tests / "maintenance-entry-guest.py").read_bytes()
    write("/maintenance-entry-test.py", raw.decode())
    source_hashes["maintenance-entry-guest.py"] = hashlib.sha256(raw).hexdigest()
    fixed_script = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py"
    write(fixed_script, "# Guest-only ancestry trace stub, NOT native activation or package admission.\nimport runpy\nrunpy.run_path('/maintenance-entry-test.py')['owner']()\n")
    (work / "maintenance-entry.sha256").write_text("".join(value + "  " + name + "\n" for name, value in sorted(source_hashes.items())))
    for name, value in sorted(source_hashes.items()):
      print("Exact repository source SHA-256: " + value + "  " + name, flush=True)
    marker = "MAINTENANCE_ENTRY_VM"
    test_command = "/usr/bin/python3 -I -B /maintenance-entry-test.py"
  elif args.maintenance_handoff:
    tests = Path(__file__).resolve().parent
    source_hashes = {}
    for name in ("maintenance_handoff.py", "maintenance_launcher.py", "maintenance_peer.py"):
      raw = (tests.parent / "hibernate" / name).read_bytes()
      target = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/" + name
      write(target, raw.decode())
      if (root / target.lstrip("/")).read_bytes() != raw:
        raise ValueError("Guest handoff sources must preserve exact repository bytes")
      source_hashes[name] = hashlib.sha256(raw).hexdigest()
    raw = (tests / "maintenance-handoff-guest.py").read_bytes()
    write("/maintenance-handoff-test.py", raw.decode())
    source_hashes["maintenance-handoff-guest.py"] = hashlib.sha256(raw).hexdigest()
    (work / "maintenance-handoff.sha256").write_text("".join(value + "  " + name + "\n" for name, value in sorted(source_hashes.items())))
    for name, value in sorted(source_hashes.items()):
      print("Exact repository source SHA-256: " + value + "  " + name, flush=True)
    marker = "MAINTENANCE_HANDOFF_VM"
    test_command = "/usr/bin/python3 -I -B /maintenance-handoff-test.py"
  elif args.maintenance_launcher:
    tests = Path(__file__).resolve().parent
    source_hashes = {}
    for name in ("maintenance_launcher.py", "maintenance_peer.py"):
      raw = (tests.parent / "hibernate" / name).read_bytes()
      target = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/" + name
      write(target, raw.decode())
      if (root / target.lstrip("/")).read_bytes() != raw:
        raise ValueError("Guest launcher/peer must preserve exact repository source bytes")
      source_hashes[name] = hashlib.sha256(raw).hexdigest()
    raw = (tests / "maintenance-launcher-guest.py").read_bytes()
    write("/maintenance-launcher-test.py", raw.decode())
    source_hashes["maintenance-launcher-guest.py"] = hashlib.sha256(raw).hexdigest()
    (work / "maintenance-launcher.sha256").write_text("".join(value + "  " + name + "\n" for name, value in sorted(source_hashes.items())))
    for name, value in sorted(source_hashes.items()):
      print("Exact repository source SHA-256: " + value + "  " + name, flush=True)
    marker = "MAINTENANCE_LAUNCHER_VM"
    test_command = "/usr/bin/python3 -I -B /maintenance-launcher-test.py"
  elif args.native_inhibitor:
    tests = Path(__file__).resolve().parent
    adapter = tests.parent / "hibernate/boot_policy_native.py"
    raw = adapter.read_bytes()
    write("/native-adapter.py", raw.decode())
    if (root / "native-adapter.py").read_bytes() != raw:
      raise ValueError("Guest adapter must preserve exact repository source bytes")
    write("/native-inhibitor-test.py", (tests / "native-inhibitor-guest.py").read_text())
    fixed_script = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py"
    write(fixed_script, "# Guest-only stub launcher, NOT the production native CLI.\nimport runpy\nrunpy.run_path('/native-inhibitor-test.py')['worker']()\n")
    (work / "native-adapter.sha256").write_text(hashlib.sha256(raw).hexdigest() + "  native-adapter.py\n")
    print("Exact repository adapter SHA-256: " + hashlib.sha256(raw).hexdigest(), flush=True)
    marker = "NATIVE_INHIBITOR_VM"
    test_command = "/usr/bin/python3 -I -B /native-inhibitor-test.py"
  else:
    marker = "LOGIND_VM"
    test_command = "/test"
  write("/run-test", '#!/bin/bash\nsleep 2\n' + test_command + '\nresult=$?\necho "' + marker + '_EXIT=$result" >/dev/console\nsystemctl poweroff --force\n', True)
  units = {
    "default.target": "[Unit]\nRequires=dbus.service systemd-logind.service test.service\n",
    "dbus.service": "[Unit]\nDefaultDependencies=no\nRequires=dbus.socket\nAfter=dbus.socket\n[Service]\nType=simple\nExecStart=/usr/bin/dbus-daemon --nofork --address=systemd: --systemd-activation --config-file=/etc/dbus-1/system.conf\n",
    "dbus.socket": "[Unit]\nDefaultDependencies=no\n[Socket]\nListenStream=/run/dbus/system_bus_socket\n",
    "systemd-logind.service": "[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=notify\nExecStart=/usr/lib/systemd/systemd-logind\nEnvironment=SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK=1\nRuntimeDirectory=systemd/sessions systemd/seats systemd/users systemd/inhibit systemd/shutdown\n",
    "test.service": "[Unit]\nDefaultDependencies=no\nAfter=systemd-logind.service\n[Service]\nType=simple\nExecStart=/run-test\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n",
    "systemd-hibernate.service": "[Unit]\nDefaultDependencies=no\nRequires=sleep.target\nAfter=sleep.target\n[Service]\nType=oneshot\nExecStart=/body\n",
    "hibernate.target": "[Unit]\nDefaultDependencies=no\nRequires=systemd-hibernate.service\nAfter=systemd-hibernate.service\nStopWhenUnneeded=yes\n",
    "sleep.target": "[Unit]\nDefaultDependencies=no\nRefuseManualStart=yes\nStopWhenUnneeded=yes\n",
  }
  for name, content in units.items():
    if name.endswith(".service") and name != "test.service":
      content += "StandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n"
    write("/etc/systemd/system/" + name, content)
  initrd = work / "initrd.img"
  with initrd.open("wb") as output:
    listed = subprocess.Popen(["find", ".", "-print0"], cwd=root, stdout=subprocess.PIPE)
    packed = subprocess.Popen(["cpio", "--null", "-o", "--format=newc", "--owner=0:0"], cwd=root, stdin=listed.stdout, stdout=output, stderr=subprocess.PIPE)
    listed.stdout.close()
    _, error = packed.communicate()
    if listed.wait() or packed.returncode:
      raise RuntimeError(error.decode())
  kernel = Path("/usr/lib/modules") / os.uname().release / "vmlinuz"
  with (work / "serial.log").open("wb") as log:
    result = subprocess.run(["timeout", "--kill-after=5s", "60s", "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "1024", "-nic", "none", "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-kernel", str(kernel), "-initrd", str(initrd), "-append", "console=ttyS0 rdinit=/init loglevel=3 systemd.log_target=console"], stdout=log, stderr=subprocess.STDOUT)
  text = (work / "serial.log").read_text(errors="replace")
  print(text[-18000:])
  if result.returncode or marker + "_PASS" not in text or marker + "_EXIT=0" not in text:
    raise SystemExit("Disposable logind proof failed; retained " + str(work))
  if args.maintenance_owner:
    print("PASS: guest-only actual owner-held logind FD and latched stop requests retained across original parent death, with explicit simulated safe release; no package/native admission")
  elif args.maintenance_alpm:
    print("PASS: real disposable pacman hook/transaction fixture under retained owner-held inhibitor; no host packages, native admission or reactivation proof")
  elif args.maintenance_recovery:
    print("PASS: guest-only integrated fixture maintenance, user scope settlement and exact veto recovery under retained real inhibitor/locks; no native admission or package action")
  elif args.maintenance_scope:
    print("PASS: guest-only held user phase placement, recursive descendant drain and preserved outside owner/sentinel; no package command or native admission")
  elif args.maintenance_entry:
    print("PASS: real guest sudo/inhibitor topology in both PTY modes and retained original-client update lock; synthetic NOPASSWD/PAM, no password/session admission or package/power operation")
  elif args.maintenance_handoff:
    print("PASS: guest-only nonroot-to-root authenticated update-lock OFD handoff, CLOEXEC and sender lifetime; no package command or native admission")
  elif args.maintenance_launcher:
    print("PASS: guest-only real privilege drop, held launcher readiness, inherited stdio/update-lock descriptor and actual child status; no package command or live admission")
  elif args.native_inhibitor:
    print("PASS: unchanged native exclusion/repeated guard, real owner rejection and FD release; not native activation or hardware S4")
  else:
    print("PASS: genuine logind block, delay release/timeout and failed-target lifecycle")


if __name__ == "__main__":
  main()
