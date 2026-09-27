#!/usr/bin/python3
"""Real logind lifecycle proof in a disposable, networkless QEMU guest.

Copies only installed public executables/libraries; no host configuration,
private initramfs, EFI, modules or power interfaces are changed. The guest
hibernate body records entry and exits; it cannot invoke systemd-sleep.
Guest logind alone bypasses its swap-space check to admit the stub body.
This tests notifications and inhibitor lifecycle, not hardware hibernation.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

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
  work = Path(tempfile.mkdtemp(prefix="mba-logind-vm-"))
  root = work / "root"
  root.mkdir()
  print(f"Disposable guest evidence: {work}", flush=True)
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
  write("/etc/nsswitch.conf", "passwd: files\ngroup: files\n")
  write("/etc/os-release", "ID=arch\nNAME=Disposable-logind-test\n")
  write("/etc/machine-id", "1f0bb75b22c4490b968b906528b141b4\n")
  write("/etc/dbus-1/system.conf", '<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>\n')
  write("/etc/systemd/logind.conf", "[Login]\nInhibitDelayMaxSec=3\nHandlePowerKey=ignore\nHandleSuspendKey=ignore\nHandleHibernateKey=ignore\nHandleLidSwitch=ignore\n")
  write("/init", "#!/bin/bash\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\nmkdir -p /run/dbus\nexec /usr/lib/systemd/systemd --system\n", True)
  write("/body", '#!/bin/bash\necho "BODY ENTER" >/dev/console\ntouch /run/body\nif [[ -e /run/fail ]]; then exit 1; fi\nexit 0\n', True)
  write("/run-test", '#!/bin/bash\nsleep 2\n/test\nresult=$?\necho "LOGIND_VM_EXIT=$result" >/dev/console\nsystemctl poweroff --force\n', True)
  units = {
    "default.target": "[Unit]\nRequires=dbus.service systemd-logind.service test.service\n",
    "dbus.service": "[Unit]\nDefaultDependencies=no\nRequires=dbus.socket\nAfter=dbus.socket\n[Service]\nType=simple\nExecStart=/usr/bin/dbus-daemon --nofork --address=systemd: --systemd-activation --config-file=/etc/dbus-1/system.conf\n",
    "dbus.socket": "[Unit]\nDefaultDependencies=no\n[Socket]\nListenStream=/run/dbus/system_bus_socket\n",
    "systemd-logind.service": "[Unit]\nDefaultDependencies=no\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=notify\nExecStart=/usr/lib/systemd/systemd-logind\nEnvironment=SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK=1\nRuntimeDirectory=systemd/sessions systemd/seats systemd/users systemd/inhibit systemd/shutdown\n",
    "test.service": "[Unit]\nDefaultDependencies=no\nAfter=systemd-logind.service\n[Service]\nExecStart=/run-test\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n",
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
  if result.returncode or "LOGIND_VM_PASS" not in text or "LOGIND_VM_EXIT=0" not in text:
    raise SystemExit("Disposable logind proof failed; retained " + str(work))
  print("PASS: genuine logind block, delay release/timeout and failed-target lifecycle")


if __name__ == "__main__":
  main()
