#!/usr/bin/python3
"""Check the upstream-model UKI builder's configuration, input policy and audit rules offline."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "upstream-model/build-upstream-model-uki.py"
spec = importlib.util.spec_from_file_location("upstream_model_builder", script)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
C = build.C


def rejects(action, expected, kind=ValueError):
  try:
    action()
  except kind as error:
    assert expected in str(error), error
  else:
    raise AssertionError("Unsafe builder input accepted: " + expected)


# Private configuration: stock sources with exactly the D1 and D2 deltas.
config = build.private_config()
assert "source /etc/mkinitcpio.conf\n" in config
assert "/etc/mkinitcpio.conf.d/*.conf" in config
assert config.count("MODULES+=(t2bce_audio)") == 1
assert config.count("HOOKS+=(" + C.HOOK + ")") == 1
assert "FILES" not in config and "omarchy-t2-restore-marker" not in config and "cold" not in config
assert "HOOKS=(" not in config
assert "/etc/" not in config.replace("/etc/mkinitcpio.conf", "")
subprocess.run(("bash", "-n", "/dev/stdin"), input=config.encode(), check=True)

# The build-time hook places the blacklist at its fixed destination and has no runtime script.
hook = build.INSTALL_HOOKS / C.HOOK
subprocess.run(("bash", "-n", hook), check=True)
assert "add_runscript" not in hook.read_text()
assert C.BLACKLIST_DESTINATION in hook.read_text()
assert not (build.INSTALL_HOOKS.parent / "hooks").exists()

# Blacklist file covers exactly the brcmfmac family and nothing else.
assert C.blacklist_names(C.blacklist_text()) == {"brcmfmac", "brcmfmac-bca", "brcmfmac-cyw", "brcmfmac-wcc"}
assert "hci_bcm4377" not in C.blacklist_text() and "t2bce" not in C.blacklist_text()

# The four patched modules are the whole t2bce family the builder pins; AVE is never included.
assert set(C.T2BCE_MODULES) == {"t2bce_dma", "t2bce_core", "t2bce_vhci", "t2bce_audio"}
assert "t2bce_ave" not in C.T2BCE_MODULES
assert "974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd" in C.REJECTED_IMAGE_SHA256

# Root-owned input policy (owner is injectable so the test can run unprivileged).
with tempfile.TemporaryDirectory(prefix="t2-upstream-builder-") as temporary:
  base = Path(temporary)
  tree = base / "candidate"
  tree.mkdir()
  (tree / "provenance.json").write_text("{}")
  owner = os.getuid()
  build.require_root_tree(tree, directory=True, owner=owner)
  rejects(lambda: build.require_root_tree(tree, directory=True), "root-owned")
  (tree / "link").symlink_to("provenance.json")
  rejects(lambda: build.require_root_tree(tree, directory=True, owner=owner), "symlinked")
  (tree / "link").unlink()
  (tree / "provenance.json").chmod(0o666)
  rejects(lambda: build.require_root_tree(tree, directory=True, owner=owner), "writable")
  (tree / "provenance.json").chmod(0o600)
  rejects(lambda: build.require_root_tree(base / "missing", directory=False, owner=owner), "", FileNotFoundError)

  # Candidate validation refuses unqualified provenance before any module is read.
  (tree / "provenance.json").write_text(json.dumps({"candidate_tests": "failed"}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "tests are not recorded")
  (tree / "provenance.json").write_text(json.dumps({"candidate_tests": "passed", "candidate_kernel_release": "other"}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "was not built for")
  (tree / "provenance.json").write_text(json.dumps({
    "candidate_tests": "passed", "candidate_kernel_release": "7.2.7-test", "installed": True, "hardware_qualified": False}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "lifecycle")
  (tree / "provenance.json").write_text(json.dumps({
    "candidate_tests": "passed", "candidate_kernel_release": "7.2.7-test", "installed": False, "hardware_qualified": False,
    "candidate_module_sha256": {}}))
  rejects(lambda: build.validate_candidate(tree, "7.2.7-test"), "Missing candidate module")

  # Pre-existing output directory is refused before anything is built.
  output = base / "out"
  output.mkdir()
  original_geteuid = build.os.geteuid
  build.os.geteuid = lambda: 0
  saved = sys.argv
  sys.argv = ["build", "--candidate-source", str(tree), "--output", str(output), "--experiment-id", "upstream-test"]
  try:
    rejects(build.main, "Output already exists")
    sys.argv = ["build", "--candidate-source", str(tree), "--output", str(base / "fresh"), "--experiment-id", "upstream-test"]
    rejects(build.main, "root-owned")
    assert not (base / "fresh").exists()
    sys.argv = ["build", "--candidate-source", str(tree), "--output", "/boot/EFI/Linux/new-output", "--experiment-id", "upstream-test"]
    rejects(build.main, "EFI or boot filesystem")
  finally:
    sys.argv = saved
    build.os.geteuid = original_geteuid

# Manifest diff: only the declared deltas pass.
release = "7.2.7-test-t2"
tree_path = "usr/lib/modules/" + release + "/"
stem = tree_path + "kernel/drivers/staging/t2bce/"
production = {
  "init": "file:aa:755",
  "config": "x",
  tree_path + "modules.dep.bin": "file:01:644",
  stem + "t2bce_core/t2bce_core.ko.zst": "file:old1:644",
  stem + "t2bce_dma/t2bce_dma.ko.zst": "file:old2:644",
  stem + "t2bce_vhci/t2bce_vhci.ko.zst": "file:old3:644",
  "etc/modprobe.d/brcmfmac.conf": "file:bb:644",
}
prod_config = 'MODULES="t2bce_vhci hid_apple"\nHOOKS="udev encrypt resume"\nEARLYHOOKS="udev"\nLATEHOOKS="plymouth"\nCLEANUPHOOKS="udev"\nEMERGENCYHOOKS="plymouth"\n'
cand_config = prod_config.replace('MODULES="t2bce_vhci hid_apple"', 'MODULES="t2bce_vhci hid_apple t2bce_audio"')
audio = stem + "t2bce_audio/t2bce_audio.ko"
snd = tree_path + "kernel/sound/core/snd-pcm.ko"
candidate = {key: value for key, value in production.items() if not key.endswith(".ko.zst")}
candidate.update({
  tree_path + "modules.dep.bin": "file:02:644",
  stem + "t2bce_core/t2bce_core.ko": "file:new1:644",
  stem + "t2bce_dma/t2bce_dma.ko": "file:new2:644",
  stem + "t2bce_vhci/t2bce_vhci.ko": "file:new3:644",
  audio: "file:new4:644", snd: "file:snd:644", C.BLACKLIST_DESTINATION: "file:cc:644",
  "config": "y", "buildconfig": "z",
})
candidate_with_buildconfig = dict(candidate)
production_with_buildconfig = dict(production)
production_with_buildconfig["buildconfig"] = "a"


def diff(candidate_manifest=candidate_with_buildconfig, production_manifest=production_with_buildconfig, **overrides):
  options = {"dependencies": ["/" + audio, "/" + snd], "production_config": prod_config, "candidate_config": cand_config}
  options.update(overrides)
  return build.manifest_diff(production_manifest, candidate_manifest, release, **options)


report = diff()
assert len(report["removed"]) == 3 and audio in report["added"] and C.BLACKLIST_DESTINATION in report["added"]
assert stem + "t2bce_core/t2bce_core.ko" in report["added"] and stem + "t2bce_core/t2bce_core.ko.zst" in report["removed"]

def mutated(**changes):
  value = dict(candidate_with_buildconfig)
  for key, item in changes.items():
    value[key.replace("__", "/")] = item
  return value

rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "init": "file:ab:755"}), "changed: init")
rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "hooks/omarchy-t2-restore-marker": "file:dd:755"}), "added: hooks/omarchy-t2-restore-marker")
rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "usr/bin/extra": "file:dd:755"}), "added: usr/bin/extra")
rejects(lambda: diff(candidate_manifest={key: value for key, value in candidate_with_buildconfig.items() if key != "etc/modprobe.d/brcmfmac.conf"}), "removed: etc/modprobe.d/brcmfmac.conf")
rejects(lambda: diff(candidate_config=cand_config.replace('HOOKS="udev encrypt resume"', 'HOOKS="udev encrypt omarchy-t2-restore-marker resume"')), "HOOKS differs")
rejects(lambda: diff(candidate_config=cand_config.replace("t2bce_audio", "brcmfmac")), "MODULES differs")
rejects(lambda: diff(candidate_config=cand_config.replace('MODULES="t2bce_vhci hid_apple t2bce_audio"', 'MODULES="t2bce_vhci"')), "MODULES differs")
rejects(lambda: diff(candidate_manifest={**candidate_with_buildconfig, "usr/lib/omarchy-t2-restore-marker/marker.ko": "file:dd:600"}, dependencies=["/usr/lib/omarchy-t2-restore-marker/marker.ko"]), "marker/guard-like")
rejects(lambda: diff(dependencies=["/" + audio]), "added: " + snd)

# modprobe --dirname reports /lib/modules paths below the extracted tree; they normalise to usr/lib.
extracted = Path("/tmp/x/initrd-root")
lib = str(extracted) + "/lib/modules/" + release + "/"
assert build.normalize_dependencies([lib + "kernel/sound/core/snd-pcm.ko"], extracted) == ["/" + snd]
assert diff(dependencies=build.normalize_dependencies([lib + "kernel/sound/core/snd-pcm.ko", lib + "kernel/drivers/staging/t2bce/t2bce_audio/t2bce_audio.ko"], extracted))
# A stray .ko.zst removal, or a removal without its matching .ko, is refused.
rejects(lambda: diff(production_manifest={**production_with_buildconfig, tree_path + "kernel/fs/x.ko.zst": "file:q:644"}), "removed: " + tree_path + "kernel/fs/x.ko.zst")
rejects(lambda: diff(production_manifest={**production_with_buildconfig, stem + "t2bce_ave/t2bce_ave.ko.zst": "file:a:644"}), "t2bce_ave.ko.zst")
rejects(lambda: diff(candidate_manifest={key: value for key, value in candidate_with_buildconfig.items() if key != stem + "t2bce_dma/t2bce_dma.ko"}), "removed: " + stem + "t2bce_dma/t2bce_dma.ko.zst")

# Build arrays equal stock plus exactly the declared deltas.
with tempfile.TemporaryDirectory(prefix="t2-upstream-arrays-") as temporary:
  stock_file, private_file = Path(temporary) / "stock.conf", Path(temporary) / "private.conf"
  stock_file.write_text("HOOKS=(base udev)\nFILES=(/a)\nBINARIES=()\nMODULES=(m1)\n")
  good = stock_file.read_text() + "MODULES+=(t2bce_audio)\nHOOKS+=(" + C.HOOK + ")\n"
  private_file.write_text(good)
  assert build.audit_config(private_file, stock_file)["modules"] == ["m1", "t2bce_audio"]
  for extra, expected in (("FILES+=(/b)\n", "FILES"), ("BINARIES+=(x)\n", "BINARIES"), ("HOOKS+=(evil)\n", "HOOKS"), ("MODULES+=(brcmfmac)\n", "MODULES")):
    private_file.write_text(good + extra)
    rejects(lambda: build.audit_config(private_file, stock_file), expected)


# verify_blacklist and module counts against the REAL production shape (derived from the production
# initramfs file list): brcmfmac family, cfg80211 and brcmutil are present as .ko.zst, plus ~370 other modules.
def real_tree(root, wifi=True, count=370, brcmfmac=True):
  base = root / "usr/lib/modules" / release
  names = ["kernel/drivers/net/wireless/broadcom/brcm80211/brcmutil/brcmutil.ko.zst", "kernel/net/wireless/cfg80211.ko.zst"]
  if brcmfmac:
    names += ["updates/dkms/" + name + ".ko.zst" for name in ("brcmfmac", "brcmfmac-bca", "brcmfmac-cyw", "brcmfmac-wcc")]
  if not wifi:
    names = []
  names += ["kernel/fs/m%03d.ko.zst" % index for index in range(count)]
  for name in names:
    (base / name).parent.mkdir(parents=True, exist_ok=True)
    (base / name).write_bytes(b"")
  (root / "etc/modprobe.d").mkdir(parents=True, exist_ok=True)
  (root / "etc/modprobe.d/brcmfmac.conf").write_text("options brcmfmac feature_disable=0x82000\n")
  return root


def kmod(honours_blacklist=True, resolves=True):
  """Fake of modprobe alias resolution: kmod applies blacklist entries to alias lookups."""
  def resolve(extracted, release_, config, use_blacklist=False):
    blacklisted = (Path(config) / Path(C.BLACKLIST_DESTINATION).name).exists()
    if not resolves or (blacklisted and honours_blacklist):
      return ""
    return "insmod /lib/modules/" + release_ + "/updates/dkms/brcmfmac.ko.zst\n"
  return resolve


with tempfile.TemporaryDirectory(prefix="t2-upstream-realshape-") as temporary:
  base = Path(temporary)
  real_resolve = build.resolve_alias

  def trees(**candidate_options):
    production = real_tree(base / ("p" + str(len(list(base.iterdir())))))
    extracted = real_tree(base / ("c" + str(len(list(base.iterdir())))), **candidate_options)
    (extracted / C.BLACKLIST_DESTINATION).write_text(C.blacklist_text())
    return production, extracted

  production, extracted = trees()
  build.resolve_alias = kmod()
  try:
    report = build.verify_blacklist(extracted, release, production)
    assert report["brcmfmac_in_initramfs"] is True and len(report["wifi_module_files"]) == 6
    # The unblacklisted probe must not see our blacklist file (kmod applies it to aliases even without -b).
    seen = []
    build.resolve_alias = lambda extracted_, release_, config, use_blacklist=False: (seen.append((Path(config) / "zz-omarchy-t2-upstream-model.conf").exists()), kmod()(extracted_, release_, config, use_blacklist))[1]
    build.verify_blacklist(extracted, release, production)
    assert seen[0] is False and seen[1] is True
    # Never vacuous.
    build.resolve_alias = kmod(resolves=False)
    rejects(lambda: build.verify_blacklist(extracted, release, production), "even without the blacklist")
    build.resolve_alias = kmod(honours_blacklist=False)
    rejects(lambda: build.verify_blacklist(extracted, release, production), "still load brcmfmac")
    build.resolve_alias = kmod()
    empty_production = real_tree(base / "empty-production", wifi=False)
    rejects(lambda: build.verify_blacklist(extracted, release, empty_production), "extraction is incomplete")
    _, stripped = trees(wifi=False)
    (stripped / C.BLACKLIST_DESTINATION).write_text(C.blacklist_text())
    rejects(lambda: build.verify_blacklist(stripped, release, production), "differ from production")
    no_brcm_p, no_brcm_c = trees(brcmfmac=False)
    rejects(lambda: build.verify_blacklist(no_brcm_c, release, no_brcm_p), "differ from production")
    __import__("shutil").rmtree(no_brcm_p / "usr/lib/modules" / release / "updates")
    rejects(lambda: build.verify_blacklist(no_brcm_c, release, no_brcm_p), "vacuous")
    (extracted / C.BLACKLIST_DESTINATION).write_text("blacklist brcmfmac\n")
    rejects(lambda: build.verify_blacklist(extracted, release, production), "missing or incomplete")
  finally:
    build.resolve_alias = real_resolve

  # Module counts: complete extraction follows production through the declared delta.
  production, extracted = trees()
  tree = extracted / "usr/lib/modules" / release / "kernel/drivers/staging/t2bce"
  for name in ("t2bce_dma", "t2bce_core", "t2bce_vhci"):
    (production / "usr/lib/modules" / release / "kernel/drivers/staging/t2bce" / name).mkdir(parents=True)
    (production / "usr/lib/modules" / release / "kernel/drivers/staging/t2bce" / name / (name + ".ko.zst")).write_bytes(b"")
    (tree / name).mkdir(parents=True)
    (tree / name / (name + ".ko")).write_bytes(b"")
  (tree / "t2bce_audio").mkdir()
  (tree / "t2bce_audio/t2bce_audio.ko").write_bytes(b"")
  stem = "usr/lib/modules/" + release + "/kernel/drivers/staging/t2bce/"
  removed = [stem + name + "/" + name + ".ko.zst" for name in ("t2bce_dma", "t2bce_core", "t2bce_vhci")]
  added = [stem + name + "/" + name + ".ko" for name in ("t2bce_dma", "t2bce_core", "t2bce_vhci", "t2bce_audio")]
  assert build.verify_module_counts(production, extracted, release, removed, added) == {"production": 379, "candidate": 380}
  rejects(lambda: build.verify_module_counts(production, extracted, release, removed, added[:-1]), "count differs")
  (tree / "t2bce_audio/t2bce_audio.ko").unlink()
  rejects(lambda: build.verify_module_counts(production, extracted, release, removed, added), "count differs")
  tiny = real_tree(base / "tiny", count=3)
  rejects(lambda: build.verify_module_counts(tiny, tiny, release, [], []), "count differs")


# Inherited umask: main() runs with umask 077, but stock tools must create files with production's 0644.
with tempfile.TemporaryDirectory(prefix="t2-upstream-umask-") as temporary:
  work = Path(temporary)
  old_umask = os.umask(0o077)
  try:
    build.BASE.run(("sh", "-c", "touch inherited"), cwd=work)
    build.run_stock(("sh", "-c", "touch stock; mkdir stockdir"), cwd=work)
    assert os.umask(0o077) == 0o077, "run_stock must not change the parent's umask"
  finally:
    os.umask(old_umask)
  assert (work / "inherited").stat().st_mode & 0o777 == 0o600
  assert (work / "stock").stat().st_mode & 0o777 == 0o644 and (work / "stockdir").stat().st_mode & 0o777 == 0o755
  # The mode comparison stays strict: a 0600 file is still a difference from production's 0644.
  rejects(lambda: build.manifest_diff({"VERSION": "file:aa:644", **production_with_buildconfig}, {"VERSION": "file:aa:600", **candidate_with_buildconfig}, release,
                                      dependencies=["/" + audio, "/" + snd], production_config=prod_config, candidate_config=cand_config), "changed: VERSION")
  source = (package / "upstream-model/build-upstream-model-uki.py").read_text()
  assert "BASE.run(" not in source.replace("BASE.run with", "")

# Build configuration values parse the runtime `config` file only.
assert build.config_values(cand_config)["MODULES"] == ["t2bce_vhci", "hid_apple", "t2bce_audio"]

print("PASS: upstream-model builder enforces stock configuration deltas, root-owned inputs and manifest audit")
