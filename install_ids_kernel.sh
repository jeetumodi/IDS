#!/usr/bin/env bash
set -euo pipefail

# Beginner-safe installer for Linux 6.8 + IDS LSM
# Run as a normal user with sudo privileges.

KERNEL_DIR="${KERNEL_DIR:-$HOME/linux-6.8}"
LSM_ORDER="ids,lockdown,yama,integrity,apparmor,bpf"

log() {
  printf "[ids-setup] %s\n" "$*"
}

die() {
  printf "[ids-setup][error] %s\n" "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}

log "Checking required commands"
for c in sudo make gcc grep awk sed uname nproc; do
  require_cmd "$c"
done

log "Installing required Ubuntu packages"
sudo apt update
sudo apt install -y build-essential bc bison flex libncurses-dev libelf-dev libssl-dev dwarves zstd rsync git cpio kmod

[[ -d "$KERNEL_DIR" ]] || die "Kernel directory not found: $KERNEL_DIR"
cd "$KERNEL_DIR"

[[ -f "security/ids/ids_lsm.c" ]] || die "Missing security/ids/ids_lsm.c"
[[ -f "security/ids/Makefile" ]] || die "Missing security/ids/Makefile"

if ! grep -q 'SECURITY_IDS' security/Kconfig; then
  die "security/Kconfig does not define SECURITY_IDS"
fi
if ! grep -q 'obj-\$(CONFIG_SECURITY_IDS) += ids/' security/Makefile; then
  die "security/Makefile does not include ids/ build entry"
fi

log "Preparing kernel configuration"
cp "/boot/config-$(uname -r)" .config

if [[ ! -x scripts/config ]]; then
  die "scripts/config not found or not executable in $KERNEL_DIR"
fi

scripts/config --enable SECURITY_IDS
scripts/config --set-str LSM "$LSM_ORDER"
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str SYSTEM_REVOCATION_KEYS ""
make olddefconfig

log "Validating .config"
grep -E '^CONFIG_SECURITY_IDS=y' .config >/dev/null || die "CONFIG_SECURITY_IDS is not enabled"
grep -E '^CONFIG_LSM="ids,lockdown,yama,integrity,apparmor,bpf"' .config >/dev/null || die "CONFIG_LSM is not set correctly"
grep -E '^CONFIG_SYSTEM_TRUSTED_KEYS=""' .config >/dev/null || die "CONFIG_SYSTEM_TRUSTED_KEYS is not empty"
grep -E '^CONFIG_SYSTEM_REVOCATION_KEYS=""' .config >/dev/null || die "CONFIG_SYSTEM_REVOCATION_KEYS is not empty"

log "Building kernel (this may take a while)"
make -j"$(nproc)"

log "Installing modules and kernel"
sudo make modules_install
sudo make install

KREL="$(make -s kernelrelease)"
log "Kernel release built: $KREL"

sudo depmod -a "$KREL"
sudo update-initramfs -c -k "$KREL"
sudo update-grub

log "Done. Reboot and select kernel $KREL from GRUB Advanced options."
log "After boot, verify with: uname -r && cat /sys/kernel/security/lsm"
