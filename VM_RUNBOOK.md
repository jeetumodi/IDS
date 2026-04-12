# IDS Kernel Runbook (Beginner-Safe)

This guide is written so a new user can follow it end-to-end on Ubuntu and avoid common failures.

Scope:
- Build Linux 6.8 with built-in IDS LSM under security/ids
- Boot the custom kernel safely
- Verify IDS is active
- Recover quickly if boot fails

Quick start for most users:

chmod +x ~/install_ids_kernel.sh
~/install_ids_kernel.sh

Then reboot, select the new kernel in GRUB advanced options, and verify:

uname -r
cat /sys/kernel/security/lsm

Important:
- IDS here is an LSM built into the kernel image, not a loadable module
- Do not verify it with lsmod or /proc/modules

## 1) Prerequisites

Run on Ubuntu VM:

sudo apt update
sudo apt install -y build-essential bc bison flex libncurses-dev libelf-dev libssl-dev dwarves zstd rsync git cpio kmod

Optional but recommended disk check (kernel builds are large):

df -h /

## 2) Get source

Option A (recommended for sharing work): clone kernel git tag

cd ~
git clone --depth 1 --branch v6.8 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux-6.8
cd linux-6.8

Option B (tarball):

cd ~
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz
tar -xf linux-6.8.tar.xz
cd linux-6.8

## 3) Apply IDS files

Ensure these files exist:
- security/ids/ids_lsm.c
- security/ids/Makefile

Ensure these references exist:
- security/Makefile includes: obj-$(CONFIG_SECURITY_IDS) += ids/
- security/Kconfig defines: config SECURITY_IDS

## 4) Configure kernel correctly

Start from current running config:

cp /boot/config-$(uname -r) .config

Set required options:

scripts/config --enable SECURITY_IDS
scripts/config --set-str LSM "ids,lockdown,yama,integrity,apparmor,bpf"
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str SYSTEM_REVOCATION_KEYS ""
make olddefconfig

Verify config (must match):

grep -E '^CONFIG_SECURITY_IDS=y' .config
grep -E '^CONFIG_LSM="ids,lockdown,yama,integrity,apparmor,bpf"' .config
grep -E '^CONFIG_SYSTEM_TRUSTED_KEYS=""' .config
grep -E '^CONFIG_SYSTEM_REVOCATION_KEYS=""' .config

## 5) Build and install

make -j"$(nproc)"
sudo make modules_install
sudo make install
sudo depmod -a "$(make -s kernelrelease)"
sudo update-initramfs -c -k "$(make -s kernelrelease)"
sudo update-grub

## 6) Reboot and select new kernel

sudo reboot

In GRUB advanced options, pick the newly installed 6.8 kernel once.

After boot:

uname -r
cat /sys/kernel/security/lsm

Expected:
- uname shows your custom 6.8 kernel
- ids appears in /sys/kernel/security/lsm

## 7) Verify IDS telemetry

If your ids_lsm.c creates proc output, check it:

cat /proc/ids_monitor

Generate test events:

cat /etc/shadow >/dev/null
/tmp/test_exec 2>/dev/null || true

Read telemetry again:

cat /proc/ids_monitor

## 8) Build userspace monitor (optional)

If monitor source is in ids_monitor/ids_monitor.c:

cd ~/ids_monitor
gcc ids_monitor.c -o ids_monitor -lncurses
./ids_monitor

## 9) If boot fails (initramfs or panic)

Recovery flow:
1. Reboot and choose older known-good Ubuntu kernel in GRUB advanced options
2. Confirm root filesystem UUID:

blkid
cat /etc/fstab
cat /proc/cmdline

3. Rebuild initramfs for custom kernel:

cd ~/linux-6.8
sudo depmod -a "$(make -s kernelrelease)"
sudo update-initramfs -u -k "$(make -s kernelrelease)"
sudo update-grub

4. Reboot and try custom kernel again

## 10) Best way to share so anyone can use it

Do this in git:
1. Keep upstream Linux separate
2. Commit only your IDS delta (security/ids/* and touched Kconfig/Makefile lines)
3. Add this runbook at repo root
4. Optionally export patches:

git format-patch -1

Why this is best:
- small, reviewable changes
- avoids uploading huge build artifacts
- reproducible by others on clean Ubuntu VMs