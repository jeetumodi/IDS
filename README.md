# IDS LSM Project (Beginner Friendly)

This project shows how to add a custom IDS (Intrusion Detection System) using Linux Security Module (LSM) hooks in Linux 6.8.

It is written so a first-year student can set it up from zero.

## 1) What is IDS and what is LSM?

- IDS: A system that watches activity and reports suspicious behavior.
- LSM: A Linux kernel framework where security modules can attach hooks at sensitive points, like file open, exec, and ptrace.

In this project:
- `ids_lsm.c` registers custom LSM hooks.
- The hooks log events to a kernel buffer.
- Logs are exposed through `/proc/ids_monitor`.
- `ids_monitor.c` is an optional terminal UI to display those logs.

Important:
- This IDS is built into the kernel image, not loaded as a separate module.
- So you verify with `/sys/kernel/security/lsm`, not `lsmod`.

## 2) What files are in this repo?

- `security/ids/ids_lsm.c`: IDS LSM source code
- `security/ids/Makefile`: build file for IDS source
- `security/Kconfig`: adds `CONFIG_SECURITY_IDS`
- `security/Makefile`: includes `ids/` in security build
- `install_ids_kernel.sh`: setup automation script
- `ids_monitor.c`: optional ncurses userspace monitor

## 3) Full setup from cloning the repo

### Step A: Clone this project

```bash
cd ~
git clone <your-github-repo-url> ids-lsm-share
cd ids-lsm-share
```

### Step B: Get Linux 6.8 source (required)

This repo contains IDS files, not the full Linux source tree. Download Linux 6.8 separately:

```bash
cd ~
git clone --depth 1 --branch v6.8 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux-6.8
```

### Step C: Copy IDS files into Linux source tree

```bash
cd ~/ids-lsm-share
mkdir -p ~/linux-6.8/security/ids

cp security/ids/ids_lsm.c ~/linux-6.8/security/ids/
cp security/ids/Makefile ~/linux-6.8/security/ids/
cp security/Kconfig ~/linux-6.8/security/Kconfig
cp security/Makefile ~/linux-6.8/security/Makefile
```

### Step D: Run automatic setup (recommended)

Use the installer script from this repo. It installs dependencies, configures kernel options, builds, installs, and updates GRUB:

```bash
cd ~/ids-lsm-share
chmod +x ./install_ids_kernel.sh
KERNEL_DIR=~/linux-6.8 ./install_ids_kernel.sh
```

### Step E: Reboot and select custom kernel

```bash
sudo reboot
```

In GRUB Advanced options, select the new custom kernel once.

## 4) Verify IDS is active

After boot:

```bash
uname -r
cat /sys/kernel/security/lsm
cat /proc/ids_monitor
```

Expected:
- Kernel version shows your newly built kernel release.
- `ids` appears in `/sys/kernel/security/lsm`.
- `/proc/ids_monitor` exists and shows logs (or empty stream initially).

## 5) Optional: run terminal monitor UI

```bash
cd ~/ids-lsm-share
gcc ids_monitor.c -o ids_monitor -lncurses
./ids_monitor
```

## 6) What should you test?

Generate a few actions and re-check logs:

```bash
cat /etc/shadow >/dev/null
sh -c 'echo test'
cat /proc/ids_monitor
```

If IDS is working, new log lines should appear.

## 7) Common mistakes

- Setting `CONFIG_LSM` only in shell does nothing unless written in `.config`.
- Using smart quotes instead of normal quotes in config values.
- Trying to verify with `lsmod` for a built-in LSM.
- Forgetting to boot the newly installed kernel from GRUB.

## 8) If system does not boot custom kernel

1. Reboot and choose older working kernel from GRUB Advanced options.
2. Rebuild initramfs for the custom kernel:

```bash
cd ~/linux-6.8
sudo depmod -a "$(make -s kernelrelease)"
sudo update-initramfs -u -k "$(make -s kernelrelease)"
sudo update-grub
```

3. Reboot and try custom kernel again.

## 9) Sharing best practice

Push only source changes and scripts from this repo.
Do not push full compiled kernel artifacts (`vmlinux`, `*.o`, `*.ko`, etc.).
