// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/stdarg.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/errno.h>
#include <linux/mm.h>           /* for __get_free_page / free_page */

#define IDS_NAME     "ids"
#define IDS_MAX_LOGS 128
#define IDS_LOG_LEN  256

/* ---------------- LSM ID ---------------- */
static struct lsm_id ids_lsmid = {
    .name = IDS_NAME,
    .id   = LSM_ID_UNDEF,       /* required in kernel >= 6.8 */
};

/* ---------------- LOG BUFFER ---------------- */
static char ids_logs[IDS_MAX_LOGS][IDS_LOG_LEN];
static atomic_t log_index = ATOMIC_INIT(0);

/* ---------------- LOG FUNCTION ---------------- */
static void ids_log_event(const char *fmt, ...)
{
    va_list args;
    int idx;

    if (!current)
        return;

    /*
     * atomic_fetch_add returns the OLD value and increments atomically.
     * Each CPU gets a unique slot even under SMP — no races.
     */
    idx = atomic_fetch_add(1, &log_index) % IDS_MAX_LOGS;

    va_start(args, fmt);
    vsnprintf(ids_logs[idx], IDS_LOG_LEN, fmt, args);
    va_end(args);
}

/* ---------------- /proc READ ---------------- */
static int ids_proc_show(struct seq_file *m, void *v)
{
    int total = atomic_read(&log_index);
    int count = min(total, IDS_MAX_LOGS);
    /*
     * If the ring has wrapped, oldest slot is at (total % IDS_MAX_LOGS).
     * If not wrapped, oldest is slot 0.
     */
    int start = (total > IDS_MAX_LOGS) ? (total % IDS_MAX_LOGS) : 0;
    int i;

    for (i = 0; i < count; i++) {
        int slot = (start + i) % IDS_MAX_LOGS;
        if (ids_logs[slot][0] != '\0')
            seq_printf(m, "%s\n", ids_logs[slot]);
    }
    return 0;
}

static int ids_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, ids_proc_show, NULL);
}

static const struct proc_ops ids_proc_ops = {
    .proc_open    = ids_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ================================================================
 * HOOK 1 — EXEC (context-aware, multi-factor)
 * collect_context() → apply_rules() → decide()
 * ================================================================ */
static int ids_bprm_check(struct linux_binprm *bprm)
{
    /* --- collect_context() --- */
    const char *fname = bprm->filename;
    kuid_t      uid   = current_uid();
    pid_t       pid   = current->pid;
    /*
     * current->comm is a 16-byte kernel buffer — safe to read directly.
     * Do NOT free it. Do NOT store a pointer beyond this stack frame.
     */
    const char *proc  = current->comm;
    int suspicious    = 0;

    /* --- apply_rules() --- */

    /* RULE 1: execution from /tmp — classic malware staging area */
    if (strstr(fname, "/tmp/")) {
        suspicious = 1;
        ids_log_event("[RULE] TMP_EXEC pid=%d uid=%u file=%s",
                      pid, __kuid_val(uid), fname);
    }

    /* RULE 2: reverse shell tools */
    if (strstr(fname, "nc") || strstr(fname, "netcat")) {
        suspicious = 1;
        ids_log_event("[RULE] REVERSE_SHELL pid=%d uid=%u file=%s",
                      pid, __kuid_val(uid), fname);
    }

    /*
     * RULE 3: shell spawned by non-root.
     * Note: strstr on fname for "bash"/"sh" can match paths like
     * /usr/share/bash-completion — this is acceptable for an IDS
     * (log/alert, not block). If you later enable -EPERM here,
     * tighten this check with kbasename(fname) first.
     */
    if ((strstr(fname, "bash") || strstr(fname, "sh")) &&
        !uid_eq(uid, GLOBAL_ROOT_UID)) {
        suspicious = 1;
        ids_log_event("[RULE] NONROOT_SHELL pid=%d uid=%u file=%s",
                      pid, __kuid_val(uid), fname);
    }

    /* --- decide() --- */
    if (suspicious) {
        ids_log_event("[ALERT] EXEC pid=%d cmd=%s uid=%u file=%s",
                      pid, proc, __kuid_val(uid), fname);
        /*
         * To block instead of just alert, uncomment:
         * return -EPERM;
         */
    }

    return 0;
}

/* ================================================================
 * HOOK 2 — FILE OPEN (smart filtered — only unauthorized access)
 * collect_context() → apply_rules() → decide()
 * ================================================================ */
static int ids_file_open(struct file *file)
{
    char   *tmp;
    char   *path;
    kuid_t  uid;

    /* --- collect_context() --- */
    if (!file)
        return 0;

    uid = current_uid();

    /*
     * Use __get_free_page instead of a stack buffer.
     * Stack in kernel hooks is limited (~4-8KB); PAGE_SIZE (4096)
     * on the stack would risk a stack overflow under deep call chains.
     *
     * GFP_ATOMIC: we may be in an atomic/interrupt context here.
     * GFP_KERNEL would be wrong for LSM hooks — it can sleep,
     * and file_open can be called from non-sleepable contexts.
     *
     * SAFETY: always paired with free_page() before every return.
     */
    tmp = (char *)__get_free_page(GFP_ATOMIC);
    if (!tmp)
        return 0;   /* fail open — safer than crashing */

    path = d_path(&file->f_path, tmp, PAGE_SIZE);

    /* --- apply_rules() + decide() --- */
    if (!IS_ERR(path)) {
        /*
         * RULE: sensitive file access by non-root only.
         * Avoids log spam from legitimate root daemons.
         */
        if ((strstr(path, "/etc/shadow") ||
             strstr(path, "/etc/sudoers")) &&
            !uid_eq(uid, GLOBAL_ROOT_UID)) {
            ids_log_event(
                "[ALERT] SENSITIVE_FILE pid=%d cmd=%s uid=%u file=%s",
                current->pid,
                current->comm,
                __kuid_val(uid),
                path);
        }
    }

    /* Always free before returning — no early-return without this */
    free_page((unsigned long)tmp);
    return 0;
}

/* ================================================================
 * HOOK 3 — PTRACE (smart: allow same-user debug, block cross-user)
 * collect_context() → apply_rules() → decide()
 * ================================================================ */
static int ids_ptrace(struct task_struct *child, unsigned int mode)
{
    /* --- collect_context() --- */
    if (!child)
        return 0;

    /* --- apply_rules() + decide() --- */
    /*
     * RULE: cross-user ptrace is a known privilege escalation vector.
     * Allow same-user debugging (e.g. gdb), block everything else.
     */
    if (!uid_eq(current_uid(), task_uid(child))) {
        ids_log_event(
            "[ALERT] PTRACE_BLOCKED attacker_pid=%d target_pid=%d cmd=%s",
            current->pid,
            child->pid,
            current->comm);
        return -EPERM;  /* block — this is active defence */
    }

    return 0;
}

/* ---------------- HOOK LIST ---------------- */
static struct security_hook_list ids_hooks[] = {
    LSM_HOOK_INIT(file_open,           ids_file_open),
    LSM_HOOK_INIT(bprm_check_security, ids_bprm_check),
    LSM_HOOK_INIT(ptrace_access_check, ids_ptrace),
};

/* ---------------- LSM INIT (early — no proc here) ---------------- */
static int __init ids_init(void)
{
    pr_info("[IDS] Initializing...\n");
    security_add_hooks(ids_hooks,
                       ARRAY_SIZE(ids_hooks),
                       &ids_lsmid);
    /*
     * proc_create() is intentionally NOT called here.
     * procfs is not initialized at LSM init time.
     * It is registered below via fs_initcall instead.
     */
    pr_info("[IDS] Hooks registered\n");
    return 0;
}

/* ---------------- PROC INIT (deferred — after procfs is ready) --- */
static int __init ids_proc_init(void)
{
    if (!proc_create("ids_monitor", 0, NULL, &ids_proc_ops)) {
        pr_err("[IDS] Failed to create /proc/ids_monitor\n");
        return -ENOMEM;
    }
    pr_info("[IDS] /proc/ids_monitor ready\n");
    return 0;
}
fs_initcall(ids_proc_init);  /* runs after VFS/procfs is fully up */

/* ---------------- REGISTER ---------------- */
DEFINE_LSM(ids) = {
    .name = IDS_NAME,
    .init = ids_init,
};