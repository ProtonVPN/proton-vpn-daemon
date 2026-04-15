#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define ARGSIZE  256
#define MAXARG  128

enum event_type {
    EVENT_EXEC_ARG,
    EVENT_EXEC_RET,
    EVENT_CLONE,
    EVENT_EXIT
};

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);  // nosemgrep: raptor-incorrect-use-of-sizeof
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    data.uid = uid;

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.pid = task->pid;
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_EXEC_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    data.uid = uid;

    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.pid = task->pid;
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_EXEC_RET;
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

// Using the TRACEPOINT_PROBE macro to define the tracepoint.
// The arguments for this hook are defined in the macro.
// sched and sched_process_fork/sched_process_exit are the arguments to the
// macro itself and not part of the function signature.
//
// 'args' is the parameter given by the TRACEPOINT_PROBE macro and
// contains the fields defined in the tracepoint definition.
TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct data_t data = {};
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    data.uid = uid;
    data.pid = args->child_pid;
    data.ppid = args->parent_pid;
    data.type = EVENT_CLONE;
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct data_t data = {};
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    data.uid = uid;
    data.pid = args->pid;
    data.type = EVENT_EXIT;
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
