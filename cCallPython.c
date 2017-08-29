#include <sys/ptrace.h>  
#include <sys/types.h>  
#include <sys/wait.h>  
#include <unistd.h>
#include <errno.h>
//#include <linux/user.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/reg.h>
#include <asm-generic/errno.h>

static void process_signals(pid_t child);
static int wait_for_open(pid_t child);
static void read_file(pid_t child, char *file);
static void redirect_file(pid_t child, const char *file);
register void* rdi __asm__("rdi");
register void* rsi __asm__("rsi");
register void* rdx __asm__("rdx");
register void* rcx __asm__("rcx");
register void* rax __asm__("rax");
//register void* rbp __asm__("rbp");
register void* edi __asm__("edi");
register void* edx __asm__("edx");

#define PATH_MAX 100
struct user_regs_struct regs;

/* Function prototypes with attributes */
void main_constructor(void)
        __attribute__ ((no_instrument_function, constructor));

void main_destructor(void)
        __attribute__ ((no_instrument_function, destructor));

void __cyg_profile_func_enter(void *, void *)
        __attribute__ ((no_instrument_function));

void __cyg_profile_func_exit(void *, void *)
        __attribute__ ((no_instrument_function));

void main_constructor(void) {

}

void main_destructor(void) {

}

void __cyg_profile_func_enter(void *this, void *callsite) {

}

void __cyg_profile_func_exit(void *this, void *callsite) {

}

int func23(int parm, char* a, int p2)
{
    int out;
    void *b;
    //__asm__ ("mov %%s1, 4");
    //__asm__ ("mov %1, %0": "=r" (b):  "r" (a));
    return out;
}
//int func23(int p1, char * a)
//{
//    unsigned out = 25;
//    asm ("mul %1": "+a" (out) : "g" (p1) : "%rdx", "cc");
//    return out;
//}
int f1 (char *a) {
    char *child_addr;
    int i;
    //rdi first argument
    child_addr = (char *) ptrace(PTRACE_PEEKUSER, getpid(), sizeof(long)*RDI, 0);
    return 1;
}
int main(int argc, char **argv)
{
    pid_t pid;
    int status;


//    if (argc < 2) {
//        fprintf(stderr, "Usage: %s <prog> <arg1> ... <argN>\n", argv[0]);
//        return 1;
//    }

//    if ((pid = fork()) == 0) {
//        ptrace(PTRACE_TRACEME, 0, 0, 0);
//        printf("1: %d\n", getpid());
//        printf("2: %d\n", pid);
//
//        kill(getpid(), SIGSTOP);
//        return execvp(argv[1], argv + 1);
//    } else {
//        waitpid(pid, &status, 0);
//        printf("3: %d\n", getpid());
//        printf("4: %d\n", pid);
//
//        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
//        process_signals(pid);
//        return 0;
//    }

    if (ptrace(PTRACE_TRACEME, getpid(), 0, 0) != 0) {
        printf("Failed ---> %s\n", strerror(errno));
    }
    char* a = malloc(6* sizeof(char));
//    //a = "fffff";
    f1(a);
    return 0;
}

static void process_signals(pid_t child)
{
    const char *file_to_redirect = "ONE.txt";
    const char *file_to_avoid = "TWO.txt";

    while(1) {
        char orig_file[PATH_MAX];

        /* Wait for open syscall start */
        if (wait_for_open(child) != 0) break;

        /* Find out file and re-direct if it is the target */

        read_file(child, orig_file);

        if (strcmp(file_to_avoid, orig_file) == 0)
            redirect_file(child, file_to_redirect);

        /* Wait for open syscall exit */
        if (wait_for_open(child) != 0) break;
    }
}

static int wait_for_open(pid_t child)
{
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        /* Is it the open syscall (sycall number 2 in x86_64)? */
        long r = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, 0);

            printf("haha:%d\n", r);

        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80 &&
                r == 2) {
            return 0;
        }
        if (WIFEXITED(status)) {
            return 1;
        }
    }
}

static void read_file(pid_t child, char *file)
{
    char *child_addr;
    int i;
    //rdi first argument
    child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RDI, 0);

    do {
        long val;
        char *p;

        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1) {
            fprintf(stderr, "PTRACE_PEEKTEXT error: %s\n", strerror(errno));
            exit(1);
        }
        child_addr += sizeof (long);

        p = (char *) &val;
        for (i = 0; i < sizeof (long); ++i, ++file) {
            *file = *p++;
            if (*file == '\0') break;
        }
        printf("%s\n", file);

    } while (i == sizeof (long));
}

static void redirect_file(pid_t child, const char *file)
{
    char *stack_addr, *file_addr;
    //rsp retrun value
    stack_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RSP, 0);
    /* Move further of red zone and make sure we have space for the file name */
    stack_addr -= 128 + PATH_MAX;
    file_addr = stack_addr;

    /* Write new file in lower part of the stack */
    do {
        int i;
        char val[sizeof (long)];

        for (i = 0; i < sizeof (long); ++i, ++file) {
            val[i] = *file;
            if (*file == '\0') break;
        }
        //change out context and modify to stack_addr
        ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *) val);
        stack_addr += sizeof (long);
    } while (*file);

    /* Change argument to open */
    //RDI is first argument,chang file_addr
    ptrace(PTRACE_POKEUSER, child, sizeof(long)*RDI, file_addr);
}

//so first input argument in rdi,
//rdi modify to file_addr,and file_addr is val,val is file and file is hard code 'ONE.txt'
//finally cat TWO.txt become cat ONE.txt