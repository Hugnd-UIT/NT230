/*
 * Challenge: "Hashicorp Vault"
 *
 * Difficulty: Insane
 *
 * Description: An identity-based tool designed to securely store, manage, and control access. 
 * Can you break into the vault while dodging SECCOMP and Tcache mitigations?
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <seccomp.h>
#include <fcntl.h>

char *vaults[10];
int   sizes[10];
int   is_admin = 0;

/* ──────────────────────────────────────────────────────────
 * Initialization
 * ──────────────────────────────────────────────────────────*/
void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    for (int i = 3; i < 1024; i++) close(i);
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read),           0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write),          0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open),           0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat),         0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close),          0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek),          0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat),          0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat),     0);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk),            0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap),           0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap),         0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect),       0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap),         0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64),      0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl),     0);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction),   0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn),   0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex),          0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list),0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom),      0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid),         0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid),         0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill),         0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl),          0); 

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit),           0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group),     0);

    seccomp_load(ctx);
    seccomp_release(ctx);
}

/* ──────────────────────────────────────────────────────────
 * Format String
 * ──────────────────────────────────────────────────────────*/
void login() {
    volatile long _pad0 = 0;
    volatile long _pad1 = 0;
    char username[32];

    puts("\n--- Authentication ---");
    printf("Username: ");
    read(0, username, 31);

    if (strcmp(username, "S3cr3t_M4st3r_4dm1n\n") == 0) {
        is_admin = 1;
        puts("[+] Welcome back, Admin!");
    } else {
        printf("[-] Access denied for user: ");
        printf(username);
        puts("");
    }
    (void)_pad0; (void)_pad1;
}

/* ──────────────────────────────────────────────────────────
 * Use-After-Free
 * ──────────────────────────────────────────────────────────*/
void rent_vault() {
    int idx, size;
    printf("Vault index (0-9): ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 9) { puts("Invalid index!"); return; }

    printf("Size: ");
    scanf("%d", &size);
    if (size <= 0 || size > 0x1000) { puts("Invalid size!"); return; }

    vaults[idx] = malloc(size);
    sizes[idx]  = size;
    printf("Vault %d rented!\n", idx);
}

void store_item() {
    int idx;
    printf("Vault index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 9 || !vaults[idx]) {
        puts("Invalid index or vault empty!");
        return;
    }

    printf("Data: ");
    read(0, vaults[idx], sizes[idx]);
    puts("Stored.");
}

void view_item() {
    int idx;
    printf("Vault index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 9 || !vaults[idx]) {
        puts("Invalid index or vault empty!");
        return;
    }
    printf("Item: %s\n", vaults[idx]);
}

void return_vault() {
    int idx;
    printf("Vault index: ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 9 || !vaults[idx]) {
        puts("Invalid index or vault empty!");
        return;
    }

    free(vaults[idx]);
    vaults[idx] = NULL;
    sizes[idx]  = 0;
    puts("Vault returned.");
}

void alias_vault() {
    int src, dst;
    printf("Source vault (0-9): ");
    scanf("%d", &src);
    if (src < 0 || src > 9 || !vaults[src]) {
        puts("Invalid index or vault empty!");
        return;
    }

    printf("Alias vault (0-9): ");
    scanf("%d", &dst);
    if (dst < 0 || dst > 9 || dst == src) {
        puts("Invalid alias index!");
        return;
    }

    if (vaults[dst]) {
        free(vaults[dst]);
        vaults[dst] = NULL;
        sizes[dst]  = 0;
    }

    vaults[dst] = vaults[src];
    sizes[dst]  = sizes[src];
    printf("Vault %d aliased to %d.\n", dst, src);
}

/* ──────────────────────────────────────────────────────────
 * Heap Overflow
 * ──────────────────────────────────────────────────────────*/
void resize_vault() {
    int idx, new_size;
    printf("Vault index (0-9): ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 9 || !vaults[idx]) {
        puts("Invalid index or vault empty!");
        return;
    }

    printf("New size: ");
    scanf("%d", &new_size);
    if (new_size <= 0 || new_size > 0x1000) {
        puts("Invalid size!");
        return;
    }

    void *new_ptr = realloc(vaults[idx], new_size);
    if (!new_ptr) { puts("Resize failed!"); return; }

    vaults[idx] = new_ptr;
    printf("Vault resized new capacity hint: %d.\n", new_size);
}

/* ──────────────────────────────────────────────────────────
 * Menu
 * ──────────────────────────────────────────────────────────*/
void menu() {
    puts("\n=== HashiCorp Vault ===");
    puts("1. Rent Vault");
    puts("2. Store Item");
    puts("3. View Item");
    puts("4. Return Vault");
    puts("5. Alias Vault");
    puts("6. Resize Vault");
    puts("7. Exit");
    printf("> ");
}

int main() {
    setup();

    while (!is_admin) login();

    int choice;
    while (1) {
        menu();
        if (scanf("%d", &choice) != 1) break;
        switch (choice) {
            case 1: rent_vault();   break;
            case 2: store_item();   break;
            case 3: view_item();    break;
            case 4: return_vault(); break;
            case 5: alias_vault();  break;
            case 6: resize_vault(); break;
            default: puts("Bye!"); exit(0);
        }
    }
    return 0;
}