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
int sizes[10];
int is_admin = 0;

/* ──────────────────────────────────────────────────────────
 * Initialization
 * ──────────────────────────────────────────────────────────*/
void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_load(ctx);
}

/* ──────────────────────────────────────────────────────────
 * Format String
 * ──────────────────────────────────────────────────────────*/
void login() {
    char username[64];
    
    puts("\n--- Authentication ---");
    printf("Username: ");
    read(0, username, 63);
    
    if (strcmp(username, "S3cr3t_M4st3r_4dm1n\n") == 0) {
        is_admin = 1;
        puts("[+] Welcome back, Admin!");
    } else {
        printf("[-] Access denied for user: ");
        printf(username);
        puts("");
    }
}

/* ──────────────────────────────────────────────────────────
 * Use-After-Free
 * ──────────────────────────────────────────────────────────*/
void rent_vault() {
    int idx, size;
    printf("Vault index (0-9): ");
    scanf("%d", &idx);
    if (idx < 0 || idx > 9) {
        puts("Invalid index!");
        return;
    }
    
    printf("Size: ");
    scanf("%d", &size);
    if (size <= 0 || size > 0x1000) {
        puts("Invalid size!");
        return;
    }
    
    vaults[idx] = malloc(size);
    sizes[idx] = size;
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
    puts("Vault returned.");
}

/* ──────────────────────────────────────────────────────────
 * menu
 * ──────────────────────────────────────────────────────────*/
void menu() {
    puts("\n=== HashiCorp Vault ===");
    puts("1. Rent Vault");
    puts("2. Store Item");
    puts("3. View Item");
    puts("4. Return Vault");
    puts("5. Exit");
    printf("> ");
}

int main() {
    setup();
    
    while (!is_admin) {
        login();
    }
    
    int choice;
    while(1) {
        menu();
        if (scanf("%d", &choice) != 1) break;
        switch(choice) {
            case 1: rent_vault(); break;
            case 2: store_item(); break;
            case 3: view_item(); break;
            case 4: return_vault(); break;
            default: puts("Bye!"); exit(0);
        }
    }
    return 0;
}