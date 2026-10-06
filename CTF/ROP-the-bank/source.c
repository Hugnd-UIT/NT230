/*
 * Challenge: "ROP-the-bank"
 * 
 * Difficulty: Hard
 *
 * Description: Bypass the state-of-the-art memory mitigations of this secure ATM and walk away with a shell.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static long  g_balance    = 100000;
static int   g_logged_in  = 0;
static char  g_username[32] = {0};

/* ──────────────────────────────────────────────────────────
 * ROP gadget
 * ──────────────────────────────────────────────────────────*/
__asm__ (
    ".section .text\n"
    ".global _rop_pop_rdi\n"
    "_rop_pop_rdi:\n"
    "    pop %rdi\n"
    "    ret\n"
);

__attribute__((noinline, used))
static void withdrawal_limit(unsigned long cap)
{
    if (cap > 999999999UL)
        cap = 999999999UL;
    if (g_balance > (long)cap)
        g_balance = (long)cap;
}

/* ──────────────────────────────────────────────────────────
 * Stack Over-Read
 * ──────────────────────────────────────────────────────────*/
void show_statement(void)
{
    char history[64];
    memset(history, 0xCC, sizeof(history));

    strncpy(history, g_username, sizeof(history));

    printf("\n  [*] Account  : ");
    fflush(stdout);

    write(STDOUT_FILENO, history, 128);

    printf("\n  [*] Balance  : %ld VND\n\n", g_balance);
}

/* ──────────────────────────────────────────────────────────
 * Stack Buffer Overflow
 * ──────────────────────────────────────────────────────────*/
void deposit(void)
{
    char buf[64];

    printf("  Amount to deposit: ");
    fflush(stdout);

    ssize_t n = read(STDIN_FILENO, buf, 512);
    (void)n;

    long amount = atol(buf);
    if (amount > 0) {
        g_balance += amount;
        printf("  [+] Deposited. Balance: %ld VND\n", g_balance);
    } else {
        puts("  [-] Invalid amount.");
    }
}

void withdraw(void)
{
    long cap = g_balance / 2; 
    withdrawal_limit((unsigned long)cap);

    char buf[32];
    printf("  Amount to withdraw (max %ld): ", cap);
    fflush(stdout);
    fgets(buf, sizeof(buf), stdin);

    long amount = atol(buf);
    if (amount <= 0 || amount > cap) {
        puts("  [-] Exceeds limit or invalid.");
        return;
    }
    g_balance -= amount;
    printf("  [+] Withdrew %ld. Balance: %ld VND\n", amount, g_balance);
}

/* ──────────────────────────────────────────────────────────
 * login()
 * ──────────────────────────────────────────────────────────*/
void login(void)
{
    char pin[16];

    printf("  Username: ");
    fflush(stdout);
    fgets(g_username, sizeof(g_username), stdin);
    size_t l = strlen(g_username);
    if (l > 0 && g_username[l-1] == '\n')
        g_username[l-1] = '\0';

    printf("  PIN: ");
    fflush(stdout);
    fgets(pin, sizeof(pin), stdin);

    if (strncmp(pin, "1337\n", 5) == 0) {
        g_logged_in = 1;
        printf("  [+] Welcome, %s!\n", g_username);
    } else {
        puts("  [-] Wrong PIN.");
    }
}

void menu(void)
{
    puts("\n╔══════════════════════════════════╗");
    puts("║   ROP the bank, if you can       ║");
    puts("╚══════════════════════════════════╝");

    for (;;) {
        puts("\n  1. Login");
        puts("  2. View Statement");
        puts("  3. Deposit");
        puts("  4. Withdraw");
        puts("  5. Exit");
        printf("  > ");
        fflush(stdout);

        int c;
        if (scanf("%d", &c) != 1) {
            int ch; while ((ch = getchar()) != '\n' && ch != EOF);
            continue;
        }
        getchar();

        if (!g_logged_in && c != 1 && c != 5) {
            puts("  [-] Please login first.");
            continue;
        }

        switch (c) {
            case 1: login();       break;
            case 2: show_statement(); break;
            case 3: deposit();        break;
            case 4: withdraw();       break;
            case 5: puts("  Bye."); exit(0);
            default: puts("  [-] Unknown option.");
        }
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    menu();
    return 0;
}