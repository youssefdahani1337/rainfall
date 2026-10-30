/*
 * 3jane.c  —  reconstructed from `objdump -d 3jane`
 *
 * Faithful where it matters for the exploit:
 *   - struct layout (id@0, level@4, name@8; sizeof = 56 = 0x38)
 *   - log_request():  char buff[64]  (sub $0x50), printf(buff) format-string bug
 *   - authenticate(): char buff[128] (sub $0x90), unbounded gets() overflow
 *   - call order in main()
 *
 * Reconstructed / placeholder (exact bytes live in .rodata, not recoverable
 * from the disassembly alone): the banner text, the vault label strings,
 * the clearance values, and the snprintf format in init_vault(). These do
 * not affect the vulnerability or the exploit.
 *
 * Build to mirror the target (64-bit, PIE off, canary on, NX on):
 *   gcc -O0 -fstack-protector-all -no-pie -z noexecstack -o 3jane 3jane.c
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define VAULT_ENTRIES 4
#define NAME_LEN      48

struct VaultItem {
    int  id;              /* offset 0  */
    int  level;           /* offset 4  */
    char name[NAME_LEN];  /* offset 8  */
};                        /* sizeof = 56 (0x38) */

struct VaultItem vault[VAULT_ENTRIES];   /* .bss @ 0x4040c0 */
int access_log_idx = 0;                  /* .bss @ 0x4041a0 */

/* static init data (reconstructed) */
static const char *labels[VAULT_ENTRIES]    = { "ROOT", "WINTERMUTE", "NEUROMANCER", "3JANE" };
static const int   clearances[VAULT_ENTRIES] = { 0, 1, 2, 3 };

void init_vault(void)
{
    for (int i = 0; i < VAULT_ENTRIES; i++) {
        vault[i].id    = i;
        vault[i].level = clearances[i];

        /* name[0..] = label, bounded to 15 bytes */
        strncpy(vault[i].name, labels[i], 15);

        /* name[16..] = a derived tag (snprintf, bounded to 0x20) */
        snprintf(vault[i].name + 16, 0x20, "%#x", i * 0x1337);
    }
}

void print_banner(void)
{
    printf("\033[0;32m");
    puts("  [3JANE] Straylight vault access terminal");
    puts("  [3JANE] Holographic clearance system");
    printf("\033[0m");
}

void log_request(void)
{
    char buff[64];                      /* sub $0x50 ; canary at rbp-8 */

    printf("[3JANE] Request ID: ");
    fflush(stdout);

    fgets(buff, sizeof(buff), stdin);   /* bounded: no overflow here */
    buff[strcspn(buff, "\n")] = '\0';

    printf("[3JANE] Logging: ");
    printf(buff);                       /* BUG 1: format string (leak the canary) */
    putchar('\n');

    access_log_idx++;
}

void authenticate(void)
{
    char buff[128];                     /* sub $0x90 ; canary at rbp-8 (136 bytes) */

    printf("[3JANE] Access code: ");
    fflush(stdout);

    gets(buff);                         /* BUG 2: unbounded overflow */

    if (strncmp(buff, "STRAYLIGHT_", 11) == 0)
        printf("[3JANE] Access granted. Clearance level: %u\n", vault[0].level);
    else
        puts("[3JANE] Access denied.");
}

void display_vault(void)
{
    puts("[3JANE] Vault Contents:");

    for (int i = 0; i < VAULT_ENTRIES; i++) {
        printf("[%d] %s (Level %d)\n",
               vault[i].id,
               vault[i].name,
               vault[i].level);
    }
}

int main(void)
{
    init_vault();
    print_banner();
    log_request();
    authenticate();
    display_vault();
    return 0;
}