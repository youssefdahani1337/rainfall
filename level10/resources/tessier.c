/*
 * Approximate C reconstruction of the supplied `objdump -d tessier` output.
 *
 * IMPORTANT:
 * This is a source-level reconstruction, not an exact decompilation.
 * The disassembly does not include the actual contents of the string literals
 * referenced in .rodata, so the messages and comparison string below are
 * placeholders. Structure sizes, offsets, and control flow are inferred from
 * the assembly.
 *
 * The original uses gets(), which is unsafe. This reconstruction uses fgets()
 * to avoid reproducing the stack-buffer overflow.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_SESSIONS 4
#define SESSION_NAME_SIZE 32
#define VAULT_DATA_SIZE 256

typedef struct {
    int id;                 /* offset 0 */
    int attempts;           /* offset 4 */
    int active;             /* offset 8 */
    char name[32];          /* offset 12; record stride is 44 bytes */
} Session;

typedef struct {
    uint32_t magic;         /* 0xcafebabe */
    uint32_t capacity;      /* 0x200 */
    uint32_t attempts;      /* 3 */
    char label[16];         /* offset 12 */
    char data[VAULT_DATA_SIZE]; /* offset 28 */
} Vault;

static Session sessions[MAX_SESSIONS];
static int session_count;
static Vault vault;

static void init_vault(void)
{
    vault.magic = 0xcafebabe;
    vault.capacity = 0x200;
    vault.attempts = 3;

    /* The original copies 15 bytes from an unknown .rodata string. */
    strncpy(vault.label, "VAULT_LABEL", sizeof(vault.label) - 1);
    vault.label[sizeof(vault.label) - 1] = '\0';

    memset(vault.data, 0, sizeof(vault.data));

    /*
     * The assembly copies 255 bytes from an unknown .rodata string into
     * vault.data. Replace this placeholder with the original literal if you
     * can recover the .rodata section.
     */
    strncpy(vault.data, "PLACEHOLDER_SECRET_DATA", sizeof(vault.data) - 1);
}

static void init_sessions(void)
{
    memset(sessions, 0, sizeof(sessions));
    session_count = 0;
}

static void print_banner(void)
{
    /* Exact strings are not present in the supplied disassembly text. */
    printf("========================================\n");
    puts("        Tessier Vault Session Manager");
    puts("========================================");
    printf("Please enter your log message:\n");
}

static void format_log(void)
{
    char log_line[32];

    printf("Log: ");
    fflush(stdout);

    if (fgets(log_line, sizeof(log_line), stdin) == NULL)
        return;

    log_line[strcspn(log_line, "\n")] = '\0';

    printf("Formatted log: ");
    /* The assembly calls printf(log_line), which is a format-string bug. */
    printf("%s", log_line);
    putchar('\n');
}

static int create_session(const char *name)
{
    int index;

    if (session_count > 3)
        return -1;

    index = session_count;
    sessions[index].id = session_count;
    sessions[index].attempts = 0;
    sessions[index].active = 1;
    strncpy(sessions[index].name, name, 31);
    /* strncpy may not NUL-terminate if the source is long. */
    session_count++;

    return index;
}

static void authenticate(void)
{
    char name[64];
    int index;

    printf("Enter username: ");
    fflush(stdout);

    /*
     * The original calls gets(name), which can overflow the 64-byte buffer.
     * fgets() is used here as a safer equivalent.
     */
    if (fgets(name, sizeof(name), stdin) == NULL)
        return;
    name[strcspn(name, "\n")] = '\0';

    index = create_session(name);

    if (index < 0) {
        puts("Session limit reached.");
        return;
    }

    /*
     * The exact 8-byte comparison literal is referenced in .rodata at
     * 0x402121, but its contents are absent from the supplied text.
     * Replace "ADMINKEY" with that literal for a closer reconstruction.
     */
    if (strncmp(name, "ADMINKEY", 8) == 0) {
        sessions[index].attempts = 0xff;
        printf("Authenticated session: %d\n", index);
        printf("Vault data: %s\n", vault.data);
    } else {
        printf("Session %d not authenticated.\n", index);
        sessions[index].active = 0;
    }
}

int main(void)
{
    init_vault();
    init_sessions();
    print_banner();
    format_log();
    authenticate();
    return 0;
}
