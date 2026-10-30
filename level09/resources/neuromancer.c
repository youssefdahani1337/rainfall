/*
 * neuromancer.c  —  reconstruction of level09's `neuromancer` from objdump.
 *
 * Structs, offsets, control flow and the vulnerable calls (printf(buf),
 * gets(), the puts@GOT leak) are faithful to the disassembly. String
 * *literals* and the exact snprintf format are not present in the objdump
 * (no .rodata dump), so they are plausible reconstructions — the behaviour,
 * not the wording, is what matters.
 *
 * Node layout (40 bytes, from init_nodes' stride of 0x28):
 *   +0x00 id   +0x04 value   +0x08 status   +0x0c name[16]   +0x20 handler
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Node {
    int id;                     /* +0x00 */
    int value;                  /* +0x04 */
    int status;                 /* +0x08 */
    char name[16];              /* +0x0c */
    void (*handler)(void);      /* +0x20 (4 bytes padding at +0x1c) */
};

struct Node nodes[12];
int node_count = 0;

void default_handler(void);
void init_nodes(void);
void print_banner(void);
void show_node(unsigned int idx);
void info_leak(void);
void console_handshake(void);
void process_input(void);
void handle_command(void);


void default_handler(void) {
    puts("  [node] default handler invoked.");
}

void init_nodes(void) {
    for (int i = 0; i <= 11; i++) {
        nodes[i].id      = i;
        nodes[i].value   = i % 3;
        nodes[i].status  = 0;
        snprintf(nodes[i].name, 0x10, "node-%x", i * 0x1a2b);
        nodes[i].handler = default_handler;     /* set, but never called */
    }
    node_count = 12;
}

void print_banner(void) {
    printf("\033[0;32m");
    puts("  [WINTERMUTE] Console online.");
    puts("  [neuromancer] Awaiting operator.");
    printf("\033[0m");
}

void show_node(unsigned int idx) {
    if (idx < (unsigned int)node_count) {
        printf("  [%d] %s  value=%d  status=%d\n",
               nodes[idx].id,
               nodes[idx].name,
               nodes[idx].value,
               nodes[idx].status);
    }
}

/* Hands out the runtime address of puts in libc — a free ASLR-defeating leak. */
void info_leak(void) {
    printf("  [trace] puts @ %p\n", (void *)puts);
}

void console_handshake(void) {
    char buf[64];                       /* at rbp-0x50 */

    printf("  console> ");
    fflush(stdout);

    if (fgets(buf, 0x40, stdin) != NULL) {
        printf("  [echo] ");
        printf(buf);                    /* FORMAT-STRING BUG: leaks the canary (%15$p) */
    }
}

void process_input(void) {
    char buf[128];                      /* at rbp-0x90; 136 bytes to the canary */
    unsigned int idx;                   /* -0x94 */
    int i;                              /* -0x98 */

    printf("  cmd> ");
    fflush(stdout);

    gets(buf);                          /* UNBOUNDED: stack overflow */

    if (strncmp(buf, "show ", 5) == 0) {
        idx = (unsigned int)strtoul(buf + 5, NULL, 10);
        show_node(idx);
    } else if (strncmp(buf, "all", 4) == 0) {
        for (i = 0; i < node_count; i++)
            show_node(i);
    } else {
        puts("  [neuromancer] unknown command.");
    }
}

void handle_command(void) {
    info_leak();            /* 1. leak libc (puts)      */
    console_handshake();    /* 2. leak canary (fmt str) */
    process_input();        /* 3. overflow (gets)       */
}

int main(void) {
    init_nodes();
    print_banner();
    handle_command();
    return 0;
}
