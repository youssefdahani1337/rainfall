# rainfall
On a deliberately vulnerable VM, you climb from one account to the next by exploiting a series of SUID ELF binaries: reading their code, mapping how they lay out memory, and turning their flaws into control of execution. Each level tightens the protections (NX, stack canaries and ASLR), so your techniques must grow with them. 
