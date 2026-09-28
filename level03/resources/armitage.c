#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MSG_SIZE 128
#define MAX_JOBS 4

typedef struct {
    unsigned int id;
    unsigned int priority;
    unsigned int status;
    char payload[MSG_SIZE];
} job_t;

static job_t job_queue[MAX_JOBS];
static unsigned int job_count = 0;

static void init_queue(void)
{
    memset(job_queue, 0, sizeof(job_queue));
}

static void print_banner(void)
{
    printf("\033[0;31m");
    printf("  [ARMITAGE] I have a job for you, cowboy.\n");
    printf("  [ARMITAGE] Transmission channel open.\n");
    printf("\033[0m");
}

static int validate_job(const char *msg)
{
    if (strlen(msg) < 4)
        return 0;
    if (msg[0] != 'J' || msg[1] != 'O' || msg[2] != 'B')
        return 0;
    return 1;
}

static void queue_job(void)
{
    char msg[MSG_SIZE];

    if (job_count >= MAX_JOBS) {
        printf("[ARMITAGE] Queue full. Dropping connection.\n");
        exit(1);
    }

    printf("[ARMITAGE] Prove yourself: ");
    fflush(stdout);

    gets(msg);

    if (!validate_job(msg)) {
        printf("[ARMITAGE] Invalid job format. Expected JOB:<data>\n");
        return;
    }

    job_queue[job_count].id = job_count;
    job_queue[job_count].priority = 1;
    job_queue[job_count].status = 0;
    strncpy(job_queue[job_count].payload, msg + 4, MSG_SIZE - 1);
    job_count++;

      printf("[ARMITAGE] Job %u queued. Priority: %u\n",
        job_count - 1, job_queue[job_count - 1].priority);
}

static void process_jobs(void)
{
    for (unsigned int i = 0; i < job_count; i++) {
        printf("[ARMITAGE] Processing job %u: %.32s...\n",
            job_queue[i].id, job_queue[i].payload);
        job_queue[i].status = 1;
    }
}

int main(void)
{
    init_queue();
    print_banner();
    queue_job();
    process_jobs();
    return 0;
}






// 0x7ffff7c58750
// 0x7ffff7c47ba0
// 0x7ffff7dcb42f