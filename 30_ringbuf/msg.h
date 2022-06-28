#ifndef __MSG_H__
#define __MSG_H__

struct my_msg {
    pid_t pid;
    char command[128];
    char pathname[128];
};

#endif // __MSG_H__
