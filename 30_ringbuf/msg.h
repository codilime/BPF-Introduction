#ifndef __MSG_H__
#define __MSG_H__

struct my_msg {
    pid_t pid;
    pid_t tgid;
    char comm[32];
    char file[32];
};

#endif // __MSG_H__
