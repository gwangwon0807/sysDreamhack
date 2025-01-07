#include <stdio.h>
#include <unistd.h>

int main() {
	char *sh[2];
	sh[0] = "/bin/sh";
	sh[1] = 0;
	execve(sh[0], sh, &sh[1]);
}
