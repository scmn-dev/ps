# ps

> `ps` displays data about all running processes in the current mount namespace.

### Build

1. to build run `make` .
2. to install it run `make install`.

### Listing Processes:

```bash
./ps | head -n5

USER     PID    PPID   CPU     ELAPSED          TTY    TIME   COMMAND
root     7      1      0.000   29m26.0628125s   tty1   0s     /init
root     7      1      0.000   29m26.0640173s   tty1   0s     /init
abdfnx   8      7      0.000   29m26.0640615s   tty1   0s     -bash
abdfnx   317    8      0.290   28m44.0652407s   tty1   5s     zsh
```

### Display Different Format Descriptors:

```bash
./ps -format "pid, user, group, tty" | head -n5

PID    USER     GROUP    TTY
1      root     root     tty1
7      root     root     tty1
8      abdfnx   abdfnx   tty1
317    abdfnx   abdfnx   tty1
```
