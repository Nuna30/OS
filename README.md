# Project #2. Priority Scheduler
## 1. Implement system calls related to process priority
- setnice(), getnice(), ps()
- I will do this on this branch!
## 2. Implement priority-based scheduler on xv6
- The lower nice value, the higher priority
- The highest priority process is selected for next running
- Tiebreak: FIFO fashion
- on the branch OS-hw3. not now.
## reference
![trap handling process](./images/capture_250605_131249.png)
- The `kill()` used in the user program is generated through user.h and usys.S
- The `kill()` used in the `sys_kill()` and The `kill()` used in the user program are not the same
- This also applies to `fork()`, `setnice()`, `getnice()`, `ps()`, ...
