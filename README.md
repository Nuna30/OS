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
<details>
  <summary>proc struct</summary>

  ![proc_struct](./images/proc_struct.png)
</details>
<details>
  <summary>Trap Handling Process</summary>
  
  ![trap handling process](./images/capture_250605_131249.png)
  - The `kill()` used in the user program is generated through user.h and usys.S
  - The `kill()` used in the `sys_kill()` and The `kill()` used in the user program are not the same
  - This also applies to `fork()`, `setnice()`, `getnice()`, `ps()`, ...

</details>
<details>
  <summary>How system call parameters are passed</summary>

  - use `argint`, `argptr`, `argstr` in syscall.c
    <details> 
      <summary>view argint, argptr, argstr codes</summary>
  
      ![arg codes](./images/capture_250605_135401.png)
    </details>
    <details>
      <summary>view sys_sleep code using argint to get parameter</summary>

      ![sys_sleep code](./images/sys_sleep_code.png)
    </details>
</details>
<details>
  <summary>How to get the process corresponding to a given pid</summary>

  ![kill image](./images/kill.png)
</details>
