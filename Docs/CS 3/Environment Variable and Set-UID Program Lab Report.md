## Pre-Lab Setup

* **Objective:** Provision the required environmental dependencies for the lab exercises.
* **Execution:** Executed standard package management commands to install `zsh`, `build-essential`, and `ncal`. 
* **Observation & Analysis:** All requisite packages and compilers were successfully installed and configured in the virtual machine.

![[image-34.png]]

---

## Task 1: Manipulating Environment Variables

* **Objective:** Examine the mechanisms for modifying the shell's environment.
* **Execution:** * Listed current variables using `printenv`.
  * Instantiated a new variable via `export MY_VAR="cybersecurity_lab"`.
  * Removed the variable using `unset MY_VAR`.
* **Observation & Analysis:** The environment was successfully modified. Because `export` and `unset` are internal Bash commands rather than external binaries, they directly manipulate the memory space of the active shell process.

![[image_2026-03-29_22-20-16-1.png]]
![[image_2026-03-29_22-21-20-1.png]]

---

## Task 2: Passing Environment Variables from Parent to Child

* **Objective:** Analyze environmental inheritance during the `fork()` system call.
* **Execution:** Compiled `myprintenv.c` to capture the child process's environment into `file1`.
  * Recompiled the code to capture the parent process's environment into `file2`.
  * Compared the outputs utilizing `diff file1 file2`.
* **Observation & Analysis:** The `diff` comparison returned no output, confirming identical file contents. This demonstrates that because `fork()` duplicates the calling process's memory space, the child process inherits a complete, exact replica of the parent's environment variables.

![[image_2026-03-29_22-24-14.png]]
![[image_2026-03-29_22-23-13.png]]

---

## Task 3: Environment Variables and execve()

* **Objective:** Evaluate how environment variables are processed when a new process image is loaded via `execve()`.
* **Execution:** * Executed `myenv.c` using the call `execve("/usr/bin/env", argv, NULL);`.
  * Altered the source to explicitly pass the environment array: `execve("/usr/bin/env", argv, environ);`.
* **Observation & Analysis:** The initial execution yielded no output, proving that `execve()` does not inherently transfer environment variables. Because `execve()` entirely overwrites the process's memory space, the environment must be explicitly passed through the function's third parameter to be accessible by the new program.

![[image_2026-03-29_22-25-38.png]]


---

## Task 4: Environment Variables and system()

* **Objective:** Contrast environmental inheritance mechanisms between `system()` and `execve()`.
* **Execution:** Compiled and ran a C program utilizing `system("/usr/bin/env");`.
* **Observation & Analysis:** The variables printed successfully. The `system()` function essentially acts as a wrapper that calls `/bin/sh -c` using the `execl()` function. Because `execl()` inherently passes the environment array to the invoked shell, the variables are preserved.

![[image_2026-03-29_22-26-22.png]]

---

## Task 5: Environment Variable and Set-UID Programs

* **Objective:** Investigate how privileged Set-UID programs handle environment variables defined by unprivileged users.
* **Execution:** * Configured a program to print the environment and applied Set-UID root permissions.
  * Exported `PATH`, `ANY_NAME`, and `LD_LIBRARY_PATH` in the standard user shell.
  * Executed the privileged program.
* **Observation & Analysis:** While `PATH` and the custom variable were inherited, `LD_LIBRARY_PATH` was conspicuously absent. This is an intentional security measure; the dynamic linker sanitizes the environment by stripping potentially dangerous variables when a privilege boundary is crossed, mitigating the risk of malicious library injection.

![[image_2026-03-29_22-27-13.png]]

---

## Task 6: The PATH Environment Variable and Set-UID Programs

* **Objective:** Demonstrate the vulnerability of utilizing relative paths within Set-UID programs.
* **Execution:** * Linked `/bin/sh` to `/bin/zsh` to bypass default shell privilege-dropping protocols.
  * Exploited a Set-UID program calling `system("ls")` by creating a malicious `ls` script and prepending the current directory to the `PATH` variable.
* **Observation & Analysis:** The Set-UID program executed the malicious script with elevated root privileges. This highlights that `system()` relies on the user-controlled `PATH` variable to resolve relative binary locations, allowing attackers to easily divert the execution flow to a custom payload.

![[image_2026-03-29_22-28-02.png]]

---

## Task 7: The LD_PRELOAD Environment Variable and Set-UID

* **Objective:** Assess the dynamic linker's behavioral constraints regarding `LD_PRELOAD` and Set-UID execution.
* **Execution:** * Compiled a shared library (`libmylib.so`) overriding the `sleep()` function.
  * Preloaded the library and executed a target program under both normal user and root user conditions.
* **Observation & Analysis:** The exploit failed when the normal user executed the Set-UID root program, but succeeded when the root user executed it. The dynamic linker (`ld.so`) actively compares the Real User ID with the Effective User ID. If a discrepancy is detected (indicating privilege escalation), it ignores the `LD_PRELOAD` directive to prevent unprivileged users from injecting code into privileged processes.

![[image_2026-03-29_22-33-28.png]]

---

## Task 8: Invoking External Programs Using system() vs execve()

* **Objective:** Compare the susceptibility of `system()` and `execve()` to command injection vulnerabilities.
* **Execution:** * Created a root-owned file (`/root/protected_file`) and verified the standard user lacked access using `sudo ls -l`.
  * Launched a command injection attack (`catall.c; rm -f /root/protected_file`) against a Set-UID program utilizing `system()`.
  * Recompiled the program utilizing `execve()` and attempted the identical attack.
* **Observation & Analysis:** The `system()` implementation succumbed to the injection, resulting in the deletion of the protected file. The `execve()` implementation successfully resisted the attack. Because `system()` delegates execution to a shell, metacharacters like semicolons are processed as command separators. Conversely, `execve()` processes the input strictly as literal data, completely neutralizing the injection payload.

![[image_2026-03-29_22-41-21.png]]
![[image_2026-03-29_22-41-30.png]]

---

## Task 9: Capability Leaking

* **Objective:** Illustrate the security implications of failing to explicitly clean up system resources prior to dropping privileges.
* **Execution:** * Compiled a Set-UID program that opened a privileged file (`/etc/zzz`), downgraded its effective user ID via `setuid()`, and spawned a user shell.
  * From within the unprivileged shell, appended text directly to the file via the preserved file descriptor (e.g., `echo "Exploit" >&3`).
* **Observation & Analysis:** Data was successfully written to the protected file from an unprivileged shell. While `setuid()` successfully revoked the process's root privileges, the program neglected to close the active file descriptor before transferring control. This open file descriptor served as a leaked capability, allowing the standard user shell to bypass standard filesystem permission checks entirely.

![[image_2026-03-29_22-44-19.png]]