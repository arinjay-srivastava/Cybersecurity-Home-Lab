
A hands-on lab exploring Linux system administration, user management, and security fundamentals using a Virtual Machine.

## General System Tasks

### Task 1 - Retrieve Available Updates

```bash
sudo apt update
```

**Use:** Lets the system know which packages have updates available by retrieving the most recent package lists from preset repositories. This does **not** install anything yet.

![[image_2026-02-15_10-02-09.png]]![[image_2026-02-15_10-02-31.png]]

### Task 2 - Upgrade the System

```bash
sudo apt upgrade
```

**Use:** Downloads and installs all available updates for installed packages. Keeping our system up-to-date, patches security vulnerabilities and improves stability.

![[image_2026-02-15_10-03-29.png]]


### Task 3 - Reboot the System

```bash
sudo reboot
```

**Use:** Restarts the system. Some updates (mainly kernel updates) need a complete reboot to initialize.

---

## User Tasks

### Task 4 - Switch to Root User

```bash
sudo su root
```

**Use:** Switches the current session to the `root` superuser account. Root user has unrestricted access to all system commands and files.

> **What does the prompt look like?** The prompt end changes from `$` to `#`, indicating you are now operating as root. The username portion also changes to `root`.

![[image_2026-02-15_10-12-17.png]]

### Task 5 - Create New Users: `bobby` and `sally`

```bash
useradd bobby
adduser sally
```

**Use:** Creates two new user accounts on the system.

> **What is the difference between `useradd` and `adduser`?**
> - `useradd` is a low-level utility that creates the user with minimal setup it does **not** create a home directory by default or prompt for a password/additional info.
> - `adduser` is a higher level, more user-friendly script that **interactively** prompts for a password, full name, and other details. It also automatically creates a home directory.

![[image_2026-02-15_10-14-27-3.png]]


### Task 6 - Switch to User `sally`

```bash
su sally
```

**Use:** Switches the active session from root to the `sally` user account.

> **What does the prompt look like now?** The prompt changes to show `sally` as the current user and the `$` symbol returns (instead of `#`), indicating a non-root user session.

![[image_2026-02-15_10-15-05.png]]

### Task 7 - Attempt to Create a New User as `sally`

```bash
useradd earl
```

**Use:** Tests whether `sally` has the necessary privileges to create new users.

> **What happens? Why?** The command is denied with a "Permission denied" error. `sally` is a standard user and does **not** have root/sudo privileges, which are required to create new users.
> 
> **What could you do to allow her to create a new user?** You could add `sally` to the `sudo` group by running (as root):
> 
> usermod -aG sudo sally
>
> This would grant her the ability to run commands with elevated privileges using `sudo`.

![[image_2026-02-15_10-15-40.png]]

### Task 8 - Return to Own Account and Delete User `bobby`

```bash
exit
exit
# (repeat until back to your own account)

sudo userdel bobby
```

**Use:** `exit` steps back through each user session. `userdel` removes a user account from the system. The `-r` flag (optional) also removes the user's home directory:

```bash
sudo userdel -r bobby
```

> This task required looking up the command an important skill in CS! You won't always know the exact command, but knowing where to find it (man pages, Google, Stack Overflow) is just as valuable.

![[image_2026-02-15_10-18-15.png]]

### Task 9 - Change `sally`'s Password

```bash
sudo passwd sally
```

**Use:** Changes the password for the `sally` account. Using `sudo` allows an admin to change another user's password without knowing the current one.

![[image_2026-02-15_10-23-39.png]]


### Task 10 - Why Is Staying Logged in as Root Bad Practice?

> **Answer:** Staying logged in as `root` is dangerous for several reasons:
> 
> - **No safety net:** Every command runs with full system privileges. A typo (e.g., `rm -rf /` instead of `rm -rf ./`) can cause irreversible damage.
> - **Security risk:** If a session or terminal is left unattended, anyone with physical or remote access can execute destructive commands.
> - **Malware exposure:** Any malicious software executed while logged in as root runs with unrestricted access to the entire system.
> - **Audit difficulty:** It becomes harder to track _which_ user made changes when everything runs as root.
> 
> Best practice is to use a standard account and only elevate privileges temporarily using `sudo` when needed.


### Task 11 - Check Your User ID

```bash
id
```

**Use:** Displays the current user's UID (User ID), GID (Group ID), and all groups the user belongs to. Each user on a Linux system has a unique numeric identifier.

![[image_2026-02-15_10-24-04.png]]

---
## Group Tasks

### Task 12 - Check Groups for User `ubuntu`
```bash
groups ubuntu
```

**Use:** Displays all groups that the `ubuntu` user belongs to. By default, the primary user often belongs to groups like `sudo`, `adm`, `dialout`, and others depending on the system configuration.

![[image_2026-02-15_10-24-43.png]]


### Task 13 - Grant `sally` Sudo Privileges and Create a User
```bash
sudo usermod -aG sudo sally
```

**Use:** The `usermod` command modifies user account properties. The `-aG` flag **a**ppends the user to a supplementary **g**roup without removing them from other groups. Adding `sally` to the `sudo` group grants her the ability to execute commands with elevated privileges.

Now, switch to `sally` and try creating a new user:
```bash
su sally
sudo useradd earl
```
 

> **What happens?**
> This time, `sally` can successfully create the user `earl` because she now has sudo privileges! She may be prompted for her password the first time she uses `sudo`.

![[image_2026-02-15_10-25-47.png]]


### Task 14 - Create a New Group Called `cybersec`

```bash
exit  # Log out of sally
sudo groupadd cybersec
```

**Use:** Creates a new group named `cybersec`. Groups are used to manage permissions for multiple users at once — users in the same group can share access to files and directories.

  ![[image_2026-02-15_10-26-11.png]]


### Task 15 - Add `sally` to the `cybersec` Group

```bash
sudo usermod -aG cybersec sally
```

**Use:** Adds `sally` to the `cybersec` group as a supplementary group. Users can belong to multiple groups, allowing flexible permission management.
 ![[image_2026-02-15_10-27-36.png]]

### Task 16 - Check Which Groups `sally` Belongs To

**Various methods to check user groups:**

```bash
# Method 1: groups command
groups sally

# Method 2: id command
id sally

# Method 3: Check /etc/group file
grep sally /etc/group

# Method 4: getent command
getent group | grep sally

```

**Use:** These commands all display group membership information, but with different levels of detail:

- `groups` — Simple list of group names
- `id` — Shows UID, GID, and all group IDs with names
- `grep /etc/group` — Shows which group entries contain the username
- `getent group` — Queries the group database and filters for sally


---

## Permission and Access Control Lists

### Task 17 - Create Directory and Check Permissions

```bash
mkdir lab1
ls -ld lab1
```

**Use:**
- `mkdir lab1` creates a new directory
- `ls -ld lab1` lists directory details (the `-d` flag shows the directory itself, not its contents)

> **Understanding the output:**
> Example: `drwxr-xr-x 2 ubuntu ubuntu 4096 Feb 19 10:30 lab1`
> - **Owner:** `ubuntu` (first username)
> - **Group owner:** `ubuntu` (second username)
> - **Permissions breakdown:**
>   - `d` — Indicates it's a directory
>   - `rwx` — Owner has **r**ead, **w**rite, e**x**ecute
>   - `r-x` — Group has **r**ead, e**x**ecute (no write)
>   - `r-x` — Others have **r**ead, e**x**ecute (no write)

  
![[image_2026-02-15_10-28-46.png]]


### Task 18 -Create and Execute a Bash Script

```bash
cd lab1
nano helloWorld.sh
```

**Inside the file, add:**

```bash
#!/bin/bash
echo "Hello World!"
```

**Make it executable:**

```bash
chmod +x helloWorld.sh
./helloWorld.sh
```

**Use:**

- `nano` is a text editor to create the script
- `#!/bin/bash` (shebang) tells the system to run this file with bash
- `chmod +x` adds e**x**ecute permission
- `./helloWorld.sh` runs the script

![[image_2026-02-15_10-29-14.png]]


### Task 19 - Check File Permissions and Modify Them

```bash
ls -l helloWorld.sh
```

**Use:** Displays detailed file permissions.

> **Reading the permissions:**
> Example: `-rwxr-xr-x 1 ubuntu ubuntu 32 Feb 19 10:35 helloWorld.sh`
> - **Owner (rwx):** read, write, execute
> - **Group (r-x):** read, execute (no write)
> - **Other (r-x):** read, execute (no write)

  ![[image_2026-02-15_10-29-35.png]]

#### Task 19a - Grant Group Write and Execute Permissions

```bash
chmod g+wx helloWorld.sh
ls -l helloWorld.sh
```

**Use:**
- `chmod g+wx` adds **w**rite and e**x**ecute permissions for the **g**roup
- The group permissions change from `r-x` to `rwx`

![[image_2026-02-15_10-30-13.png]]



### Task 20 - View Access Control List (ACL)

```bash
getfacl helloWorld.sh
```

**Use:** Displays the Access Control List for the file. ACLs provide more granular permission control beyond the traditional owner/group/other model you can set permissions for specific users or groups.

![[image_2026-02-15_10-30-13-1.png]]

---
### Task 21 - Grant `sally` Read and Write Permissions Using ACL

```bash
setfacl -m u:sally:rw helloWorld.sh
```

**Use:**
- `setfacl` **m**odifies the ACL
- `u:sally:rw` grants **u**ser `sally` **r**ead and **w**rite permissions
- The second command verifies the ACL was updated  

> **Why use ACLs?**
> Traditional permissions only allow one owner and one group. ACLs let you grant specific permissions to individual users without changing ownership or group membership. This is perfect for collaborative environments where different users need different access levels to the same file.
  
![[image_2026-02-15_10-30-45.png]]

---
