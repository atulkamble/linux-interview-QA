# 📘 Full Linux Interview Q\&A Collection (200+ Questions)

---

## 📑 Section 1: Basic / Low Difficulty Questions

| #  | Question                                      | Answer                                                                                                   |
| :- | :-------------------------------------------- | :------------------------------------------------------------------------------------------------------- |
| 1  | What is Linux?                                | An open-source Unix-like operating system kernel widely used in servers, desktops, and embedded systems. |
| 2  | How to check the present working directory?   | `pwd`                                                                                                    |
| 3  | Command to list files including hidden files? | `ls -a`                                                                                                  |
| 4  | How to create a directory?                    | `mkdir dirname`                                                                                          |
| 5  | How to view file content?                     | `cat filename`                                                                                           |
| 6  | How to display the first 10 lines of a file?  | `head filename`                                                                                          |
| 7  | How to display the last 10 lines?             | `tail filename`                                                                                          |
| 8  | How to copy files?                            | `cp source destination`                                                                                  |
| 9  | How to move/rename files?                     | `mv source destination`                                                                                  |
| 10 | How to delete a file?                         | `rm filename`                                                                                            |

---
## 📑 Section 2: Moderate / Mid-Level Questions

| #  | Question                                    | Answer                                                               |
| :- | :------------------------------------------ | :------------------------------------------------------------------- |
| 11 | What does `chmod 755 file` do?              | Sets permissions: owner (7) = rwx, group (5) = r-x, others (5) = r-x |
| 12 | How to find the size of a directory?        | `du -sh directory/`                                                  |
| 13 | Difference between hard link and soft link? | Hard link: same inode, Soft link: shortcut with different inode      |
| 14 | How to check CPU usage?                     | `top` or `htop`                                                      |
| 15 | Command to list all running services?       | `systemctl list-units --type=service`                                |
| 16 | How to restart the networking service?      | `systemctl restart network` (RHEL/CentOS)                            |
| 17 | How to check system uptime?                 | `uptime`                                                             |
| 18 | How to display disk partitions?             | `lsblk`                                                              |
| 19 | How to mount a filesystem?                  | `mount /dev/sdX /mnt/point`                                          |
| 20 | How to view system logs?                    | `journalctl` or `/var/log/messages`                                  |

---

## 📑 Section 3: Advanced / High-Level Questions

| #  | Question                              | Answer                                                                  |
| :- | :------------------------------------ | :---------------------------------------------------------------------- |
| 21 | What is SELinux?                      | Security-Enhanced Linux; enforces security policies                     |
| 22 | How to disable SELinux temporarily?   | `setenforce 0`                                                          |
| 23 | What is the function of `/etc/fstab`? | Contains static info about filesystems for automatic mounting           |
| 24 | How to check available memory?        | `free -m`                                                               |
| 25 | How to limit user disk usage?         | Using disk quotas                                                       |
| 26 | How to manage user groups?            | `groupadd`, `usermod -aG group user`                                    |
| 27 | Difference between `su` and `sudo`?   | `su`: switch user shell; `sudo`: execute single command as another user |
| 28 | What is LVM?                          | Logical Volume Manager for flexible disk management                     |
| 29 | How to create a new LVM partition?    | `pvcreate`, `vgcreate`, `lvcreate`                                      |
| 30 | How to resize an LVM volume?          | `lvresize` + `resize2fs`                                                |

---

## 📑 Section 4: Scenario-Based / Practical Mock Questions

| #   | Question                                                   | Description                                                             |
| :-- | :--------------------------------------------------------- | :---------------------------------------------------------------------- |
| 31 | Disk space on `/` is full — how will you fix this?         | Check large files with `du -sh *`, delete unnecessary logs, clean cache |
| 32 | A user can’t SSH into the server — troubleshoot.           | Check network, SSH service, firewall, and `/etc/ssh/sshd_config`        |
| 33 | High CPU load — steps to troubleshoot.                     | Use `top`, `ps aux`, check for hung processes                           |
| 34 | A cron job isn't running — how to debug?                   | Check `crontab -l`, `/var/log/cron`, permissions                        |
| 35 | Configure a backup script to run every Sunday at midnight. | Create shell script, set cron entry `0 0 * * 0 /path/backup.sh`         |
| 36 | Migrate website from server A to B.                        | Rsync files, migrate DB, configure web server                           |
| 37 | Install and configure Docker on CentOS.                    | `yum install docker`, `systemctl start docker`, `docker run`            |
| 38 | Configure a firewall to allow SSH and HTTP only.           | `firewall-cmd --permanent --add-service=ssh`, `--add-service=http`      |
| 39 | Write a script to check and email disk usage if >90%.      | Use `df -h`, `awk`, and `mail` command                                  |
| 40 | Deploy Nginx as a reverse proxy for an application.        | Install Nginx, edit `/etc/nginx/nginx.conf`                             |

---

## 📑 Section 5: Assignment-Based Questions

| #   | Assignment                                         | Instructions                                         |          |           |
| :-- | :------------------------------------------------- | :--------------------------------------------------- | -------- | --------- |
| 41 | Create 5 user accounts with home directories       | Use `useradd -m username`                            |          |           |
| 42 | Set password expiry policy for users               | Use `chage` command                                  |          |           |
| 43 | Create a bash script to monitor load average       | Use `uptime` and log results                         |          |           |
| 44 | Schedule cleanup of `/tmp` at midnight daily       | Cron job: `0 0 * * * rm -rf /tmp/*`                  |          |           |
| 45 | Create a soft link and hard link for a file        | `ln file hardlink` and `ln -s file softlink`         |          |           |
| 46 | Install Apache and host a static website           | `yum install httpd` or `apt install apache2`         |          |           |
| 47 | Find top 5 largest files in `/var`                 | \`find /var -type f -exec du -h {} +                 | sort -rh | head -5\` |
| 48 | Setup local YUM repository                         | Mount ISO, create `repo` file in `/etc/yum.repos.d/` |          |           |
| 49 | Generate system report with CPU, Memory, Disk info | Combine `lscpu`, `free -m`, `df -h` in a script      |          |           |
| 50 | Create Docker image with Apache installed          | Write Dockerfile, build image, run container         |          |           |

---

## 📑 Section 6: Troubleshooting Case Studies

| #   | Issue                          | Expected Troubleshooting                    |
| :-- | :----------------------------- | :------------------------------------------ |
| 51 | Server boot loop               | Check `/var/log/messages`, kernel logs      |
| 52 | Service failed to start        | `systemctl status service`, logs            |
| 53 | No internet on server          | Check `/etc/resolv.conf`, `ping 8.8.8.8`    |
| 54 | Disk performance issue         | Use `iotop`, `iostat`                       |
| 55 | SSH Key authentication fails   | Check `.ssh/authorized_keys`, permissions   |
| 56 | User account locked            | `passwd -S username`, `usermod -U username` |
| 57 | High swap usage                | Check processes, increase RAM or optimize   |
| 58 | Cron not executing scripts     | Permissions, path issues, cron logs         |
| 59 | Network service drops randomly | Check NIC driver, logs, `dmesg`             |
| 60 | SELinux blocking application   | `getenforce`, `audit2allow` tools           |


---

## 📑 Section 7: Kernel, Storage, Networking, and Performance (High-Difficulty)

| #   | Question                                                     | Answer                                                                                            |
| :-- | :----------------------------------------------------------- | :------------------------------------------------------------------------------------------------ |
| 61 | How do you list kernel modules currently loaded?             | `lsmod`                                                                                           |
| 62 | How to load and unload a kernel module?                      | `modprobe module_name`, `modprobe -r module_name`                                                 |
| 63 | Where are kernel parameters stored for runtime modification? | `/proc/sys/`                                                                                      |
| 64 | How to permanently update kernel parameters?                 | Edit `/etc/sysctl.conf` and run `sysctl -p`                                                       |
| 65 | Command to view kernel version?                              | `uname -r`                                                                                        |
| 66 | What is a kernel panic?                                      | A critical system error from which the OS cannot recover                                          |
| 67 | How to debug a kernel panic?                                 | Check `/var/log/messages`, `journalctl -xb`, console output                                       |
| 68 | How to compile a custom Linux kernel?                        | Download source, configure with `make menuconfig`, `make`, `make modules_install`, `make install` |
| 69 | What is `initrd` or `initramfs`?                             | Temporary root file system used during boot before actual root filesystem is mounted              |
| 70 | What is `strace` and how is it useful?                       | A diagnostic tool to trace system calls by a program                                              |

---

## 📑 Section 8: Storage and Filesystem Management

| #   | Question                                      | Answer                                                    |
| :-- | :-------------------------------------------- | :-------------------------------------------------------- |
| 71 | How to check filesystem type of a partition?  | `df -T` or `blkid`                                        |
| 72 | How to create an ext4 filesystem?             | `mkfs.ext4 /dev/sdX`                                      |
| 73 | Command to check filesystem errors?           | `fsck /dev/sdX`                                           |
| 74 | What is a swap partition?                     | A space on disk used when RAM is full                     |
| 75 | How to add additional swap space?             | Create a swap file, `mkswap`, `swapon`                    |
| 76 | How to extend a mounted filesystem using LVM? | `lvextend -L +5G /dev/vg/lv` → `resize2fs /dev/vg/lv`     |
| 77 | How to view mounted filesystems?              | `mount` or `findmnt`                                      |
| 78 | Difference between RAID 0, 1, 5, and 10?      | 0: striping, 1: mirroring, 5: parity, 10: striped mirrors |
| 79 | How to check RAID status?                     | `cat /proc/mdstat`                                        |
| 80 | How to create a software RAID in Linux?       | `mdadm --create`                                          |

---

## 📑 Section 9: Networking

| #   | Question                                   | Answer                                                              |
| :-- | :----------------------------------------- | :------------------------------------------------------------------ |
| 81 | Command to display IP addresses?           | `ip addr`                                                           |
| 82 | How to configure static IP on Linux?       | Edit `/etc/sysconfig/network-scripts/ifcfg-ethX` or `/etc/netplan/` |
| 83 | How to flush the DNS cache?                | `systemd-resolve --flush-caches` (systemd)                          |
| 84 | How to test DNS resolution?                | `dig`, `nslookup`                                                   |
| 85 | How to check open TCP/UDP ports?           | `ss -tulnp`                                                         |
| 86 | How to capture network packets?            | `tcpdump`                                                           |
| 87 | What is `/etc/hosts` file used for?        | Static hostname to IP mapping                                       |
| 88 | How to add a static route?                 | `ip route add 192.168.1.0/24 via 10.0.0.1`                          |
| 89 | How to disable/enable a network interface? | `ip link set eth0 down` / `up`                                      |
| 90 | How to test network latency?               | `ping`, `mtr`                                                       |

---

## 📑 Section 10: Performance Tuning and Monitoring

| #   | Question                                          | Answer                                             |
| :-- | :------------------------------------------------ | :------------------------------------------------- |
| 91 | How to check system load average?                 | `uptime` or `top`                                  |
| 92 | What is the significance of load average numbers? | Average runnable processes in 1, 5, 15 minutes     |
| 93 | How to check disk I/O statistics?                 | `iostat`                                           |
| 94 | How to identify a memory leak?                    | Monitor increasing memory usage with `top`, `free` |
| 95 | How to limit CPU usage for a process?             | `cpulimit` or `nice/renice`                        |
| 96 | How to check swap usage?                          | `swapon -s`, `free -m`                             |
| 97 | How to tune system limits for open files?         | Edit `/etc/security/limits.conf`                   |
| 98 | What is `vm.swappiness`?                          | Kernel parameter controlling swap tendency         |
| 99 | How to reduce swappiness?                         | `sysctl -w vm.swappiness=10`                       |
| 100 | How to monitor network bandwidth usage?           | `iftop` or `nload`                                 |

---

## 📑 Section 11: Additional Advanced Linux Operations & Commands

| #   | Question                                            | Answer                                                               |
| :-- | :-------------------------------------------------- | :------------------------------------------------------------------- |
| 101 | How to search for a string in a file?               | `grep "text" filename`                                               |
| 102 | How to search recursively inside directories?       | `grep -r "text" /path`                                               |
| 103 | Difference between `find` and `locate`?             | `find` searches real-time; `locate` uses a prebuilt index            |
| 104 | How to find files modified in last 24 hours?        | `find /path -mtime -1`                                               |
| 105 | How to find files over 500MB size?                  | `find / -type f -size +500M`                                         |
| 106 | How to compress a directory as a `.tar.gz`?         | `tar -czvf archive.tar.gz /dir`                                      |
| 107 | How to extract `.tar.gz` files?                     | `tar -xzvf archive.tar.gz`                                           |
| 108 | What is the difference between `screen` and `tmux`? | Both are terminal multiplexers; `tmux` is more modern and scriptable |
| 109 | How to kill a process by name?                      | `pkill processname`                                                  |
| 110 | How to list all environment variables?              | `printenv`                                                           |

---

## 📑 Section 12: DevOps and Cloud-Friendly Linux Operations

| #   | Question                                        | Answer                                                   |
| :-- | :---------------------------------------------- | :------------------------------------------------------- |
| 111 | How to install Docker on Ubuntu?                | `apt install docker.io`                                  |
| 112 | How to enable and start Docker service?         | `systemctl enable --now docker`                          |
| 113 | How to check running Docker containers?         | `docker ps`                                              |
| 114 | How to create a new user with sudo permissions? | `useradd -m username && usermod -aG sudo username`       |
| 115 | How to create an SSH key pair?                  | `ssh-keygen -t rsa`                                      |
| 116 | How to copy SSH public key to another server?   | `ssh-copy-id user@host`                                  |
| 117 | How to monitor real-time network connections?   | `netstat -tunap` or `ss -tunap`                          |
| 118 | How to configure Nginx reverse proxy?           | Install Nginx → Edit `nginx.conf` to set `proxy_pass`    |
| 119 | How to install Kubernetes minikube on Linux?    | Download binary → `chmod +x` → move to `/usr/local/bin/` |
| 210 | How to test TCP/UDP connectivity?               | `nc -zv host port`                                       |

---

## 📑 Section 13: Linux Security and Hardening

| #   | Question                                                 | Answer                                                                |
| :-- | :------------------------------------------------------- | :-------------------------------------------------------------------- |
| 201 | How to disable root SSH login?                           | Edit `/etc/ssh/sshd_config` → `PermitRootLogin no`                    |
| 202 | How to set a firewall rule to allow SSH only?            | `firewall-cmd --permanent --add-service=ssh` → `--reload`             |
| 203 | How to set password complexity policy?                   | Modify `/etc/login.defs` and PAM modules                              |
| 204 | How to list currently open ports?                        | `ss -tulnp`                                                           |
| 205 | How to audit file access logs?                           | `auditd` → configure rules in `/etc/audit/audit.rules`                |
| 206 | How to check failed login attempts?                      | `lastb` or check `/var/log/secure` or `/var/log/auth.log`             |
| 207 | What is AppArmor and how does it differ from SELinux?    | Mandatory Access Control tool like SELinux, but path-based            |
| 208 | How to disable USB devices on a Linux server?            | Blacklist USB kernel modules in `/etc/modprobe.d/` config             |
| 209 | How to check if your system is under brute-force attack? | Check `/var/log/secure`, use `fail2ban` logs                          |
| 210 | How to enable password history restriction?              | Configure `pam_unix.so` with `remember=N` in `/etc/pam.d/system-auth` |

---
## 👨‍💻 Author

**Atul Kamble**

- 💼 [LinkedIn:atuljkamble](https://www.linkedin.com/in/atuljkamble)
- 🐙 [GitHub:atulkamble](https://github.com/atulkamble)
- 🐦 [X:atul_kamble](https://x.com/Atul_Kamble)
- 📷 [Instagram:atuljkamble](https://www.instagram.com/atuljkamble)
- 🌐 [Website:wwww.atulkamble.in](https://www.atulkamble.in)
