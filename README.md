# Linux Commmands Cheatsheet
##User and group management


! Hard link works only with the same partition!
! hard link would show as regular file



redirect only the output:
ls -la /root 2> errormsg

refine output - PIPE:
ls | more



whatis
--help
man

**Create user**
! User will be created with custom group specified. If -g is not provided, group is created with the same name.
useradd -g GROUP -s /bin/bash -c "user description" -m -d /home/USERNAME USERNAME

**Check user**
id USERNAME

**Delete user along with the home directory**
userdel -r USERNAME

**Create group**
groupadd GROUP

**Delete group**
groupdel GROUP

**Add or remove user from group**
```
usermod -G -a user group                    # Adds the user to the group
usermod -G -r user group

gpasswd -a user group                       # Remove the user from the group
gpasswd -d user group
```

/etc/passwd = users
/etc/groups = groups
/etc/shadow = users password

**Set shell for user**
usermod -s /sbin/nologin USER       # When the user tries to login, it will be politely told that a user doesn't have a shell
usermod -s /bin/false USER      # When the user tries to login, the connection will immediately drop

**Get ID of user and group
´´´
id USER
´´´

**Default user parameters**
/etc/login.defs

PASS_MAX_DAYS = 99999
PASS_MIN_DAYS = 0
PASS_MIN_LEN = 5
PASS_WARN_AGE = 7

**Change password requirements**
```
/etc/security/pwquality.conf
```

**set parameters around password for user**
```chage -m mindays -M maxdays -d lastday -I -E expiredate -W warndays USER```

**Become root**
```su -```

**Elevate yourself in interactive mode**
```sudo -i```

**change user**
```su USER```

**run a command through sudo**
```sudo COMMAND```

# Permisson

**List all files with tmp**
```ls -l tmp```

**Remove write from group on file/folder**
```chmod g-w tmp```

**Remove read from others on file/folder**
```chmod a-r tmp```

**Remove write from user on file/folder**
```chmod u-w tmp```

**Add read and write to user on file/folder**
```chmod u+rw```

**Add read and execute to use on file**
```chmod u+x```

**Add read, write and execute to all users on file/folder**
```chmod a+rwx```

! Even though user hasn't any read permission, the user will still be able to delete the file

! You need execute permission to "cd" (ls) into folder


**Change owner or group recursive**
```
chown -R USER
chgrp -R GROUP
```

**View partition, mounts and filesystem
```df -hT```

**View files and sort by size in reverse order
```du -h ~ | sort -nr```

**See indivial cores on cpu in top
```top AND THEN PRESS 1```

**List open files
```lsof | grep PATTERN```

**Output all network interface to file
```tcpdump -i INTERFACE > FILE```

**Move hidden files
#**Zsh
setopt glob_dots
mv Foo/* Bar/
unsetopt glob_dots

#**Bash
shopt -s dotglob
mv Foo/* Bar/
shopt -u dotglob

**List processes**
```
ps aux | grep PROCESS
ps aux --forest
pstree
ps aux --sort=-%cpu | head -10
ps aux --sort=-%mem | head -10
```

# List processes
```ps aux | grep PROCESS```

**Force killing of process
```kill -9 PID```

**Force killing all processes with certain name 
```killall -s 9 apache2```


systecmctl --version


systemctl --all

**Reload configuration for a service**
```systemctl reload application.service```

**
```systemctl status/start/stop/restart application.service```

**Enable or disable service at boot time**
```systemctl enable/disable application.service```


**Enable or disable service completely**
```systecmctl mask/unmask application.service```

# Misc
**Verify checksum of file**
```
echo checksum file | sha256sum -c

OR

echo $(cat checksumfile) file | sha256sum -c
```

**Calculate checksum of multiple files**
```
find . -type f -exec sha256sum {} \;                # Calculate checksum of files in the current directory.

OR

find /etc -type f -exec sha256sum {} \;             # Calculate checksum of files in a specific directory.

```
**List how many matches a grep results in**
```
cat file | grep string | wc -l
```

**Grep this OR that**
```
grep -E "this|that"
```

**List unique lines**
```
cat file | uniq
```

**Download output from URL**
```
wget -O FILE URL                # Download output as file from URL
```

/var/log/boot - Boot evetns
/var/log/messages - All events
/var/log/secure - Security events
/var/log/cron - Cron events
/var/log/maillog - SMTP events

# Vim
**List newline**
```
:set list
```

dmesg

**Stream file
```tail -f FILE```


**Search input file for regex matches (in this case for a MAC address) and output matches and their respective line numbers**
cat FILE | grep -n -i [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]




**Check if package is installed
```rpm -qa | grep PACKAGE```



#############**TIME

**Set and view time and date configuration**
```timedatectl```

**View time zones**
```timedatectl list-timezones```

**Set time zone**
```timedatectl set-timezone Europe/Stockholm```

**Set time**
```
timedatectl set-time 20:15:50
```
OR
```
timedatectl set-time '2021-08-18 20:15:50'
```
OR
```
date -s '2021-08-18 20:15:50'
```
**Sync time with NTP
```timedatectl set-ntp true```


chronyd

/etc/chrony.conf
/var/log/chrony.log

systemctl status chronyd

! Only one daemon should be running and syncing NTP servers

# Set keymap temporary
loadkeys se

# Set keymap persistent
localectl set-keymap se

##SSH

Configuration /etc/ssh/sshd_config

##Client time out
ClientAliveInterval 600
ClientAliveCountMax 1

-> systemctl restart sshd


**Disable root login
PermitRootLogin no

-> systemctl restart sshd

**Disable Empty Passwords
PermitEmptyPasswords no

-> systemctl restart sshd

**Allow certain users
Allow user1 user2

-> systemctl restart sshd

**Change port
Port 2222

-> systemctl restart sshd




##**Analyze servers and get support
```
sosreport
sos report
```

**Install and access cockpit
```
dnf install cockpit
systemctl enable --now cockpit
https://IP:9090
```



##Install software and doing updates


**Install certain package**
```
yum install PACKAGE
```

**Remove certain package**
```
yum remove PACKAGE
```

**List all installed packages in the system**
```
rpm -qa
```

**Search for package in the current system**
```
rpm -qa | grep PACKAGE
```

**Installs, verify and get hash of a local package**
```
rpm -ihv PACKAGE.RPM
```

**Remove package**
```
rpm -e PACKAGE.RPM
```

/etc/yum.repos.d/

rpm - locally install package

apt-get - Debian-based

# Check when system was last updated
cat /var/log/apt/history.log
rpm -qi --last

**Get current version**
```cat /etc/redhat-release```

**Minor upgrade (6.0 -> 6.1), but will preserve current packages**
```yum update```

**Minor upgrade (6.0 -> 6.1), but will remove packages and replace with newer onces**
```yum upgrade```


**Query package for info**
```rpm -qi PACKAGE```

**List configuration files for package**
```rpm -qc PACKAGE```

**Check what executable is assiciatted with what package**
```rpm -qf PACKAGE/FULL PATH TO EXECUTABLE```

**Rename all files ending with specific file extension in the current folder**
```sh
rename -vn currentname newname *.png      # Dry run
rename -v currentname newname *.png       # Actually doing it
```

**Compress and extract files**
```
tar -cvf FILE.TAR ~     # Create an archive from file/folder
tar -xvf FILE.TAR       # Extract an archive

tar -cvzf FILE.TAR.GZ ~     # Create an gzip compress archive from file/folder
tar -xvzf FILE.TAR.GZ       # Extract an gzip compress archive

tar -cvjf FILE.TAR.BZ2 ~    # Create an bz2 compress archive from file/folder
tar -xvjf FILE.TAR.BZ2      # Extract an bz2 compress archive

zip --password MY_SECRET secure.zip file1 file2 file3
unzip secure.zip

7za a -tzip -pMY_SECRET -mem=AES256
7za e secure.zip
```

# List listening processes
```
ss -lntup
netstat -autp
netstat -nat # Show all current TCP connections 
```
**FTP
```yum install vsftpd```

# Find something (case insensitive) and supress permission issues
find / -iname nanorc 2>/dev/null

# Do something with results
```find -iname nanorc | xargs cat```


# Block process termination
```nohup apt-get update```

## Parsing
### jq (or yq)

**Return all items with the name property**
```sh
command | jq .[].name
command | jq -r .[].name        # raw ouput
```

**Return the first item with the name property**
```sh
command | jq .[0].name
command | jq -r .[0].name       # raw output
```

/etc/vsftpd/vsftpd.conf


anonymous_enable=NO
ascii_upload_enable=YES
ascii_download_enable=YES
ftpd_banner= Welcome to bla bla bla
use_localtime=YES


ftp X.X.X.X
Login
bi = binary mode to transfer files
hash = progress bar
put FILE
bye


**Transfer file to via SSH (SCP)
```scp FILE USER@X.X.X.X:/home/USER```

**NetworkManager
nmcli = cli editor for NetworkManager
nmtui = ncurses editor for NetworkManager


/etc/sysconfig/network-scripts = upstart script for network configuration
/etc/hosts 
/etc/hostname = hostname for machine
/etc/resolve.conf = DNS server for name resolving
/etc/nsswitch.conf = order for name lookup


**Set process priority**
```nice -n PRIORITY PROCESSNAME```

**Change process priority**
```renice -n PRIORITY PROCESSID```

Userspace
    High priority = -20
    Lower priority = 19

System
    High priority = -99
    Lower priority = 39


## Permission ACL

**Set or remove ACL on file or directory**
```
setfacl -m u:USER:rwx PATH
setfacl -m g:GROUP:r PATH
setfacl -Rm g:GROUP:r PATH
setfacl -x g:GROUP PATH
```

**Remove all ACL from file or directory**
```
setfacl -b PATH
```

**Get current ACL on file or directory**
```
getfacl
```
> ! Permission write with ACL doesn't allow deletion of files

**SELinux
! Is default enabled in Redhat, CentOS and Fedora
Enforcing = Enabled
Permissive = Disable, but logs the activity
Disable = Disable

**Check SELinux status**
```
sestatus
getenforce
```

**Change SELinux mode**
```
setenforce 0 = Permissive/Disable
setenforce 1 = Enable
```

**Configuration 
/etc/selinux/config
SELINUX=enforcing
OR
SELINUX=disable

SELinux
    Labeling

**List label of file
```
ls -lZ FILE
```

**List label of directory
```
ls -dZ DIRECTORY
```

**List label of process
```
ps axZ | grep PROCESS
```

**List label of socket
```
netstat -tnlpZ | grep PROCESS
```
!!!!!!!!!!!!!!!!!!!!!!!!!! ps -ef


semanage boolean


**List of boolean
getsebool -a 
semanage boolean -l

**Active or disable boolean
setsebool -P BOOLEANNAME on/off

**Change the type of label
chcon -t TYPE FILE
semanage -t TYPE FILE

/.autorelabel ??

##Storage


df -h


**List partitions**
```
fdisk -l
```

**Format partition**
```
mkfs.xfs /dev/sdb1
```

**Mount disk upon boot**
Edit /etc/fstab


**
Physical volume = volume on partition on block device
Volume group = One or more volumes from partition from block device
Logical volume = One or more logical partitions from volume group


1. create physical partition
fdisk
n
t 8e

2. create physical volume
pvcreate /dev/sdb1 
pvcreate /dev/sdc1

3. 
vgcreate LOGICALNAME /dev/sdb1
OR
vgcreate LOGICALNAME /dev/sdb1 /dev/sdc1


lvcreate --name LOGICALNAME -l +100%FREE LOGICALNAME
mkfs.ext4


vgextend LOGICALNAME /dev/sdc1
lvextend -l +100%FREE LOGICALNAME
resize2fs


lvcreate -n data1_lv -l +100%FREE data1_vg
#########################################################3

Stratis

! Uses thin provision as default


dnf install stratis-cli stratisd


stratis pool create pool1 /dev/sdc

stratis pool list

stratis pool add-data pool1 /dev/sdd


stratis filesystem create pool1 fs1
stratis filesystem list

mkdir /data3
mount /stratis/pool1/fs1 /data3


! Stratis volumes will always show 1 TB when eg. running df

**Create snapshot of filesystem
stratis filesystem snapshot pool1 fs1 SNAPSHOTNAME

Add to fstab
/etc/fstab
UUID="UUIDOFFILESYSTEM" /fs1 xfs defaults,x-systemd.requires=stratisd.service 0 0

##**Machine operations and target levels
! shutdown and reboot is symbolic links to systemctl

systemctl poweroff = shutdown and power off system
systemctl reboot = shutdown and reboot

**Get current target or run-level
systemctl get-default
who -r

**List targets
ls -al /lib/systemd/system/runlevel*

**Set target on system
systemctl set-default graphical.target

**Reset root password on Red Hat (SELinux enabled)
edit GRUB using e key
replace "quiet" with "rd.break" under Linux
rd.break
ctrl+x
mount -o remount,rw /sysroot
chroot /sysroot
passwd root
touch /.autorelabel
exit
exit

**Reset root password on Ubuntu
edit GRUB using e key
After the /swap type:
replace "ro quiet splash $vt_handoff” with “rw init=/bin/bash” under Linux
ctrl+x
mount | grep -w /
passwd root
REBOOT

## Firewalls
**Overview**
tables
    filter
    mangle
    nat
    raw

chain
    INPUT = incomming traffic
    FORWARD = going to a router, from one device to another
    OUTPUT = outgoing traffic

target
    ACCEPT - accept connection
    REJECT - send reject response
    DROP - drop connection without sending any response

**iptables
#**List iptables rules
iptables -L

#**Remove all iptables rules
iptabels -F





# Containers
```
dnf install podman
```

**Check podman specs**
```
podman info
```

**Start container**
```
podman run -dt -p 3000:3000 redmine
```

**Generate podman file**
```
podman generate systemd --new --files --name redmine
cp /root/container-redmine.service /etc/systemd/system
systemctl enable container-redmine.service
systemctl start container-redmine.service
```

# NFS
**Server
> ! nosuid
```
dnf install nfs-utils libnfssidmap
systemctl enable rpcbind
systemctl enable nfs-server
systemctl start rpcbind
systemctl start nfs-server
systemctl start rpc-statd
systemctl start nfs-idmapd
mkdir /data
chmod a+rwx /data
Modify /etc/exports
**/data 192.168.12.7 (rw,sync,root_squash)
**/data * (rw,sync,root_squash)
exportfs -rv
```
**Client
```
dnf install nfs-utils rpcbind
systemctl start rpcbind
showmount -e x.x.x.x
mkdir /mnt/data
mount x.x.x.x:/data /mnt/data
df -h
```
# Samba
**Server
```
dnf install samba samba-client samba-common
firewall-cmd --add-service=samba --permanent
firewall-cmd --reload
mkdir -p /data2
chmod a+rwx /data2
chmod 770 /data3
chown -R nobody:nobody /data2
chown -R USER:GROUP /data3
chcon -t samba_share_ /data2
Modify configuration for samba at /etc/samba/smb.conf
```
```
[global]
    workgroup = WORKGROUP
    netbios name = centos
    security = user
    map to guest = bad user
    dns proxy = no

[guest_share]
    path = /data2
    browsable = yes
    writable = yes
    guest ok = yes
    guest only = yes
    read only = no

[users_share]
    path = /data3
    valid users = @samba
    browsable = yes
    writable = yes
    guest ok = no
```
```
testparm
```
**Client
```
dnf install cifs-utils samba-client
mkdir -p /mnt/data2
mount -t cifs //192.168.0.10/guest_share /mnt/data2
```
## Shell
**Get current shell
```
echo $0
cat /etc/passwd | grep YOURUSERNAME
```

**List available shells
```
cat /etc/shells
```

## Logs
Successful and non-successful login attempts:
```
/var/log/auth.log       # Debian/Ubuntu
         secure.log     # Red Hat/CentOS
```

## Network
### Configure network (Red Hat)
```
General
nmcli con show PROFILENAME  # Display settings from profile
nmcli con up INTERFACE      # Load new settings from profile

IPv4
nmcli con mod INTERFACE ipv4.addresses IPADDRESS/XX,IPADDRESS/XX        # Primary (or seconday IP address)
nmcli con mod INTERFACE ipv4.gateway IPADDRESS      # Sets gateway
nmcli con mod INTERFACE ipv4.dns IPADDRESS,IPADDRESS        # Sets DNS servers
nmcli con mod INTERFACE ipv4.dns-search DOMAIN      # Sets search domain aka. DNS suffix
nmcli con mod INTERFACE ipv4.method manual      # Set either static (manual) IP address or a address from DHCP (auto).

IPv6
nmcli con mod INTERFACE ipv6.addresses IPADDRESS/XX,IPADDRESS/XX        # Primary (or seconday IP address)
nmcli con mod INTERFACE ipv6.dns IPADDRESS,IPADDRESS        # Sets DNS servers
nmcli con mod INTERFACE ipv6.dns-search DOMAIN     # Sets search domain aka. DNS suffix
nmcli con mod INTERFACE ipv6.method manual      # Set either static (manual) IP address, a address from DHCP (auto) or disabled.

OR

Use nmtui 😉
```

## Firewall
### Configure firewall (Red Hat)
```
firewall-cmd --list-all                             # List all firewall rules
firewall-cmd --get-zones                            # List firewall zones

firewall-cmd --get-active-zone                      # Check current firewall zone
firewall-cmd --zone=public --list-all               # List all firewall rules for the public zone

firewall-cmd --get-services                         # List all firewall appliable services rules
firewall-cmd --add-service=http --permanent         # Add service to the firewall
firewall-cmd --remove-service=http --permanent      # Remove service to the firewall
firewall-cmd --add-port=80/tcp --permanent          # Add port to the firewall
firewall-cmd --remove-port=80/tcp --permanent       # Remove port to the firewall
firewall-cmd --add-icmp-block-inversion             # Block ICMP (ping)
firewall-cmd --remove-icmp-block-inversion          # Allow ICMP (ping)

firewall-cmd --reload                               # Reload firewall rules
firewall-cmd --complete-reload                      # Reload the firewall service, which also terminate active connections
firewall-cmd --runtime-to-permanent                 # Make current configuration permanent
```

### Advanced firewall (Red Hat)
**Add custom service to firewalld**
1. Copy any XML file under /usr/lib/firewalld/services/ and modify it.
2. Restart the firewall:
> systemctl restart firewalld
3. List all services - you should find you newly added service:
> firewall-cmd --get-services
4. Add the service as a rule to the firewall and save it permanently:
> firewall-cmd --add-service=XX --permanent

## Advanced networking
### IP forwarding
```
sysctl -w net.ipv4.ip_forward=1 OR net.ipv6.conf.all.forwarding = 1
```
Permanent save
1. Edit /etc/sysctl.conf
2. Add net.ipv4.ip_forward = 1
3. sysctl -p /etc/sysctl.conf 

## Logging
**Log a specific message to system log files**
```
$ logger -s "Message"     
```

**Log a specific message to Kernel log buffer (useful for dmesg debugging)**
```
# echo "Message" >> /dev/kmsg
```

## Scheduling
### Cron

**Allow or disallow access to crontab**
> Based on existence of /etc/cron.allow and /etc/cron.deny, user is allowed or denied to edit the crontab in below sequence.
> 
>     If cron.allow exists - only users listed into it can use crontab
>     If cron.allow does not exist - all users except the users listed into cron.deny can use crontab
>     If neither of the file exists - only the root can use crontab
>     If a user is listed in both cron.allow and cron.deny - that user can use crontab.
> 

source: https://www.thegeeksearch.com/how-cron-allow-and-cron-deny-can-be-user-to-limit-access-to-crontab-for-a-particular-user/

```
echo USER >>/etc/cron.allow      # Allow specific user(s) to use crontab
echo ALL >>/etc/cron.deny       # Deny all users from using crontab except those in cron.allow
```

### At
**Enable or disable the atd service**
```
systemctl status atd
```

**Allow or disallow access to at**
```
echo USER >>/etc/at.allow      # Allow specific user(s) to use at
echo ALL >>/etc/at.deny       # Deny all users from using at except those in at.allow
```


## Performance tuning
### Tuned
**List tuned profiles**
```tuned-adm list```

**View current tuned profile active**
```tuned-adm active```

**Active tuned profile**
```tuned-adm profile powersave```

**Disable tuned profile**
```tuned-adm off```

**Get tuned profile recommendation**
```tuned-adm recommend```

## Storage
### Generic
```
lsblk       # List block devices
blkid       # List UUID for block devices
```

### SWAP
```
swapoff -a                                      # Disable all SWAP devices
```

### Mounting
```
mount -o loop /PATH/TO/ISO /MOUNTPATH           # Mount a ISO image on desired path
mount -a                                        # Remount all entries in /etc/fstab
```

### LVM
```
vgcreate NAMEOFVOLUMEGROUP /dev/BLOCKDEVICE                                     # Create new VG on block device - a PV is automatically created 
lvcreate NAMEOFVOLUMEGROUP --name NAMEOFLOGICALVOLUME --size 50GB               # Create new LV with 50 GB size
lvresize /dev/mapper/NAMEOFVOLUMEGROUP-NAMEOFLOGICALVOLUME --size 100GB         # Resize LV to new size - add -r to resize underlaying file system
mkfs.ext4 /dev/mapper/NAMEOFVOLUMEGROUP-NAMEOFLOGICALVOLUME                     # Create a ext4 file system on the new LV
mkfs.xfs /dev/mapper/NAMEOFVOLUMEGROUP-NAMEOFLOGICALVOLUME                      # Create a xfs file system on the new LV
resize2fs /dev/mapper/NAMEOFVOLUMEGROUP-NAMEOFLOGICALVOLUME                     # Resize underlaying file system
```

## Boot
### Boot options
```
systemctl get-default                       # Get current setting
systemctl set-default graphical.target      # Set to GUI
systemctl set-default multi-user.target     # Set to CLI
```

### Grub2
```
grub2-mkconfig -o /boot/grub2/grub.cfg
```

## Git
**Revert last commit without removing any changes**
```
git reset --soft HEAD~1

OR

git reset --soft <hash of commit>
```

**Revert last commit and changes made since last commit (POTENTIALLY DANGEROUS!)**
```
git reset --hard HEAD~1

OR

git reset --hard <hash of commit>
```

**Remove unstaged files**
```
git reset @
```

**Add all changes to staged**
```
git add *
```

**Add all changed to staged including deleted files**
```
git add --all .
```

**Force push**
```
git push --force
```

**Change commit author**
```
git commit --amend --reset-author
```

**Commit with comment**
```
git commit -m "Message"
```

## SSH
**Generate new keys
```
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -C "comment"

OR

ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "comment"
```

**Copy you keys to a remote computer**
```
ssh-copy-id USER@192.168.1.120 -i .ssh/id_rsa.pub
```