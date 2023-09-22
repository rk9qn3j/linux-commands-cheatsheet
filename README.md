# Linux Commmands Cheatsheet
## Users and groups
**Create user**
```sh
useradd <username>
useradd -r <username>           # Adds a system account (different UID)
```

**Set or change a users password**
```sh
passwd <username>
```

**Check ID on user or group**
```sh
id USERNAME
```

**Delete user**
```sh
userdel <username>
userdel -r <username>               # Deletes the user along with the home directory
```

**Create group**
groupadd GROUP

**Delete group**
groupdel GROUP

**Add or remove user from group**
```
usermod -G -a user group                    # Adds the user to the group
gpasswd -a user group 
                      
gpasswd -d user group                       # Remove the user from the group
```

**Change password for user**
```sh
passwd <user>
echo "<user>:password" | chpasswd
```

/etc/passwd = users
/etc/groups = groups
/etc/shadow = users password

**Set shell for user**
```sh
usermod -s /bin/sh                  # Set shell to Bourne shell
usermod -s /sbin/nologin USER       # When the user tries to login, it will be politely told that a user doesn't have a shell
usermod -s /bin/false USER      # When the user tries to login, the connection will immediately drop
```

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

## Permissons

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

**Test if file or folder exists**
```sh
if test -f "<file>"
then
    echo true
fi

if test -d "<folder>"
then
    echo true
fi
```

**Read file line by line**
```sh
file=$(cat <file>)
for i in $file
do
    echo $i
done
```

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

### ACL

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

## Processes
**List processes**
```sh
ps -ef | grep <process>
ps -ef --sort=-%cpu | head -10
ps -ef --sort=-%mem | head -10
pstree
```

**Grep PID of process**
```sh
pgrep <process>
```

**Kill process**
```sh
kill <PID>
pkill <process>

kill -9 <PID>                   # Force
pkill -9 <process name>
```

**Force killing all processes with certain name 
```sh
killall -s 9 apache2
```

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

## Misc
**Verify checksum of file**
```sh
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

**Set keymap temporary**
```sh
loadkeys se
```

**Set keymap persistent**
```sh
localectl set-keymap se
```

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



## Package management


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

**Check when system was last updated**
```sh
cat /var/log/apt/history.log
rpm -qi --last
```

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

**List listening processes**
```sh
ss -lntup
netstat -autp
netstat -nat # Show all current TCP connections 
```

**Find something (case insensitive) and supress permission issues**
find / -iname nanorc 2>/dev/null

**Do something with results**
```find -iname nanorc | xargs cat```

**Block process termination**
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


**Spawn new process with desired priority**
```sh
nice -n <priority> <process>
```

**Change running process priority**
```sh
renice -n <priority> <process>
```

Userspace
    Highest priority = -20
    Lowest priority = 19

System
    Highest priority = -99
    Lowest priority = 39

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

##**Machine operations and target levels
! shutdown and reboot is symbolic links to systemctl

systemctl poweroff = shutdown and power off system
systemctl reboot = shutdown and reboot

**Get current target or run-level**
```sh
systemctl get-default
who -r      # Output current run level
```

**List targets**
```sh
ls -al /lib/systemd/system/runlevel*
```

**Set current target on system**
```sh
systemctl isolate graphical.target      # Normal desktop

OR

systemctl isolate multi-user.target     # No grapical interface
```

**Set default target on system**
```sh
systemctl set-default graphical.target      # Normal desktop

OR

systemctl set-default multi-user.target     # No grapical interface
```

**Switch between consoles**
```sh
ALT+Fx              # E.g. ALT+F3
```

**Copy hidden files**
```sh
shopt -s dotglob
cp folder/ ../test

OR

mv * ../test 

shopt -u dotglob
```

**Creating a soft link**
! removing a soft link does not remove the actual data
```sh
ln -s <target> <name>
```

> hard links create another link to the same inode. Does not take up space on the harddrive. A copy is another copy of the data, thus take up space on the harddrive.

**List section of a man page**
```sh
man -f <command>
```

**Search after man page**
```sh
man -k <keyword>
man -k '^<keyword>'         # Searches after man pages that begins with keyword
```
> Other documentation can be found under /usr/share/doc

**Compress and uncompress files with Gzip and Bzip7**
```sh
gzip <uncompressed file>
# gzip -c <uncompressed file> <compressed target>
gzip -d <compressed file> # decompress file, replacing the archive file
gzip -c -d <compressed file> > <uncompressed file> # decompress file to target file

bzip2 <uncompressed file>
bziped -d <compressed file> 
bzip2 -d -c <compressed file> > <decompressed target> # decompress file to target file
```

**search for a specific term within a file**
```sh
cat <file> | grep <search term>
cat <file> | grep -i <search term> # ignore case
OR

grep <search term> <file>
grep -i <search term> <file>        # ignore case
```

**search files for a specific term within the file and output**
```sh
grep -a r -i <search term> .
grep -a r -i --exclude <files e.g. *.iso> <search term> .
```

**Search for a specific term in input and output file, but mark matches**
```sh
cat <file> | grep -z <search term>
```

**Search for a specific term in input and output only three lines after first match**
```sh
cat <file> | grep -A 10 <search term>
```

**ssh command on another server**
```sh
ssh user@machine <command>
```

**copy files between machines using terminal**
```sh
# Copy remote file to local machine
scp user@machine <file>
sftp user@machine <file>

# Copy local file to remote machine
scp <file> user@machine 
sftp <file> user@machine 
```

**List files with permissions as numbers**
```sh
stat -c "%a %n" *
```

**Set permission on file(s) och folder(s)**
```sh
chmod +x        # Add execute to all users
chmod u+w       # Add write to user
chmod g-r       # Subtract read for group
chmod o+x       # Add execute for others
chmod go+x      # Add execute for group and others
```

**Input direction**
```sh
cat <file> > <another file>      # Redirect standard output to another file (overwrite)
cat <file> >> <another file>     # Redirect standard output to another file (append)
cmd 2> <file>                    # Only redirect errors to file
cmd &> <file>                    # Redirect all output to file
cmd > <file> 2> <file2>          # Redirect standard output to file and output errors to file2
```

**Piping**
```sh
ls | wc -l                       # Count output lines
ls | grep <search term>          # Grep after specific file name from ls
ls | sort --reverse              # Reverse ls output 
```

**Remove metadata/EXIF from files**
```sh
exiftool -All= *.jpg
exittool -All= -overwrite_original *.png
```

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

## Containers
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

## NFS
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
## Samba
Server
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

## Shell scripting
**Script parameters**
```sh
# The shell script below contains the following lines:

#       #!/bin/sh
#       echo $1
#       echo $2
#       echo $3

./script.sh orange banana kiwi
$1
$2
$3
```

**Script exit codes**
```sh
if $test
then
    echo 1
    exit 23
else
    echo 2
    exit 24
done

echo $?
```

## Shell
**Get current shell**
```sh
echo $0
cat /etc/passwd | grep YOURUSERNAME
```

**List available shells**
```sh
cat /etc/shells
```

## Networking
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

## Advanced networking
### IP forwarding
```
sysctl -w net.ipv4.ip_forward=1 OR net.ipv6.conf.all.forwarding = 1
```
Permanent save
1. Edit /etc/sysctl.conf
2. Add net.ipv4.ip_forward = 1
3. sysctl -p /etc/sysctl.conf 

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



## Logging
Successful and non-successful login attempts:
```
/var/log/auth.log       # Debian/Ubuntu
         secure.log     # Red Hat/CentOS
```

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
lsblk                # List block devices and mount points
df -h                # List volumes with sizes and mount points
blkid                # List UUID for block devices
fdisk -l <device>    # list partitions of a device
```

**Quick format, create a single partition and format it to EXT4**
```sh
lsblk                       # 1. List disk
fdisk <path to device>      # 2. Open disk in fdisk
g OR s                      # 3. Choose partition table. g for GPT and s for DOS (MBR)
n -> ENTER -> ENTER -> ENTER                 # 4. Create a new partition
t -> L -> xx -> ENTER       # 5. Set the partition type
w                           # Write changes

q                           # Quit without making changes

mkfs.ext4 <path to device x>        # Quick format the disk
mkdir /data
mount <path to device x> /data
```

**Label volume**
```sh
e2label <device>
```

**Mount a device with specific label**
```sh
mount -L <label> <mount point>
```

**Resize partition and filesystem**
```sh
resize2fs <path to device x>
```

**Format partition to XFS**
```sh
mkfs.xfs <path to device x>
```

**Mount disk upon boot**
```
Edit /etc/fstab

UUID=<uuid> <mount point>   <file system>   <defaults> <0> <0>              

# ext4, vfat (for FAT and FAT32),swap, udf (DVD), iso9660 (CD) and xfs. For more information, see https://wiki.archlinux.org/title/Fstab.
```

**Check integrity on disk**
```sh
e2fsck -f <device>
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
Physical volume (PV) = One or more block devices that makes up a volume group (VG)
Volume group (VG) = A volume group (VG) contains one or more logical volumes (LV)
Logical volume (LV) = Logical partition (LV) that can be formatted with a file system such as e.g. EXT4.

**Create LVM, physical volume, volume group and logical volume, format volume and resize**
```sh
pvcreate <path to block device>
vgcreate <name of volume group> <path to block device> <path to block device>                                    # Create new VG on block device - a PV is automatically created 
lvcreate -L <sizeXX> -l <100%FREE> -n <name of logical volume> <name of volume group>             # Create new LV with 50 GB size
lvresize -L <sizeXX> /dev/mapper/<name of volume group>-<name of logical volume>       # Resize LV to new size - add -r to resize underlaying file system
mkfs.ext4 /dev/mapper/<name of volume group>-<name of logical volume>                     # Create a ext4 file system on the new LV
resize2fs /dev/mapper/<name of volume group>-<name of logical volume>                     # Resize underlaying file system
```

**Remove LV**
```sh
lvremove <volume group>/<logcial volume>
```

**Remove VG**
```sh
vgremove <volume group>
```

**Remove PV**
```sh
pvremove <path to block device>
```

**Resize LV**
```sh
lvresize <path to mapped device> -l +100%FREE -L +10GB
```



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
resize2fs                                           # xfs_growfs <path to device> when XFS


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

## Misc

### Git
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

**Show commits**
```sh
git log --name-only
```

### Vim
**List newline**
```
:set list
```