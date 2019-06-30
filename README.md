# checkperms
A small tool to check file permissions in a Linux environment. The user running the command must have
enought rights to check all files permissions.

## Example 1
Show files that a user can't edit in his home folder:

`./checkperms-bin -u user1 -p /home/user1/ -m 7 -l -n`

`DENIED 7 /home/user1/Documents/VM/debian9.qcow2`

## Example 2
Show files that a user can edit in another one's home folder:

`./checkperms-bin -u user1 -p /home/user2/ -m 7 -l -y`
