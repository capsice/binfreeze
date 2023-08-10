# binfreeze

A potentially system-breaking tool for paranoid Linux sysadmins.

## Why?

I recently set up a honeypot and allowed scanners of all kinds to attack me. From my extensive logging of these attempts, I noticed some commonalities between most of them, namely that they were mostly based on (duh) exploiting some sort of reverse execution vulnerability to spawn a shell in one way or another, wget some binaries from their servers and then execute them.

Now, there are a million ways to prevent these things from happening, or at least to minimise their potential damage, such as keeping your software up to date and your privileges under control, but the use of zero-day exploits to compromise systems has been on the rise recently.

This may be incredibly inconvenient in systems that are constantly changing, but my intention is to allow system administrators to freeze the binaries allowed to run on their systems by taking snapshots whenever necessary, and to forbid the execution of unexpected things in production environments, thereby preventing sneaky intrusions.

## Usage

```
binfreeze 0.0.1
usage: binfreeze [options]
options:
        -v              verbose
        -g              generate config to stdout
        -h              show this usage information
        -n              do not block executables if they change
        -a <conf>       specify configuration file for programs to allow
        -b <conf>       specify configuration file for programs to block
```

### Block on change

If binfreeze is running with a list of allowed programs, and one of the files in that list changes its content, it will be blocked by default.

You can disable this behavior with the `-n` flag.

### As service

You can run binfreeze as a service with your favourite init system, but be very careful as it is incredibly easy to accidentally lock up your system by forgetting to allow certain programs or libraries to run.

## Configuration

### Warning

If both -b and -a are used, any program that is on both the block list and the allow list will not be allowed to run, as the block list takes precedence.

Also, for the love of God, if you're running an allow list only, don't forget to add `ld.so` to it. Otherwise your system will probably crash.

```
realpath "$(which ld.so)" >> allow.conf
```
---

binfreeze accepts its rules as a file with line-separated paths to executables. Globbing is not supported.

Here's a simple example for reference:

```
# /etc/binfreeze/allow.conf
# oh, did I mention it supports comments?
/usr/bin/ls
/home/capsice/.local/bin/pw
```

You can create a simple allow list containing all of your system executables by doing something like this:

```
find / -type f -perm /111 | sort -u  > /etc/binfreeze/allow.conf
```

And then run binfreeze like so:

```
binfreeze -a /etc/binfreeze/allow.conf
```

After this you can check that if you create a new executable file of any type in the system, it won't be possible to run it, even with root permissions.

```
[capsice@pc ~]$ touch a
[capsice@pc ~]$ chmod +x a
[capsice@pc ~]$ ./a 
bash: ./a: Operation not permitted

[capsice@pc ~]$ su
Password: 
[capsice@pc capsice]# ./a 
bash: ./a: Operation not permitted

```