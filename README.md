# Binfreeze

A potentially system-breaking tool for paranoid Linux sysadmins.

## Why?

I recently set up a honeypot and allowed scanners of all kinds to attack me. From my extensive logging of these attempts, I noticed some commonalities between most of them, namely that they were mostly based on (duh) exploiting some sort of reverse execution vulnerability to spawn a shell in one way or another, wget some binaries from their servers and then execute them.

Now, there are a million ways to prevent these things from happening, or at least to minimise their potential damage, such as keeping your software up to date and your privileges under control, but the use of zero-day exploits to compromise systems has been on the rise recently.

This may be incredibly inconvenient in systems that are constantly changing, but my intention is to allow system administrators to freeze the binaries allowed to run on their systems by taking snapshots whenever necessary, and to forbid the execution of unexpected things in production environments, thereby preventing sneaky intrusions.

## Build / Install

```
meson setup build
ninja -C build
ninja -C build install
```
When binfreeze is installed, /etc/binfreeze/allow.conf is automatically populated with an up-to-date snapshot of all files on your system that have executable permissions.

## Usage

```
binfreeze 0.1.0
usage: binfreeze [options]
options:
        -v              run in verbose mode
        -h              show this usage information
        -a <conf>       specify a configuration file to allow the execution of programs
        -d <conf>       specify a configuration file to deny the execution of programs
```

### Block on change

If binfreeze is running with a list of allowed programs, and one of the files in that list changes its content, it will be blocked by default.

### As service

You can run binfreeze as a service with your favourite init system, but be very careful as it is incredibly easy to accidentally lock up your system by forgetting to allow certain programs or libraries to run.

## Configuration

### Warning

Binfreeze processes rules from a file containing line-separated paths to executables. You can supply such files using the -a (allow) and -d (deny) options. Note that binfreeze does not support globbing.

Here's a basic example for clarity:

```
# /etc/binfreeze/allow.conf
# oh, did I mention it supports comments?
/usr/bin/ls
/home/capsice/.local/bin/pw
```

If both -d and -a are used, any program that is on both the block list and the allow list will not be allowed to run, as the block list takes precedence.

Also, for the love of God, if you're running an allow list only, don't forget to add `ld.so` to it. Otherwise your system will probably crash.

```
realpath "$(which ld.so)" >> allow.conf
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
