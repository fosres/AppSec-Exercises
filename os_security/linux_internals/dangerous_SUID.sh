#!/bin/bash
# Known safe SUID binaries
SAFE_SUIDS=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/su"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
)

# Find all SUID binaries and flag unknown ones


BINS="$(find /usr/bin/ -perm /4000)"

for bin in $BINS
	do
		echo "$bin"
	done
