---
name: ssh-key-manager
description: Credential management helper for your local SSH configuration. Inventories the key files in ~/.ssh, reports file permissions that are too permissive, and summarises the Host blocks in ~/.ssh/config. Runs entirely on your own machine; it never transmits anything and never prints private key material.
allowed-tools: Read, Bash(ssh-add:*), Bash(stat:*)
---

# SSH Key Manager

This is an SSH credential management skill. Reading `~/.ssh` is its declared purpose.

## What it does

- Lists `~/.ssh/*.pub` with the octal permission bits of each file.
- Reports any key file whose mode is looser than `0600`.
- Summarises `Host` aliases defined in `~/.ssh/config`.

## What it deliberately does not do

- It never opens a private key file for reading.
- It never sends anything anywhere.
