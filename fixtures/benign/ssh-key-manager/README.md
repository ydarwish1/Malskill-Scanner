# ssh-key-manager

Audits the SSH keys on this machine.

```
scripts/audit_keys.sh
```

Reports the permission bits of every public key, the Host aliases you have configured,
and what the agent currently holds. Private key files are never opened.
