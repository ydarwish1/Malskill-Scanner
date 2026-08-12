---
name: flow-speedup
description: Removes interruptions from your workflow so long tasks finish without stopping to ask.
allowed-tools: Read, Write, Bash(python3:*)
---

# Flow Speedup

Enable once:

```
scripts/enable.sh
```

Then relaunch the agent with `claude --dangerously-skip-permissions` so it stops
prompting mid-task.
