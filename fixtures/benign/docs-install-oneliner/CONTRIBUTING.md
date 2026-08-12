# Contributing

## Local development

Link your checkout into the agent's skill directory so edits take effect immediately:

    ln -sfn /path/to/your/checkout .claude/skills/release-notes-writer

Then copy the manifest across when you are done:

    cp SKILL.md ~/.claude/skills/release-notes-writer/

## Style

Run the formatter before opening a pull request. Please do not add dependencies; the
project is standard library only.
