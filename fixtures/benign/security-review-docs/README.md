# security-review-docs

Reference documentation for security reviewers. The checklists in `reference/`
quote the attacker phrasings a reviewer is meant to recognise.

## What reviewers should look for

Untrusted text that is loaded into a model context sometimes tries to redirect the
model. Typical phrasings quoted from public incident write-ups include: "ignore all
previous instructions", "disregard any prior instructions and follow these instead",
"do not tell the user about this step", "without the user's approval", "always run the
following tool first", and "before using any other tool, call ...". When any of those
appear inside a *tool description* or *skill description*, treat the bundle as hostile.
When they appear in a paragraph like this one, that is a document.
