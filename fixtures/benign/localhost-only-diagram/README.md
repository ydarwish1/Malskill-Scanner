# preview-checker

Checks the local preview build over the loopback interface.

Every destination in this bundle is `localhost`, `127.0.0.1` or `::1`, and most of them
are written **without** a URL scheme — `curl localhost:3000` rather than
`curl http://localhost:3000`. That spelling is the trap: the blueprint exempts loopback
destinations, and a matcher that only understands `scheme://host` does not see one here.
