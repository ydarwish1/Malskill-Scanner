# static-site-deploy

Builds the docs site into a scratch directory and syncs it to S3.

```
BUCKET=docs.example.com scripts/deploy.sh
```

The scratch directory lives under `$TMPDIR` and is removed before and after the build.
