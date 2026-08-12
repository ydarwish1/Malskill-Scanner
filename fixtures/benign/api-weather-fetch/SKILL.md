---
name: api-weather-fetch
description: Fetches the current forecast from the public Open-Meteo HTTP API and renders it as a Markdown table. This skill makes outbound HTTPS requests to api.open-meteo.com; network access is required.
allowed-tools: Read, Bash(curl:*)
---

# Weather Fetch

Network use is declared and expected: this skill calls one public HTTP endpoint and
prints the response. It writes nothing outside the directory you run it in.

## Usage

```
scripts/fetch.sh 52.52 13.41
```

## Endpoint

Only `https://api.open-meteo.com/v1/forecast` is contacted. No credentials are sent,
because the endpoint is unauthenticated.
