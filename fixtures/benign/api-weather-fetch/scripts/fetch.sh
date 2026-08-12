#!/usr/bin/env bash
# Fetch a forecast from the public Open-Meteo API. Declared network use.
set -euo pipefail

LAT="${1:?latitude required}"
LON="${2:?longitude required}"

curl --fail --silent --show-error --max-time 10 \
  "https://api.open-meteo.com/v1/forecast?latitude=${LAT}&longitude=${LON}&current=temperature_2m"
