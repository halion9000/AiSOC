---
sidebar_position: 90
title: Forwarded from CORE
description: Sources that CORE reads with its own saved credentials (Huntress, Blumira, ...) and forwards into AiSOC, shown on the Connectors page with real status and counts.
---

# Forwarded from CORE

CORE already holds the credentials for the tools an MSP uses (Huntress, Blumira, and others) and reads them on its own. Instead of copying those
credentials here, CORE posts what it finds into AiSOC's [push inbox](./universal-capture.md) and reports each run's outcome. A source CORE forwards shows
up on the **Connectors** page as a row of type *Forwarded from CORE*, with the same columns as any other connector: health, last sync, events ingested,
errors.

There is nothing to configure here. Connect the tool in CORE; the row appears after CORE's next run (about every five minutes).

## How it works

1. At launch, CORE asks AiSOC for a push token (`python -m app.scripts.ensure_core_feed_token`, label `core-feed`, template `generic-json`).
2. Every few minutes CORE reads each connected source, and posts the new records to `POST /v1/inbox/{token}`.
3. After each run CORE reports the result to `POST /api/v1/inbox/core-feed/{token}/status`. That is what fills the row's health, counts and last sync.

## What the status means

- **Healthy**: CORE's last run read the source and AiSOC accepted the data (which may have been nothing new).
- **Unhealthy**: the last run failed, either reading the source (a bad key, an outage) or delivering to AiSOC. CORE's own message is not shown here; check
  the source in CORE.
- **Events ingested** counts records AiSOC accepted. An updated record (for example a changed status) is sent again and counted again.

AiSOC does not poll these rows, because it has no credentials for the source: a poll would only overwrite what CORE reported.
