# KARST — backlog (not started)

A running checklist of agreed-but-not-started work. Ordered roughly by priority.
Started items move into a commit + a channel post; done items drop off here and land
in [STATUS.md](STATUS.md).

## Delivery / resilience

- [ ] **Send-side multi-homing** · _priority 1 · medium_
  Receiving already polls every configured relay; make SENDING deposit on all relays shared
  with the recipient (or fail over to a backup) so a blocked/down primary doesn't stop you
  sending — only receiving is resilient today.

## Privacy / metadata minimization

- [ ] **Cover traffic + response padding (Loopix-style)** · _large_
  Poll timing is already jittered; the next layer is Poisson cover loops + padding the relay's
  fetch-response size, so an observer can't read "active vs idle" from traffic volume.
