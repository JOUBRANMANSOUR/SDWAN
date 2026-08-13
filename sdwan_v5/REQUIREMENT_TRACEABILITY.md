# Requirement traceability

The initial requirement-to-code-and-test matrix is in [`docs/PRE_IMPLEMENTATION.md`](docs/PRE_IMPLEMENTATION.md). This document is updated with exact test names and saved evidence paths as each implementation phase completes.

Every mandatory ID has a positive test, a negative test and an Ubuntu evidence command. The permanent source of truth for those IDs is the persistent policy/route or ZTP store, never the Ryu packet-in loop or the NFQUEUE callback.
