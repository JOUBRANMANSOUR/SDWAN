# Evidence model

State kinds are `configured`, `desired`, `applied`, `observed`, and `derived`.
Sources identify their source type and observation time. Each fact has an opaque
request-scoped ID in the form `<request-id>:fact:<ordinal>` and references a source.

An evidence bundle is created per chat message and stores tool calls, typed facts,
sources, unknowns, limitations, and final validation metadata. It is owned by the
chat session actor and is finalized once; browser tokens, signed context tokens,
private keys, credentials, and environment values are never stored.
