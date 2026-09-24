# xmip-core-runtime

The Xmip Service and the Xmip Host Services it supervises: configuration, execution tree, startup validation, host-process planning, and capability and Module registries.

The runtime composes capabilities and invokes Handlers through the application binary interface (ABI). Technology implementations remain in their capability repositories.

Its native library is what the operator surfaces load (`xmip_operate.h`): the table they read a node through, starting and validating a node, section 7 — the rules a surface calls instead of keeping its own — and section 8, a publication read for a surface. `src/rule.rs` and `src/rule/node.rs` forward each rule to the crate that owns it (`observe::Scope`, `observe::Health`, `observe::Standing`, `observe::Counted`, `observe::capability`, `node::Stage`, `node::Capability`), one call per export and no rule of its own; `src/publication.rs` reads a publication by `observe::Publication` and hands it out as the header's values (ADR-0027 and ADR-0052, amendments 2026-09-24). The Message treatments are `xmip-core-message`'s (`MessageTreatment::CONVERSATION`, `BUSINESS`, `PASS_THROUGH`); `src/generation.rs` keeps only what a generation is.

`architecture.toml` carries the maturity; this file does not repeat it.
