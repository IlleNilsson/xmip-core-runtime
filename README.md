# xmip-core-runtime

The Xmip Service and the Xmip Host Services it supervises: configuration, execution tree, startup validation, host-process planning, and capability and Module registries.

The runtime composes capabilities and invokes Handlers through the application binary interface (ABI). Technology implementations remain in their capability repositories.

Its native library is what the operator surfaces load (`xmip_operate.h`): the table they read a node through, starting and validating a node, and section 7 — the rules a surface calls instead of keeping its own. `src/rule.rs` forwards each of those to the crate that owns it (`observe::Scope`, `observe::Health` and `observe::Standing`, `node::Stage`), one call per export and no rule of its own (ADR-0027 and ADR-0052, amendments 2026-09-24).

`architecture.toml` carries the maturity; this file does not repeat it.
