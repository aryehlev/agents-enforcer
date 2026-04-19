//! Per-runtime uprobe recipes. Each file here owns the knowledge
//! for one TLS stack — which binary fingerprint matches, which
//! symbol names to look up, and which eBPF program each probe
//! should fire. Adding a new runtime is a new file in here plus a
//! line in `plan_all`'s recipe list.

pub mod nodejs;
pub mod openssl;
