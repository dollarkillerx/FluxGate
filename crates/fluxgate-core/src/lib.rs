//! # fluxgate-core
//!
//! Shared domain models for FluxGate — the high-performance reverse proxy and
//! programmable WAF built on Pingora.
//!
//! These types are intentionally decoupled from any transport or storage layer.
//! The admin API (`fluxgate-admin`) serializes them over JSON-RPC, and the
//! proxy runtime is expected to consume the same structures when wiring up the
//! real data plane. Keeping them here means the admin console and the runtime
//! never drift out of sync.

pub mod models;

pub use models::*;
