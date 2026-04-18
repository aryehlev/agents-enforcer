//! Per-agent daily spend accounting.
//!
//! In-memory only. Survives the process lifetime, not the pod
//! lifetime — a restart gifts the agent the remainder of the day's
//! budget. That's the intentional trade in v1alpha1: a distributed
//! counter (Redis / a controller-side aggregator) adds coordination
//! overhead we don't want on the hot path. Double-spend on restart
//! is bounded by the max_daily_spend_usd ceiling per replica, so the
//! blast radius is small and proportional to replicas.

use std::collections::HashMap;

use chrono::{DateTime, Datelike, Utc};
use parking_lot::Mutex;

/// Running totals bucketed by (agent_id, UTC day).
#[derive(Default)]
pub struct BudgetStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Current UTC day (`ordinal0()` of the year + year). A day
    /// change clears `spend`.
    day_key: Option<(i32, u32)>,
    /// agent_id -> dollars spent today.
    spend: HashMap<String, f64>,
}

impl BudgetStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the agent's dollars spent today at `now`. Rolls over if
    /// the last recorded day is stale.
    pub fn spent_today(&self, agent_id: &str, now: DateTime<Utc>) -> f64 {
        let mut g = self.inner.lock();
        maybe_roll_day(&mut g, now);
        g.spend.get(agent_id).copied().unwrap_or(0.0)
    }

    /// Add `amount` USD to the agent's running day total, rolling
    /// over first if needed. Returns the new total.
    pub fn add(&self, agent_id: &str, now: DateTime<Utc>, amount: f64) -> f64 {
        let mut g = self.inner.lock();
        maybe_roll_day(&mut g, now);
        let slot = g.spend.entry(agent_id.to_string()).or_insert(0.0);
        *slot += amount;
        *slot
    }

    /// Snapshot every tracked agent's current spend. Used to export
    /// a gauge metric without holding the lock across the loop.
    pub fn snapshot(&self, now: DateTime<Utc>) -> Vec<(String, f64)> {
        let mut g = self.inner.lock();
        maybe_roll_day(&mut g, now);
        g.spend.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

fn maybe_roll_day(inner: &mut Inner, now: DateTime<Utc>) {
    let day = (now.year(), now.ordinal0());
    match inner.day_key {
        Some(prev) if prev == day => {}
        _ => {
            inner.day_key = Some(day);
            inner.spend.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(y: i32, m: u32, d: u32, hh: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, hh, 0, 0).unwrap()
    }

    #[test]
    fn fresh_agent_has_zero_spent() {
        let s = BudgetStore::new();
        assert_eq!(s.spent_today("a", t(2026, 1, 1, 10)), 0.0);
    }

    #[test]
    fn add_accumulates_within_same_day() {
        let s = BudgetStore::new();
        s.add("a", t(2026, 1, 1, 8), 0.25);
        s.add("a", t(2026, 1, 1, 14), 0.75);
        assert_eq!(s.spent_today("a", t(2026, 1, 1, 23)), 1.0);
    }

    #[test]
    fn day_rollover_zeroes_spend() {
        let s = BudgetStore::new();
        s.add("a", t(2026, 1, 1, 20), 5.0);
        // Cross midnight UTC.
        assert_eq!(s.spent_today("a", t(2026, 1, 2, 0)), 0.0);
    }

    #[test]
    fn rollover_applies_to_every_agent() {
        let s = BudgetStore::new();
        s.add("a", t(2026, 1, 1, 10), 1.0);
        s.add("b", t(2026, 1, 1, 10), 2.0);
        s.add("a", t(2026, 1, 2, 10), 0.0); // force the roll
        assert_eq!(s.spent_today("a", t(2026, 1, 2, 11)), 0.0);
        assert_eq!(s.spent_today("b", t(2026, 1, 2, 11)), 0.0);
    }

    #[test]
    fn snapshot_returns_every_tracked_agent() {
        let s = BudgetStore::new();
        s.add("a", t(2026, 1, 1, 10), 1.0);
        s.add("b", t(2026, 1, 1, 10), 2.0);
        let mut snap = s.snapshot(t(2026, 1, 1, 11));
        snap.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(snap, vec![("a".to_string(), 1.0), ("b".to_string(), 2.0)]);
    }
}
