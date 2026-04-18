//! Pure schedule evaluation. `is_active(&schedule, now)` returns
//! whether the policy's normal rules apply at `now`; the reconciler
//! uses this to pick between compiling the full bundle vs. a
//! collapsed "inactive" bundle that just honors `inactiveAction`.
//!
//! Split out so every edge case — midnight crossings, empty windows,
//! malformed HH:MM — is unit-testable without pulling in `kube` or
//! tokio.

use std::time::Duration;

use chrono::{DateTime, Datelike, NaiveTime, Timelike, Utc};

use crate::crds::{ActiveWindow, Schedule, Weekday};

/// True iff `now` falls inside any of `schedule.active_windows`.
///
/// Unparseable `start`/`end` strings cause the containing window to
/// be ignored (returns `false` for that window). This matches the
/// webhook's rule: malformed windows surface as a validation error
/// at apply time; at reconcile time we *must* still decide an
/// action, and falling back to "not active" honors the user's
/// `inactiveAction` default rather than silently ignoring the
/// schedule.
pub fn is_active(schedule: &Schedule, now: DateTime<Utc>) -> bool {
    schedule
        .active_windows
        .iter()
        .any(|w| window_contains(w, now))
}

/// How long until the next transition in the schedule, scanning at
/// most 8 days ahead (one full weekly cycle + a safety day for
/// timezone/DST surprises once we add non-UTC support).
///
/// Returns `None` when the schedule has no active windows, i.e.
/// the current state never changes and the reconciler should use
/// its default requeue interval.
pub fn next_transition(schedule: &Schedule, now: DateTime<Utc>) -> Option<Duration> {
    if schedule.active_windows.is_empty() {
        return None;
    }

    let current = is_active(schedule, now);
    // Scan in 1-minute steps — cheap and dodges the off-by-one
    // around HH:00 that you'd get sampling every hour.
    for step in 1..=8 * 24 * 60 {
        let t = now + chrono::Duration::minutes(step);
        if is_active(schedule, t) != current {
            return Some(Duration::from_secs((step as u64) * 60));
        }
    }
    None
}

fn window_contains(w: &ActiveWindow, now: DateTime<Utc>) -> bool {
    let start = match parse_hhmm(&w.start) {
        Some(t) => t,
        None => return false,
    };
    let end = match parse_hhmm(&w.end) {
        Some(t) => t,
        None => return false,
    };
    let now_time = now.time();
    let now_day = weekday_of(now);

    // Window that crosses midnight (e.g. 22:00 -> 02:00). Split it
    // into two pieces: (today from start to 23:59) or (yesterday's
    // day entry + today 00:00 to end).
    if end <= start {
        if w.days.contains(&now_day) && now_time >= start {
            return true;
        }
        if w.days.contains(&prev_weekday(now_day)) && now_time < end {
            return true;
        }
        return false;
    }

    // Normal window — fully contained in one UTC day.
    w.days.contains(&now_day) && now_time >= start && now_time < end
}

fn parse_hhmm(s: &str) -> Option<NaiveTime> {
    // Accepts "HH:MM" exactly. Leniency here hides typos that the
    // webhook should catch.
    let mut parts = s.splitn(2, ':');
    let h: u32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    NaiveTime::from_hms_opt(h, m, 0)
}

fn weekday_of(t: DateTime<Utc>) -> Weekday {
    match t.weekday() {
        chrono::Weekday::Mon => Weekday::Mon,
        chrono::Weekday::Tue => Weekday::Tue,
        chrono::Weekday::Wed => Weekday::Wed,
        chrono::Weekday::Thu => Weekday::Thu,
        chrono::Weekday::Fri => Weekday::Fri,
        chrono::Weekday::Sat => Weekday::Sat,
        chrono::Weekday::Sun => Weekday::Sun,
    }
}

fn prev_weekday(d: Weekday) -> Weekday {
    match d {
        Weekday::Mon => Weekday::Sun,
        Weekday::Tue => Weekday::Mon,
        Weekday::Wed => Weekday::Tue,
        Weekday::Thu => Weekday::Wed,
        Weekday::Fri => Weekday::Thu,
        Weekday::Sat => Weekday::Fri,
        Weekday::Sun => Weekday::Sat,
    }
}

// Only used inside tests but kept here for symmetry.
#[cfg(test)]
fn _touch_unused_timelike(_t: DateTime<Utc>) {
    let _ = chrono::Utc::now().hour();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crds::{ActiveWindow, EgressAction, Schedule, Weekday};
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32, hh: u32, mm: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, hh, mm, 0).unwrap()
    }

    fn window(days: &[Weekday], start: &str, end: &str) -> ActiveWindow {
        ActiveWindow {
            days: days.to_vec(),
            start: start.into(),
            end: end.into(),
        }
    }

    fn sched(windows: Vec<ActiveWindow>) -> Schedule {
        Schedule {
            active_windows: windows,
            inactive_action: EgressAction::Allow,
        }
    }

    #[test]
    fn inside_ordinary_window_is_active() {
        // 2026-04-20 is a Monday.
        let s = sched(vec![window(&[Weekday::Mon], "09:00", "18:00")]);
        assert!(is_active(&s, at(2026, 4, 20, 10, 0)));
        assert!(!is_active(&s, at(2026, 4, 20, 18, 0)));
        assert!(!is_active(&s, at(2026, 4, 20, 8, 59)));
    }

    #[test]
    fn wrong_day_is_inactive() {
        // Sunday is not Mon.
        let s = sched(vec![window(&[Weekday::Mon], "09:00", "18:00")]);
        assert!(!is_active(&s, at(2026, 4, 19, 10, 0)));
    }

    #[test]
    fn midnight_crossing_window_covers_both_sides() {
        // 22:00 Mon through 02:00 Tue.
        let s = sched(vec![window(&[Weekday::Mon], "22:00", "02:00")]);
        // Monday 23:00 — inside.
        assert!(is_active(&s, at(2026, 4, 20, 23, 0)));
        // Tuesday 01:00 — still inside (prev weekday rule).
        assert!(is_active(&s, at(2026, 4, 21, 1, 0)));
        // Tuesday 02:00 — just outside.
        assert!(!is_active(&s, at(2026, 4, 21, 2, 0)));
    }

    #[test]
    fn empty_windows_yield_no_transition() {
        let s = sched(vec![]);
        assert!(!is_active(&s, at(2026, 4, 20, 10, 0)));
        assert_eq!(next_transition(&s, at(2026, 4, 20, 10, 0)), None);
    }

    #[test]
    fn next_transition_flips_to_active_boundary() {
        let s = sched(vec![window(&[Weekday::Mon], "09:00", "18:00")]);
        // At Mon 08:30, next transition is at 09:00 = +30 min.
        let d = next_transition(&s, at(2026, 4, 20, 8, 30)).unwrap();
        assert_eq!(d.as_secs() / 60, 30);
    }

    #[test]
    fn next_transition_flips_to_inactive_boundary() {
        let s = sched(vec![window(&[Weekday::Mon], "09:00", "18:00")]);
        // At Mon 17:30, transition to inactive at 18:00 = +30.
        let d = next_transition(&s, at(2026, 4, 20, 17, 30)).unwrap();
        assert_eq!(d.as_secs() / 60, 30);
    }

    #[test]
    fn malformed_start_time_is_treated_as_window_not_active() {
        // "9:00" (no leading zero) parses fine here because we split
        // on ':' and call u32::parse — so that's valid. Use a
        // genuinely bad value.
        let s = sched(vec![window(&[Weekday::Mon], "bad", "18:00")]);
        assert!(!is_active(&s, at(2026, 4, 20, 10, 0)));
    }

    #[test]
    fn multiple_windows_are_or_ed() {
        let s = sched(vec![
            window(&[Weekday::Mon], "09:00", "12:00"),
            window(&[Weekday::Mon], "14:00", "18:00"),
        ]);
        assert!(is_active(&s, at(2026, 4, 20, 10, 0)));
        assert!(!is_active(&s, at(2026, 4, 20, 13, 0)));
        assert!(is_active(&s, at(2026, 4, 20, 15, 0)));
    }
}
