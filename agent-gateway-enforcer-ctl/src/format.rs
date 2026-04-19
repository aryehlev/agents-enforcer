//! Table rendering. Pure — every command builds a `comfy_table::Table`
//! in a helper here so the command code stays about "fetch + filter"
//! and we can snapshot-test the human-readable output.

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};

/// Column specs for a policies list. Keep stable — tooling scrapes
/// `enforcerctl policies list` output in some shops.
pub fn policies_table(rows: &[PolicyRow]) -> String {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "NAMESPACE",
            "NAME",
            "SELECTOR",
            "ENFORCED",
            "HASH",
            "MESSAGE",
        ]);
    for r in rows {
        t.add_row(vec![
            r.namespace.clone(),
            r.name.clone(),
            r.selector.clone(),
            r.enforced_pods.to_string(),
            r.hash.clone(),
            r.message.clone(),
        ]);
    }
    t.to_string()
}

/// A policy as the CLI wants to print it. Built by
/// `commands::policies` from the CR + its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRow {
    pub namespace: String,
    pub name: String,
    pub selector: String,
    pub enforced_pods: u32,
    pub hash: String,
    pub message: String,
}

pub fn violations_table(rows: &[ViolationRow]) -> String {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "NAMESPACE",
            "POD",
            "POLICY",
            "KIND",
            "DETAIL",
            "COUNT",
            "LAST SEEN",
        ]);
    for r in rows {
        t.add_row(vec![
            r.namespace.clone(),
            r.pod.clone(),
            r.policy.clone(),
            r.kind.clone(),
            r.detail.clone(),
            r.count.to_string(),
            r.last_seen.clone(),
        ]);
    }
    t.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViolationRow {
    pub namespace: String,
    pub pod: String,
    pub policy: String,
    pub kind: String,
    pub detail: String,
    pub count: u32,
    pub last_seen: String,
}

pub fn capabilities_table(rows: &[CapabilityRow]) -> String {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "NAMESPACE",
            "NAME",
            "MODELS",
            "TOOLS",
            "BUDGET $",
            "SPENT $",
            "UTIL %",
        ]);
    for r in rows {
        t.add_row(vec![
            r.namespace.clone(),
            r.name.clone(),
            r.models.clone(),
            r.tools.clone(),
            format!("{:.2}", r.budget_usd),
            format!("{:.2}", r.spent_usd),
            // Percentage used — rendered only when a budget is set;
            // `N/A` preserves column layout when cost is disabled.
            r.budget_usd
                .gt(&0.0)
                .then(|| format!("{:.1}", 100.0 * r.spent_usd / r.budget_usd))
                .unwrap_or_else(|| "N/A".to_string()),
        ]);
    }
    t.to_string()
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityRow {
    pub namespace: String,
    pub name: String,
    pub models: String,
    pub tools: String,
    pub budget_usd: f64,
    pub spent_usd: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_table_renders_header_and_rows() {
        let rendered = policies_table(&[PolicyRow {
            namespace: "prod".into(),
            name: "agent".into(),
            selector: "app=ai".into(),
            enforced_pods: 3,
            hash: "abcd1234".into(),
            message: String::new(),
        }]);
        assert!(rendered.contains("NAMESPACE"));
        assert!(rendered.contains("prod"));
        assert!(rendered.contains("abcd1234"));
    }

    #[test]
    fn empty_tables_still_render_a_header() {
        // A CLI that prints nothing when there's nothing to show is
        // ambiguous — is it broken? is the cluster empty? Emit the
        // header row always.
        let rendered = policies_table(&[]);
        assert!(rendered.contains("NAMESPACE"));
        assert!(rendered.contains("NAME"));
    }

    #[test]
    fn capability_row_with_zero_budget_shows_n_a() {
        let rendered = capabilities_table(&[CapabilityRow {
            namespace: "prod".into(),
            name: "agent".into(),
            models: "gpt-4o".into(),
            tools: "search".into(),
            budget_usd: 0.0,
            spent_usd: 0.0,
        }]);
        assert!(rendered.contains("N/A"));
    }

    #[test]
    fn capability_row_with_budget_computes_util() {
        let rendered = capabilities_table(&[CapabilityRow {
            namespace: "prod".into(),
            name: "agent".into(),
            models: "gpt-4o".into(),
            tools: "search".into(),
            budget_usd: 10.0,
            spent_usd: 2.5,
        }]);
        assert!(rendered.contains("25.0"));
    }

    #[test]
    fn violations_table_formats_timestamp_verbatim() {
        let rendered = violations_table(&[ViolationRow {
            namespace: "prod".into(),
            pod: "agent-0".into(),
            policy: "p".into(),
            kind: "EgressBlocked".into(),
            detail: "1.2.3.4:443".into(),
            count: 5,
            last_seen: "2026-04-18T12:34:56Z".into(),
        }]);
        assert!(rendered.contains("2026-04-18T12:34:56Z"));
        assert!(rendered.contains("EgressBlocked"));
    }
}
