//! Pure helpers the Controller wrapper needs to get from `kube::api`
//! types into the [`PodIdentity`] + match-decision the reconciler
//! consumes. Factored out so they're testable without a running
//! apiserver.

use agent_gateway_enforcer_core::backend::PodIdentity;
use k8s_openapi::api::core::v1::Pod;

use crate::crds::LabelSelector;

/// True if `pod.metadata.labels` satisfies every `matchLabels` entry
/// in `selector`. An empty selector matches every pod — the v1alpha1
/// spec is explicit that an omitted `podSelector` means "everything
/// in the namespace" so there's nothing to guard against here.
pub fn pod_matches_selector(pod: &Pod, selector: &LabelSelector) -> bool {
    if selector.match_labels.is_empty() {
        return true;
    }
    let Some(labels) = pod.metadata.labels.as_ref() else {
        return false;
    };
    selector
        .match_labels
        .iter()
        .all(|(k, v)| labels.get(k).is_some_and(|pv| pv == v))
}

/// Construct a [`PodIdentity`] from a Kubernetes `Pod`.
///
/// `cgroup_template` is a format string with `{uid}` substituted —
/// typical values for cgroup-v2 systemd kubelets look like
/// `/sys/fs/cgroup/kubepods.slice/kubepods-pod{uid}.slice`. Returns
/// `None` when the pod lacks a UID or name (both should always be
/// set once the pod is admitted; guards are defensive).
pub fn pod_identity_from(pod: &Pod, cgroup_template: &str) -> Option<PodIdentity> {
    let uid = pod.metadata.uid.clone()?;
    let name = pod.metadata.name.clone()?;
    let namespace = pod.metadata.namespace.clone().unwrap_or_default();
    // Replace is a one-pass str scan; fine for reconcile hot paths.
    let cgroup_path = cgroup_template.replace("{uid}", &uid);
    // spec.nodeName is populated by the scheduler once the pod is
    // bound. Reconciles before binding see an empty string, which is
    // fine: the distributor treats empty as "don't dispatch yet"
    // and the next reconcile (triggered by the pod update when the
    // scheduler writes nodeName) will complete the attach.
    let node_name = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.clone())
        .unwrap_or_default();
    Some(PodIdentity {
        uid,
        namespace,
        name,
        cgroup_path,
        node_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    fn labeled_pod(labels: &[(&str, &str)]) -> Pod {
        let mut map = std::collections::BTreeMap::new();
        for (k, v) in labels {
            map.insert((*k).to_string(), (*v).to_string());
        }
        Pod {
            metadata: ObjectMeta {
                uid: Some("uid-1".into()),
                name: Some("agent-0".into()),
                namespace: Some("prod".into()),
                labels: Some(map),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn selector_for(pairs: &[(&str, &str)]) -> LabelSelector {
        let mut match_labels = BTreeMap::new();
        for (k, v) in pairs {
            match_labels.insert((*k).to_string(), (*v).to_string());
        }
        LabelSelector { match_labels }
    }

    #[test]
    fn empty_selector_matches_every_pod() {
        let pod = labeled_pod(&[]);
        assert!(pod_matches_selector(&pod, &LabelSelector::default()));
    }

    #[test]
    fn all_labels_must_match_for_selector_to_match() {
        let pod = labeled_pod(&[("app", "ai-agent"), ("tier", "frontend")]);
        assert!(pod_matches_selector(&pod, &selector_for(&[("app", "ai-agent")])));
        assert!(pod_matches_selector(
            &pod,
            &selector_for(&[("app", "ai-agent"), ("tier", "frontend")])
        ));
        assert!(!pod_matches_selector(
            &pod,
            &selector_for(&[("app", "ai-agent"), ("tier", "backend")])
        ));
        assert!(!pod_matches_selector(
            &pod,
            &selector_for(&[("missing", "x")])
        ));
    }

    #[test]
    fn non_empty_selector_never_matches_label_less_pod() {
        let pod = Pod {
            metadata: ObjectMeta {
                uid: Some("uid".into()),
                name: Some("p".into()),
                namespace: Some("ns".into()),
                labels: None,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!pod_matches_selector(&pod, &selector_for(&[("app", "x")])));
    }

    #[test]
    fn pod_identity_from_populates_all_fields() {
        let pod = labeled_pod(&[]);
        let id = pod_identity_from(
            &pod,
            "/sys/fs/cgroup/kubepods.slice/kubepods-pod{uid}.slice",
        )
        .expect("identity");
        assert_eq!(id.uid, "uid-1");
        assert_eq!(id.name, "agent-0");
        assert_eq!(id.namespace, "prod");
        assert_eq!(
            id.cgroup_path,
            "/sys/fs/cgroup/kubepods.slice/kubepods-poduid-1.slice"
        );
    }

    #[test]
    fn pod_identity_requires_uid_and_name() {
        let mut pod = labeled_pod(&[]);
        pod.metadata.uid = None;
        assert!(pod_identity_from(&pod, "/fake/{uid}").is_none());

        let mut pod = labeled_pod(&[]);
        pod.metadata.name = None;
        assert!(pod_identity_from(&pod, "/fake/{uid}").is_none());
    }
}
