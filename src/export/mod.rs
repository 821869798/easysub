mod clash;
mod singbox;

use std::collections::{HashMap, HashSet};

use crate::model::Proxy;

pub use clash::{to_clash, to_clash_full, to_clash_with_base};
pub use singbox::{to_singbox, to_singbox_full, to_singbox_with_base};

fn prepare_nodes(nodes: &[Proxy], append_type: bool, sort: bool) -> Vec<Proxy> {
    let mut nodes = nodes.to_vec();
    if append_type {
        for node in &mut nodes {
            node.name = format!("[{}] {}", node.kind.label(), node.name);
        }
    }
    let mut used = HashSet::with_capacity(nodes.len());
    let mut next = HashMap::<String, usize>::new();
    for node in &mut nodes {
        node.name = node.name.replace('=', "-");
        if used.insert(node.name.clone()) {
            continue;
        }
        let base = node.name.clone();
        let counter = next.entry(base.clone()).or_insert(2);
        loop {
            let candidate = format!("{base} {counter}");
            *counter += 1;
            if used.insert(candidate.clone()) {
                node.name = candidate;
                break;
            }
        }
    }
    if sort {
        nodes.sort_by(|left, right| left.name.cmp(&right.name));
    }
    nodes
}

#[cfg(test)]
mod tests {
    use crate::model::{Proxy, ProxyKind};

    use super::*;

    #[test]
    fn deduplicates_names_like_go_implementation() {
        let mut nodes = Vec::new();
        for name in ["node", "node", "node 2", "node"] {
            let mut proxy = Proxy::new(ProxyKind::Vmess, "example.com".into(), 443);
            proxy.name = name.into();
            nodes.push(proxy);
        }
        let names: Vec<_> = prepare_nodes(&nodes, false, false)
            .into_iter()
            .map(|node| node.name)
            .collect();
        assert_eq!(names, ["node", "node 2", "node 2 2", "node 3"]);
    }
}
