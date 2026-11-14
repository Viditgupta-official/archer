use super::contracts::ApiError;
use crate::analyzer::Report;
use serde_json::Value;
use std::{collections::HashMap, path::Path};

struct Projection<'a> {
    root: &'a Path,
    include_text: bool,
    opaque: HashMap<String, String>,
}
impl Projection<'_> {
    fn source_path(&self, text: &str) -> String {
        let clean = text.trim_start_matches("\\\\?\\");
        let root = self.root.to_string_lossy();
        let root = root.trim_start_matches("\\\\?\\");
        Path::new(clean)
            .strip_prefix(root)
            .ok()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "[external source]".into())
    }
    fn text(&mut self, key: &str, text: &str) -> String {
        if key == "file" || key.ends_with("_file") {
            return self.source_path(text);
        }
        if matches!(key, "path" | "scope_prefix") {
            return text.to_owned();
        }
        if matches!(
            key,
            "method"
                | "status"
                | "kind"
                | "category"
                | "classification"
                | "strength"
                | "confidence"
                | "relation"
                | "stage"
                | "enforcement"
                | "code"
        ) {
            return text.to_owned();
        }
        if matches!(
            key,
            "handler" | "handler_path" | "definition_path" | "dimension"
        ) && text.len() <= 256
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-:".contains(&b))
        {
            return text.to_owned();
        }
        let mut normalized = text.to_owned();
        let root = self.root.to_string_lossy();
        for path in [
            root.to_string(),
            root.trim_start_matches("\\\\?\\").to_owned(),
            root.replace('\\', "/"),
        ] {
            normalized = normalized.replace(&path, "[repository]");
        }
        if self.include_text {
            return normalized;
        }
        if let Some(id) = self.opaque.get(&normalized) {
            return id.clone();
        }
        let id = format!("[redacted-evidence-{:06}]", self.opaque.len() + 1);
        self.opaque.insert(normalized, id.clone());
        id
    }
    fn walk(&mut self, value: &mut Value, key: &str) {
        match value {
            Value::String(text) => *text = self.text(key, text),
            Value::Array(values) => {
                for value in values {
                    self.walk(value, key);
                }
            }
            Value::Object(object) => {
                for (key, value) in object {
                    self.walk(value, key);
                }
            }
            _ => {}
        }
    }
}

/// The stable privacy projection is public for API/CLI parity checks. The
/// immutable engine result is authoritative; only its presentation is changed.
pub fn project_json(mut value: Value, root: &Path, include_text: bool) -> Value {
    let graph = value.get_mut("graph").map(Value::take);
    let mut projection = Projection {
        root,
        include_text,
        opaque: HashMap::new(),
    };
    projection.walk(&mut value, "");
    if let Some(mut graph) = graph {
        let mut ids = HashMap::new();
        if let Some(nodes) = graph.get_mut("nodes").and_then(Value::as_array_mut) {
            for (i, node) in nodes.iter_mut().enumerate() {
                if let Some(id) = node.get("id").and_then(Value::as_str) {
                    ids.insert(id.to_owned(), format!("node-{:06}", i + 1));
                }
                projection.walk(node, "");
                node["id"] = Value::String(format!("node-{:06}", i + 1));
            }
        }
        if let Some(edges) = graph.get_mut("edges").and_then(Value::as_array_mut) {
            for edge in edges {
                for key in ["from", "to"] {
                    if let Some(id) = edge
                        .get(key)
                        .and_then(Value::as_str)
                        .and_then(|s| ids.get(s))
                        .cloned()
                    {
                        edge[key] = Value::String(id);
                    }
                }
            }
        }
        value["graph"] = graph;
    }
    value
}

pub fn project_report(
    report: Report,
    root: &Path,
    include_text: bool,
) -> Result<(Value, String), ApiError> {
    let mut graph = report.graph.clone();
    let value = project_json(
        serde_json::to_value(report).map_err(|_| ApiError::internal())?,
        root,
        include_text,
    );
    // Reuse the engine's DOT renderer and preserve all kinds, relations and
    // endpoints. Only identifiers, labels and file presentation are projected.
    if let Some(graph) = &mut graph {
        let nodes = value["graph"]["nodes"]
            .as_array()
            .ok_or_else(ApiError::internal)?;
        for (node, safe) in graph.nodes.iter_mut().zip(nodes) {
            node.id = safe["id"].as_str().ok_or_else(ApiError::internal)?.into();
            node.label = safe["label"]
                .as_str()
                .ok_or_else(ApiError::internal)?
                .into();
            node.file = safe.get("file").and_then(Value::as_str).map(Into::into);
        }
        let edges = value["graph"]["edges"]
            .as_array()
            .ok_or_else(ApiError::internal)?;
        for (edge, safe) in graph.edges.iter_mut().zip(edges) {
            edge.from = safe["from"].as_str().ok_or_else(ApiError::internal)?.into();
            edge.to = safe["to"].as_str().ok_or_else(ApiError::internal)?.into();
        }
    }
    Ok((value, graph.map(|g| g.to_dot()).unwrap_or_default()))
}
