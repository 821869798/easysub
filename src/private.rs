use std::collections::HashMap;

use serde::Deserialize;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PrivateSubscriptions {
    #[serde(default)]
    vars: Vec<KeyValue>,
    #[serde(default)]
    rewrites: Vec<KeyValue>,
    #[serde(skip)]
    routes: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct KeyValue {
    key: String,
    value: String,
}

impl PrivateSubscriptions {
    pub async fn load(path: &str) -> Result<Self> {
        let source = match std::env::var("EASYSUB_PRIVATE") {
            Ok(source) if !source.is_empty() => source,
            _ => tokio::fs::read_to_string(path).await.map_err(|error| {
                AppError::Config(format!(
                    "failed to read private subscription config {path}: {error}"
                ))
            })?,
        };
        Self::parse(&source)
    }

    pub fn parse(source: &str) -> Result<Self> {
        let mut config: Self = toml::from_str(source).map_err(|error| {
            AppError::Config(format!("invalid private subscription TOML: {error}"))
        })?;
        config.prepare();
        Ok(config)
    }

    pub fn route(&self, path: &str) -> Option<&str> {
        self.routes.get(path).map(String::as_str)
    }

    fn prepare(&mut self) {
        let mut variables = HashMap::with_capacity(self.vars.len());
        for variable in &self.vars {
            let value = resolve_environment(&variable.value);
            let value = expand(&value, &variables);
            variables.insert(variable.key.clone(), value);
        }

        let encoded: HashMap<_, _> = variables
            .into_iter()
            .map(|(key, value)| (key, form_encode(&value)))
            .collect();
        self.routes = self
            .rewrites
            .iter()
            .map(|rewrite| (rewrite.key.clone(), expand(&rewrite.value, &encoded)))
            .collect();
    }
}

fn resolve_environment(value: &str) -> String {
    value
        .strip_prefix("env:")
        .map(|name| name.trim_start_matches('/'))
        .and_then(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| value.to_owned())
}

fn expand(value: &str, variables: &HashMap<String, String>) -> String {
    variables
        .iter()
        .fold(value.to_owned(), |output, (key, value)| {
            output.replace(&format!("{{{key}}}"), value)
        })
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_nested_variables_and_encodes_rewrite_values() {
        let config = PrivateSubscriptions::parse(
            r#"
[[vars]]
key = "first"
value = "trojan://one.test:443#one"

[[vars]]
key = "all"
value = "{first}|https://two.test/a b"

[[rewrites]]
key = "/clash/token"
value = "sub?target=clash&url={all}"
"#,
        )
        .unwrap();
        assert_eq!(
            config.route("/clash/token"),
            Some(
                "sub?target=clash&url=trojan%3A%2F%2Fone.test%3A443%23one%7Chttps%3A%2F%2Ftwo.test%2Fa+b"
            )
        );
    }
}
