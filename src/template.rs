use std::{collections::HashMap, sync::LazyLock};

use liquid_core::{
    Display_filter, Filter, FilterReflection, ParseFilter, Runtime, Value, ValueView, model::State,
};
use regex::{Captures, Regex};
use serde_json::{Map, Value as JsonValue};

use crate::{
    config::AppConfig,
    error::{AppError, Result},
};

static RULESET_TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\{%\s*ruleset\s+([^\s%]+)\s+([^\s%]+)\s*%\}"#)
        .expect("static ruleset regex is valid")
});

pub fn render(
    source: &str,
    request: &HashMap<String, String>,
    config: &AppConfig,
    singbox: bool,
) -> Result<String> {
    let prepared = if singbox {
        expand_ruleset_tags(source, config)?
    } else {
        source.to_owned()
    };
    let parser = liquid::ParserBuilder::with_stdlib()
        .filter(BoolFilterParser)
        .build()
        .map_err(|error| AppError::Conversion(format!("Liquid parser setup failed: {error}")))?;
    let template = parser
        .parse(&prepared)
        .map_err(|error| AppError::Conversion(format!("Liquid template is invalid: {error}")))?;

    let mut root = Map::new();
    let mut request_object = serde_json::json!({
        "clash": {"dns": "false"},
        "singbox": {"ipv6": "false", "enable_tun": "false"}
    })
    .as_object()
    .expect("request defaults are an object")
    .clone();
    for (key, value) in request {
        insert_dotted(&mut request_object, key, JsonValue::String(value.clone()));
    }
    let mut global_object = Map::new();
    for item in &config.template.globals {
        insert_dotted(
            &mut global_object,
            &item.key,
            JsonValue::String(item.value.clone()),
        );
    }
    root.insert("Request".into(), JsonValue::Object(request_object));
    root.insert("Global".into(), JsonValue::Object(global_object));
    let globals = liquid::to_object(&root)
        .map_err(|error| AppError::Conversion(format!("Liquid variables are invalid: {error}")))?;
    template
        .render(&globals)
        .map_err(|error| AppError::Conversion(format!("Liquid rendering failed: {error}")))
}

fn expand_ruleset_tags(source: &str, config: &AppConfig) -> Result<String> {
    let mut missing = None;
    let rendered = RULESET_TAG.replace_all(source, |captures: &Captures<'_>| {
        let kind = captures[1].to_ascii_lowercase();
        let value = captures[2].to_ascii_lowercase();
        let Some(transform) = config.node_pref.singbox_rulesets.get(&kind) else {
            missing = Some(kind);
            return "null".into();
        };
        let url = transform.url_format.replace("%s", &value);
        serde_json::json!({
            "tag": format!("{kind}-{value}"),
            "type": "remote",
            "format": "binary",
            "url": url,
            "http_client": {"detour": "DIRECT"},
            "update_interval": format!("{}s", config.managed_config.ruleset_update_interval)
        })
        .to_string()
    });
    if let Some(kind) = missing {
        return Err(AppError::Config(format!(
            "no sing-box ruleset transform configured for {kind}"
        )));
    }
    Ok(rendered.into_owned())
}

fn insert_dotted(object: &mut Map<String, JsonValue>, key: &str, value: JsonValue) {
    let mut parts = key.split('.').filter(|part| !part.is_empty()).peekable();
    let mut current = object;
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            current.insert(part.to_owned(), value);
            break;
        }
        current = current
            .entry(part.to_owned())
            .or_insert_with(|| JsonValue::Object(Map::new()))
            .as_object_mut()
            .expect("dotted variable path must remain an object");
    }
}

#[derive(Clone, ParseFilter, FilterReflection)]
#[filter(
    name = "bool",
    description = "Converts common scalar values to booleans.",
    parsed(BoolFilter)
)]
struct BoolFilterParser;

#[derive(Debug, Default, Display_filter)]
#[name = "bool"]
struct BoolFilter;

impl Filter for BoolFilter {
    fn evaluate(
        &self,
        input: &dyn ValueView,
        _runtime: &dyn Runtime,
    ) -> liquid_core::Result<Value> {
        if input.is_nil() || input.query_state(State::Empty) {
            return Ok(Value::scalar(false));
        }
        let value = input.as_scalar().is_none_or(|scalar| {
            scalar
                .to_bool()
                .or_else(|| scalar.to_integer().map(|value| value != 0))
                .unwrap_or_else(|| scalar.to_kstr().parse::<bool>().unwrap_or(false))
        });
        Ok(Value::scalar(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_nested_values_and_bool_filter() {
        let mut request = HashMap::new();
        request.insert("target".into(), "clash".into());
        request.insert("clash.dns".into(), "false".into());
        let output = render(
            "{% if Request.target == \"clash\" %}ok{% endif %}{% assign enabled = Request.clash.dns | bool %}{% if enabled %}bad{% endif %}",
            &request,
            &AppConfig::default(),
            false,
        )
        .unwrap();
        assert_eq!(output, "ok");
    }
}
