//! Test-only [`tracing_subscriber::Layer`] that records every span (name +
//! final field values) so tests can assert that critical spans are emitted
//! with the expected attributes.
//!
//! Span fields recorded via `span.record(...)` after the span is created
//! (e.g. `Empty` placeholders that get filled in once an LLM call returns)
//! are captured — `on_record` updates the stored values in place.

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

#[derive(Clone, Debug, Default)]
pub struct CapturedSpan {
    pub name: String,
    pub fields: HashMap<String, String>,
}

impl CapturedSpan {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }
}

#[derive(Default)]
struct FieldVisitor {
    out: HashMap<String, String>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.out
            .insert(field.name().to_string(), format!("{:?}", value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.out.insert(field.name().to_string(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.out.insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.out.insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.out.insert(field.name().to_string(), value.to_string());
    }
}

#[derive(Clone, Default)]
pub struct SpanCapture {
    inner: Arc<Mutex<HashMap<u64, CapturedSpan>>>,
}

impl SpanCapture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<CapturedSpan> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    pub fn find(&self, name: &str) -> Option<CapturedSpan> {
        self.snapshot().into_iter().find(|s| s.name == name)
    }

    pub fn find_all(&self, name: &str) -> Vec<CapturedSpan> {
        self.snapshot()
            .into_iter()
            .filter(|s| s.name == name)
            .collect()
    }
}

impl<S> Layer<S> for SpanCapture
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);
        let span = CapturedSpan {
            name: attrs.metadata().name().to_string(),
            fields: visitor.out,
        };
        self.inner.lock().unwrap().insert(id.into_u64(), span);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        values.record(&mut visitor);
        if let Some(span) = self.inner.lock().unwrap().get_mut(&id.into_u64()) {
            for (k, v) in visitor.out {
                span.fields.insert(k, v);
            }
        }
    }
}

/// Install a [`SpanCapture`] for the duration of one test. Returns a guard
/// that keeps the subscriber active and a handle to inspect captured spans.
pub fn install_capture() -> (tracing::subscriber::DefaultGuard, SpanCapture) {
    use tracing_subscriber::layer::SubscriberExt;

    let capture = SpanCapture::new();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    (guard, capture)
}
