//! Ollama API provider (OpenAI-compatible endpoint).
//!
//! Ollama exposes an OpenAI-compatible Chat Completions API at `/v1/chat/completions`.
//! This provider reuses the OpenAI serialization format with a custom base URL.
//! See: <https://github.com/ollama/ollama/blob/main/docs/openai.md>

use tracing::debug;

use super::{LlmError, LlmProvider, LlmRequest, LlmResponse};

pub struct OllamaProvider {
    inner: super::openai::OpenAiProvider,
}

impl OllamaProvider {
    pub fn new(base_url: String) -> Self {
        let api_url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
        // Ollama doesn't require an API key, but the OpenAI provider expects one
        let inner = super::openai::OpenAiProvider::new("ollama".to_string(), Some(api_url));
        Self { inner }
    }
}

#[async_trait::async_trait]
impl LlmProvider for OllamaProvider {
    async fn chat(&self, request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        debug!(model = %request.model, "Ollama API request (via OpenAI compat)");
        self.inner.chat(request).await
    }

    fn name(&self) -> &str {
        "ollama"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_provider_creation() {
        let provider = OllamaProvider::new("http://localhost:11434".to_string());
        assert_eq!(provider.name(), "ollama");
    }

    #[test]
    fn test_ollama_url_trailing_slash() {
        // Should handle trailing slash gracefully
        let _provider = OllamaProvider::new("http://localhost:11434/".to_string());
    }
}
