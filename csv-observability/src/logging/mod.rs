//! Structured Logging and Tracing Module
//!
//! This module provides structured logging and tracing capabilities for the Parwana.
//! It includes:
//! - Structured log levels and formats
//! - Tracing instrumentation for distributed tracing
//! - Context propagation across async boundaries
//! - Log correlation with events and metrics

use std::sync::Arc;
use tokio::sync::RwLock;

/// Log level for structured logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum LogLevel {
    /// Trace level - very detailed diagnostic information
    Trace,
    /// Debug level - detailed diagnostic information
    Debug,
    /// Info level - general informational messages
    Info,
    /// Warn level - warning messages for potentially harmful situations
    Warn,
    /// Error level - error messages for error events
    Error,
}

impl LogLevel {
    /// Convert log level to string
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    /// Parse log level from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "TRACE" => Some(LogLevel::Trace),
            "DEBUG" => Some(LogLevel::Debug),
            "INFO" => Some(LogLevel::Info),
            "WARN" => Some(LogLevel::Warn),
            "ERROR" => Some(LogLevel::Error),
            _ => None,
        }
    }
}

/// Structured log entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEntry {
    /// Timestamp of the log entry
    pub timestamp: u64,
    /// Log level
    pub level: LogLevel,
    /// Component or module that generated the log
    pub component: String,
    /// Log message
    pub message: String,
    /// Optional correlation ID for tracing
    pub correlation_id: Option<String>,
    /// Optional transfer ID for cross-chain transfer tracking
    pub transfer_id: Option<String>,
    /// Optional operation ID for operation tracking
    pub operation_id: Option<String>,
    /// Optional chain identifier
    pub chain: Option<String>,
    /// Additional structured fields
    pub fields: Vec<(String, String)>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(level: LogLevel, component: &str, message: &str) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level,
            component: component.to_string(),
            message: message.to_string(),
            correlation_id: None,
            transfer_id: None,
            operation_id: None,
            chain: None,
            fields: Vec::new(),
        }
    }

    /// Set correlation ID
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Set transfer ID
    pub fn with_transfer_id(mut self, transfer_id: String) -> Self {
        self.transfer_id = Some(transfer_id);
        self
    }

    /// Set operation ID
    pub fn with_operation_id(mut self, operation_id: String) -> Self {
        self.operation_id = Some(operation_id);
        self
    }

    /// Set chain
    pub fn with_chain(mut self, chain: String) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Add a field
    pub fn with_field(mut self, key: String, value: String) -> Self {
        self.fields.push((key, value));
        self
    }

    /// Format as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Format as structured log line
    pub fn to_log_line(&self) -> String {
        let timestamp = self.timestamp;
        let level = self.level.as_str();
        let component = &self.component;
        let correlation_id = self.correlation_id.as_deref().unwrap_or("N/A");
        let transfer_id = self.transfer_id.as_deref().unwrap_or("N/A");
        let operation_id = self.operation_id.as_deref().unwrap_or("N/A");
        let chain = self.chain.as_deref().unwrap_or("N/A");
        let message = &self.message;

        format!(
            "[{}] {} [{}] correlation_id={} transfer_id={} operation_id={} chain={} - {}",
            timestamp, level, component, correlation_id, transfer_id, operation_id, chain, message
        )
    }
}

/// Structured logger
pub struct StructuredLogger {
    /// Minimum log level
    min_level: LogLevel,
    /// Log entries storage
    entries: Arc<RwLock<Vec<LogEntry>>>,
    /// Whether to output to stdout
    stdout_output: bool,
}

impl StructuredLogger {
    /// Create a new structured logger
    pub fn new(min_level: LogLevel) -> Self {
        Self {
            min_level,
            entries: Arc::new(RwLock::new(Vec::new())),
            stdout_output: true,
        }
    }

    /// Create a new structured logger without stdout output
    pub fn new_no_output(min_level: LogLevel) -> Self {
        Self {
            min_level,
            entries: Arc::new(RwLock::new(Vec::new())),
            stdout_output: false,
        }
    }

    /// Log an entry
    pub async fn log(&self, entry: LogEntry) {
        if entry.level >= self.min_level {
            if self.stdout_output {
                println!("{}", entry.to_log_line());
            }
            self.entries.write().await.push(entry);
        }
    }

    /// Log at trace level
    pub async fn trace(&self, component: &str, message: &str) {
        let entry = LogEntry::new(LogLevel::Trace, component, message);
        self.log(entry).await;
    }

    /// Log at debug level
    pub async fn debug(&self, component: &str, message: &str) {
        let entry = LogEntry::new(LogLevel::Debug, component, message);
        self.log(entry).await;
    }

    /// Log at info level
    pub async fn info(&self, component: &str, message: &str) {
        let entry = LogEntry::new(LogLevel::Info, component, message);
        self.log(entry).await;
    }

    /// Log at warn level
    pub async fn warn(&self, component: &str, message: &str) {
        let entry = LogEntry::new(LogLevel::Warn, component, message);
        self.log(entry).await;
    }

    /// Log at error level
    pub async fn error(&self, component: &str, message: &str) {
        let entry = LogEntry::new(LogLevel::Error, component, message);
        self.log(entry).await;
    }

    /// Get all log entries
    pub async fn get_entries(&self) -> Vec<LogEntry> {
        self.entries.read().await.clone()
    }

    /// Get log entries filtered by level
    pub async fn get_entries_by_level(&self, level: LogLevel) -> Vec<LogEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.level == level)
            .cloned()
            .collect()
    }

    /// Get log entries filtered by correlation ID
    pub async fn get_entries_by_correlation_id(&self, correlation_id: &str) -> Vec<LogEntry> {
        self.entries
            .read()
            .await
            .iter()
            .filter(|e| e.correlation_id.as_deref() == Some(correlation_id))
            .cloned()
            .collect()
    }

    /// Clear all log entries
    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }
}

impl Default for StructuredLogger {
    fn default() -> Self {
        Self::new(LogLevel::Info)
    }
}

/// Tracing span for distributed tracing
#[derive(Debug, Clone)]
pub struct TraceSpan {
    /// Span ID
    pub span_id: String,
    /// Parent span ID if nested
    pub parent_span_id: Option<String>,
    /// Trace ID for the entire trace
    pub trace_id: String,
    /// Component name
    pub component: String,
    /// Operation name
    pub operation: String,
    /// Start timestamp
    pub start_time: u64,
    /// End timestamp
    pub end_time: Option<u64>,
    /// Additional metadata
    pub metadata: Vec<(String, String)>,
}

impl TraceSpan {
    /// Create a new trace span
    pub fn new(trace_id: String, component: &str, operation: &str) -> Self {
        Self {
            span_id: uuid::Uuid::new_v4().to_string(),
            parent_span_id: None,
            trace_id,
            component: component.to_string(),
            operation: operation.to_string(),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            end_time: None,
            metadata: Vec::new(),
        }
    }

    /// Create a child span
    pub fn child(&self, operation: &str) -> Self {
        Self {
            span_id: uuid::Uuid::new_v4().to_string(),
            parent_span_id: Some(self.span_id.clone()),
            trace_id: self.trace_id.clone(),
            component: self.component.clone(),
            operation: operation.to_string(),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            end_time: None,
            metadata: Vec::new(),
        }
    }

    /// Finish the span
    pub fn finish(&mut self) {
        self.end_time = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.push((key, value));
        self
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> Option<u64> {
        self.end_time.map(|end| (end - self.start_time) * 1000)
    }
}

/// Tracer for managing trace spans
pub struct Tracer {
    /// Active spans
    spans: Arc<RwLock<Vec<TraceSpan>>>,
}

impl Tracer {
    /// Create a new tracer
    pub fn new() -> Self {
        Self {
            spans: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start a new trace
    pub async fn start_trace(&self, component: &str, operation: &str) -> TraceSpan {
        let trace_id = uuid::Uuid::new_v4().to_string();
        let span = TraceSpan::new(trace_id, component, operation);
        self.spans.write().await.push(span.clone());
        span
    }

    /// Finish a span
    pub async fn finish_span(&self, span_id: &str) {
        if let Some(span) = self
            .spans
            .write()
            .await
            .iter_mut()
            .find(|s| s.span_id == span_id)
        {
            span.finish();
        }
    }

    /// Get all spans for a trace
    pub async fn get_trace(&self, trace_id: &str) -> Vec<TraceSpan> {
        self.spans
            .read()
            .await
            .iter()
            .filter(|s| s.trace_id == trace_id)
            .cloned()
            .collect()
    }

    /// Get all spans
    pub async fn get_all_spans(&self) -> Vec<TraceSpan> {
        self.spans.read().await.clone()
    }

    /// Clear all spans
    pub async fn clear(&self) {
        self.spans.write().await.clear();
    }
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from_str("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("invalid"), None);
    }

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "test_component", "test message");
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.component, "test_component");
        assert_eq!(entry.message, "test message");
    }

    #[test]
    fn test_log_entry_with_fields() {
        let entry = LogEntry::new(LogLevel::Info, "test_component", "test message")
            .with_correlation_id("corr-123".to_string())
            .with_transfer_id("transfer-456".to_string())
            .with_operation_id("op-789".to_string())
            .with_chain("ethereum".to_string());

        assert_eq!(entry.correlation_id, Some("corr-123".to_string()));
        assert_eq!(entry.transfer_id, Some("transfer-456".to_string()));
        assert_eq!(entry.operation_id, Some("op-789".to_string()));
        assert_eq!(entry.chain, Some("ethereum".to_string()));
    }

    #[tokio::test]
    async fn test_structured_logger() {
        let logger = StructuredLogger::new_no_output(LogLevel::Debug);
        logger.info("test_component", "test message").await;

        let entries = logger.get_entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].level, LogLevel::Info);
    }

    #[test]
    fn test_trace_span() {
        let span = TraceSpan::new("trace-123".to_string(), "component", "operation");
        assert_eq!(span.trace_id, "trace-123");
        assert!(span.end_time.is_none());

        let mut span = span;
        span.finish();
        assert!(span.end_time.is_some());
    }

    #[test]
    fn test_child_span() {
        let parent = TraceSpan::new("trace-123".to_string(), "component", "parent_op");
        let child = parent.child("child_op");

        assert_eq!(child.parent_span_id, Some(parent.span_id));
        assert_eq!(child.trace_id, parent.trace_id);
    }
}
