//! Audit Operations
//!
//! Audit event listing with cursor-based pagination.

use crate::context::RuntimeContext;
use crate::error::EkkaResult;

use super::cache::{get_or_init_vault_manager, VaultManagerCache};
use super::types::{AuditEvent, AuditListOptions, AuditListResult, AuditLog};

/// Maximum events per page
const MAX_LIMIT: u32 = 100;
/// Default events per page
const DEFAULT_LIMIT: u32 = 50;

/// Cursor structure for pagination (simple offset-based)
#[derive(Debug)]
struct Cursor {
    /// Index into the sorted events list
    offset: usize,
}

impl Cursor {
    fn new(offset: usize) -> Self {
        Self { offset }
    }

    /// Encode cursor as a simple string (format: "c_{offset}")
    fn encode(&self) -> String {
        format!("c_{}", self.offset)
    }

    /// Decode cursor from string
    fn decode(encoded: &str) -> Option<Self> {
        if let Some(offset_str) = encoded.strip_prefix("c_") {
            let offset = offset_str.parse().ok()?;
            return Some(Self { offset });
        }
        None
    }
}

/// List audit events with cursor-based pagination
pub fn list(
    ctx: &RuntimeContext,
    cache: &dyn VaultManagerCache,
    opts: Option<AuditListOptions>,
) -> EkkaResult<AuditListResult> {
    let mgr = get_or_init_vault_manager(ctx, cache)?;
    let opts = opts.unwrap_or_default();

    // Collect all audit events from monthly files
    let mut all_events: Vec<AuditEvent> = Vec::new();

    // List all audit files for this tenant
    let audit_dir = format!("t_{}/audit", mgr.tenant_id());
    let audit_files = mgr.vault.list(&audit_dir).unwrap_or_default();

    for file in audit_files {
        if file.ends_with(".json") {
            let path = format!("audit/{}", file);
            if let Ok(log) = mgr.read_json::<AuditLog>(&path) {
                all_events.extend(log.events);
            }
        }
    }

    // Filter events
    let filtered: Vec<AuditEvent> = all_events
        .into_iter()
        .filter(|e| {
            // Filter by action
            let action_match = opts.action.as_ref().map_or(true, |action_filter| {
                // Convert enum to string for comparison
                let event_action = serde_json::to_string(&e.action)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string();
                event_action == *action_filter
            });

            // Filter by secret_id
            let secret_match = opts
                .secret_id
                .as_ref()
                .map(|sid| e.secret_id.as_ref() == Some(sid))
                .unwrap_or(true);

            // Filter by bundle_id
            let bundle_match = opts
                .bundle_id
                .as_ref()
                .map(|bid| e.bundle_id.as_ref() == Some(bid))
                .unwrap_or(true);

            // Filter by path prefix
            let path_match = opts.path_prefix.as_ref().map_or(true, |prefix| {
                e.path.as_ref().map_or(false, |p| p.starts_with(prefix))
            });

            // Text search
            let search_match = opts.search.as_ref().map_or(true, |search| {
                let search_lower = search.to_lowercase();
                e.secret_name
                    .as_ref()
                    .map_or(false, |n| n.to_lowercase().contains(&search_lower))
                    || e.path
                        .as_ref()
                        .map_or(false, |p| p.to_lowercase().contains(&search_lower))
            });

            action_match && secret_match && bundle_match && path_match && search_match
        })
        .collect();

    // Sort by timestamp descending (newest first)
    let mut sorted = filtered;
    sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Parse cursor to get offset
    let offset = opts
        .cursor
        .as_ref()
        .and_then(|c| Cursor::decode(c))
        .map(|c| c.offset)
        .unwrap_or(0);

    // Apply limit
    let limit = opts
        .limit
        .map(|l| l.min(MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT) as usize;

    // Get page of events
    let total_count = sorted.len();
    let events: Vec<AuditEvent> = sorted.into_iter().skip(offset).take(limit).collect();

    // Determine if there are more events
    let next_offset = offset + events.len();
    let has_more = next_offset < total_count;

    // Generate next cursor if there are more events
    let next_cursor = if has_more {
        Some(Cursor::new(next_offset).encode())
    } else {
        None
    };

    Ok(AuditListResult {
        events,
        next_cursor,
        has_more,
    })
}
