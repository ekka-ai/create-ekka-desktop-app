# Tech Debt: ekka-artifact-store

## API Extensions Needed (2026-01-30)

### ArtifactRef Missing Fields
- **Issue**: `ArtifactRef` returned by `put_bytes()` doesn't include `content_type`, `compressed`, `created_at`
- **Impact**: Caller must call `head()` to get full metadata for engine responses
- **Fix**: Either:
  1. Extend `ArtifactRef` to include these fields, OR
  2. Add `put_bytes_opts()` that takes `PutOptions { compress: Option<bool> }` and returns `ArtifactRefFull`
- **Priority**: Needed when Agent C integrates with engine artifact responses

### Caller-Controlled Compression
- **Issue**: Compression is auto-detected from content_type, caller can't force/disable
- **Fix**: Add `compress: Option<bool>` to `put_bytes()` or provide `put_bytes_opts()`

---

## Simplifying Assumptions (2026-01-30)

### No File Locking
- **Issue**: No file locking during put/delete operations
- **Risk**: Concurrent writes to same artifact may corrupt data
- **Mitigation**: Content-addressed storage reduces collision risk (same content = same hash = same path)
- **Fix**: Add flock or advisory locks for write operations

### No Atomic Writes
- **Issue**: Writes are not atomic (no temp file + rename pattern)
- **Risk**: Interrupted writes leave partial artifacts
- **Fix**: Write to `.tmp` file, then rename to final path

### GC Performance
- **Issue**: `garbage_collect_expired` does full directory traversal
- **Risk**: Slow on large stores
- **Fix**: Maintain an index or use modified-time based pruning

### No Quota/Size Limits
- **Issue**: No per-tenant storage quotas
- **Risk**: Unbounded storage growth
- **Fix**: Add quota tracking and enforcement

---

## Retention Enforcement (2026-01-30)

### DB Index Pruning Not Implemented
- **Issue**: Sweeper only handles filesystem artifacts, no DB index pruning
- **Context**: Current implementation scans filesystem metadata sidecars for `expires_at`
- **Missing**: If artifacts are indexed in a database (e.g., for search), those references remain stale after sweeper deletes files
- **Fix**: When DB indexing is added:
  1. Add `DELETE FROM artifacts WHERE expires_at < now` to sweeper
  2. Or use soft-delete in DB, then hard-delete after confirming filesystem cleanup
  3. Consider two-phase: mark expired in DB, delete files, purge DB records
- **Priority**: Medium - only needed when DB indexing is implemented
- **Related**: `examples/sweeper.rs` demonstrates filesystem-only retention enforcement
