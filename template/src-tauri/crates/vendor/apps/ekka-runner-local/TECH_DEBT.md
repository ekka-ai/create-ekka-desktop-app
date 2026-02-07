# Technical Debt - ekka-runner-local

## TD-TIMEOUT-001: Make LLM timeout configurable per prompt/workflow

**Status:** Open
**Created:** 2026-01-30
**Priority:** Medium

### Current State

LLM execution timeout is a single global default (`LLM_TIMEOUT_SECS_DEFAULT = 1200`, i.e., 20 minutes).
Can be overridden via `EKKA_LLM_TIMEOUT_SECS` environment variable for testing.

### Problem

Different prompts/workflows have vastly different execution times:
- Simple classification: 5-30 seconds
- Document generation (docgen): 2-15 minutes
- Complex analysis: 10-30+ minutes

A single global timeout either:
- Times out legitimate long-running tasks (too short)
- Delays failure detection for stuck tasks (too long)

### Proposed Solution

1. Add `timeout_secs` field to `PromptRunTaskPayloadV1`:
   ```rust
   #[serde(default)]
   pub timeout_secs: Option<u64>,
   ```

2. Engine workflow definition specifies expected timeout per prompt/step.

3. Runner uses `payload.timeout_secs.unwrap_or(LLM_TIMEOUT_SECS_DEFAULT)`.

4. Enforce safe maximum cap (e.g., 3600 seconds / 1 hour) to prevent runaway tasks.

5. Log both configured and effective timeout in `prompt_run.llm.started` for observability.

### Considerations

- Backward compatibility: absent field uses default
- Security: cap maximum to prevent DoS
- Observability: log configured vs effective timeout
- Engine schema: add `timeout_secs` to prompt_run task input schema

---

## TD-TOOLS-001: Make tool allowlist/disallowlist prompt/workflow-driven

**Status:** Open
**Created:** 2026-01-30
**Priority:** High

### Current State

Claude CLI tool configuration uses a global default:
- `--allowedTools default` (broad toolset for many prompt types)
- `--disallowedTools Bash,WebFetch,WebSearch` (blocks risky tools)

This one-size-fits-all approach is applied to all prompts regardless of their needs.

### Problem

Different prompts/workflows need different tool profiles:
- **docgen**: needs Write, Read, Glob, Grep (file operations only)
- **compare**: needs Read, Glob, Grep (read-only analysis)
- **plan**: needs Read, Glob, Grep, EnterPlanMode (planning only)
- **execute**: may need broader tool access with approval

A single global toolset either:
- Over-permits tools for simple tasks (security risk)
- Under-permits tools for complex tasks (functionality blocked)

### Proposed Solution

1. Add `tool_profile` or `allowed_tools`/`disallowed_tools` fields to `PromptRunTaskPayloadV1`:
   ```rust
   #[serde(default)]
   pub tool_profile: Option<String>, // e.g., "docgen", "readonly", "full"

   #[serde(default)]
   pub allowed_tools: Option<Vec<String>>,

   #[serde(default)]
   pub disallowed_tools: Option<Vec<String>>,
   ```

2. Define tool profiles in engine/prompt registry:
   - `readonly`: Read, Glob, Grep only
   - `docgen`: Read, Write, Edit, Glob, Grep
   - `planning`: Read, Glob, Grep, EnterPlanMode, ExitPlanMode
   - `full`: default toolset (current behavior)

3. Runner applies profile or explicit lists, with safe defaults.

4. Enforce a "never allowed" blocklist regardless of profile:
   - Bash (arbitrary command execution)
   - WebFetch/WebSearch (network access without approval)

5. Log effective tool configuration in `prompt_run.llm.started`.

### Considerations

- Backward compatibility: absent fields use current global defaults
- Security: always enforce blocklist even if profile says "full"
- AskUserQuestion behavior: revisit whether to enable when `--permission-mode dontAsk` is set
  (currently allowed but user cannot respond, may cause hangs or confusing behavior)
- Engine schema: add tool configuration to prompt_run task input schema
- Capability integration: consider tying tool profiles to capability grants
