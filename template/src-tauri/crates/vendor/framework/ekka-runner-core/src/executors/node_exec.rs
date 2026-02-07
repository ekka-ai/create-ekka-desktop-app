//! node_exec executor - executes node capabilities via local node HTTP API

use reqwest::Client;
use tracing::info;
use uuid::Uuid;

use crate::types::TaskExecutionContext;

pub async fn execute(
    client: &Client,
    node_url: &str,
    session_id: &str,
    ctx: &TaskExecutionContext,
) -> Result<serde_json::Value, String> {
    let capability_code = ctx.input_json
        .get("capability_code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let inputs = ctx.input_json
        .get("inputs")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    info!(
        op = "runner.task.node_exec",
        task_id = %ctx.task_id_short,
        capability = %capability_code,
        "Executing node capability"
    );

    execute_capability(client, node_url, session_id, capability_code, &inputs).await
}

async fn execute_capability(
    client: &Client,
    node_url: &str,
    session_id: &str,
    capability_code: &str,
    inputs: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    match capability_code {
        "agent.run" | "CAP_EXECUTE_AGENT" => {
            let url = format!("{}/v0/agent/run", node_url);
            let prompt = inputs
                .get("prompt")
                .and_then(|v| v.as_str())
                .unwrap_or("Process the request");

            let response = client
                .post(&url)
                .header("X-Session-Id", session_id)
                .json(&serde_json::json!({
                    "job_id": Uuid::new_v4().to_string(),
                    "prompt": prompt,
                    "inputs": inputs.get("inputs"),
                }))
                .send()
                .await
                .map_err(|e| format!("Agent capability failed: {}", e.without_url()))?;

            if !response.status().is_success() {
                let status = response.status();
                return Err(format!("Agent capability failed ({})", status));
            }

            response
                .json()
                .await
                .map_err(|e| format!("Failed to parse agent response: {}", e))
        }
        _ => Err(format!("Unknown capability_code: {}", capability_code)),
    }
}
