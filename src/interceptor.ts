/**
 * Interceptor — the main hook that fires on every intent.
 *
 * Flow:
 * 1. User issues an intent (e.g., "login to GitHub")
 * 2. Interceptor queries ClawMind Cloud for a matching Lobster macro
 * 3. If hit → execute the Lobster workflow directly (skip LLM exploration)
 * 4. If miss → passthrough to normal OpenClaw flow
 * 5. On success → contribute the trace back to the cloud
 * 6. On failure → report failure for circuit breaker tracking
 */

import { CloudClient } from "./cloud-client.js";
import { parseIntent } from "./intent-parser.js";
import { compileTrace } from "./trace-compiler.js";
import { generateEmbedding } from "./embedding.js";
import { sanitizeDomSnapshot } from "./sanitizer.js";
import type {
  OpenClawContext,
  MatchResponse,
  LobsterExecutionResult,
} from "./types.js";

export async function interceptIntent(ctx: OpenClawContext): Promise<void> {
  const { browser, lobster, sessions, gateway, workspace, config, logger } = ctx;

  // Check if skill is enabled
  if (!config.get<boolean>("enabled")) {
    gateway.passthrough();
    return;
  }

  const cloudEndpoint = config.get<string>("cloud_endpoint");
  const timeoutMs = config.get<number>("timeout_ms");
  const client = new CloudClient(cloudEndpoint, timeoutMs, logger);

  const sessionId = sessions.getCurrentSessionId();
  const history = await sessions.getHistory(sessionId);
  const intent = history.intent;

  if (!intent) {
    gateway.passthrough();
    return;
  }

  const url = await browser.getCurrentUrl();
  const domHash = await browser.getDomSkeletonHash();
  const nodeId = workspace.getNodeId();
  const parsed = parseIntent(intent, url);

  logger.info(`[ClawMind] Intercepting intent: "${parsed.normalized}" on ${parsed.domain}`);

  // Generate intent embedding for semantic matching
  let intentEmbedding: number[] | undefined;
  try {
    intentEmbedding = await generateEmbedding(parsed.normalized, cloudEndpoint, 2000);
    if (intentEmbedding) {
      logger.debug(`[ClawMind] Generated embedding vector (${intentEmbedding.length} dims)`);
    } else {
      logger.debug(`[ClawMind] Embedding generation failed, using exact match only`);
    }
  } catch (err) {
    logger.debug(`[ClawMind] Embedding error: ${err}`);
  }

  // Ensure dom_skeleton_hash is not empty string
  const cleanDomHash = domHash && domHash.trim() !== "" ? domHash : undefined;

  // Query cloud for a matching macro
  let matchResult: MatchResponse | null = null;
  try {
    matchResult = await client.match({
      intent: parsed.normalized,
      intent_embedding: intentEmbedding,
      url,
      dom_skeleton_hash: cleanDomHash,
      node_id: nodeId,
    });
  } catch (err) {
    logger.debug(`[ClawMind] Cloud unreachable: ${err}`);
    gateway.passthrough();
    return;
  }

  // No match — let OpenClaw handle it normally
  if (!matchResult || !matchResult.hit || !matchResult.macro) {
    logger.info("[ClawMind] No macro match, passing through to OpenClaw");
    gateway.passthrough();
    return;
  }

  const macro = matchResult.macro;
  logger.info(
    `[ClawMind] Match found: ${macro.macro_id} (score: ${matchResult.match_score}, method: ${matchResult.match_method})`
  );

  // Validate the workflow before execution
  if (!lobster.validate(macro.lobster_workflow)) {
    logger.warn(`[ClawMind] Workflow validation failed for ${macro.macro_id}`);
    gateway.passthrough();
    return;
  }

  // Execute the Lobster workflow
  let execResult: LobsterExecutionResult;
  try {
    execResult = await lobster.execute(macro.lobster_workflow);
  } catch (err) {
    logger.error(`[ClawMind] Lobster execution threw: ${err}`);

    // P2: Get DOM snapshot on failure and sanitize
    let domSnapshot: string | undefined;
    try {
      const rawDom = await browser.invoke("getOuterHTML", {});
      if (rawDom.success && typeof rawDom.data === "string") {
        domSnapshot = sanitizeDomSnapshot(rawDom.data);
      }
    } catch {}

    // Report failure to cloud (fire-and-forget)
    client.reportFailure({
      macro_id: macro.macro_id,
      node_id: nodeId,
      error_type: "other",
      error_detail: String(err),
      dom_snapshot: domSnapshot,
    }).catch(() => {});

    // Fall back to normal OpenClaw flow
    gateway.passthrough();
    return;
  }

  if (execResult.success) {
    logger.info(
      `[ClawMind] Macro ${macro.macro_id} executed successfully (${execResult.steps_completed}/${execResult.total_steps} steps)`
    );
    gateway.respond(
      `✅ Done via ClawMind cached workflow (${macro.macro_id}). ` +
      `${execResult.steps_completed} steps replayed.`
    );
  } else {
    logger.warn(
      `[ClawMind] Macro ${macro.macro_id} failed at step ${execResult.failed_step_id}: ${execResult.error}`
    );

    // Map error to error_type
    const errorType = mapErrorType(execResult.error || "");

    // P2: Get DOM snapshot on failure and sanitize
    let domSnapshot: string | undefined;
    try {
      const rawDom = await browser.invoke("getOuterHTML", {});
      if (rawDom.success && typeof rawDom.data === "string") {
        domSnapshot = sanitizeDomSnapshot(rawDom.data);
      }
    } catch {}

    client.reportFailure({
      macro_id: macro.macro_id,
      node_id: nodeId,
      error_type: errorType,
      error_detail: execResult.error,
      dom_snapshot: domSnapshot,
      failed_step_id: execResult.failed_step_id,
    }).catch(() => {});

    // Fall back to normal OpenClaw flow
    gateway.passthrough();
  }
}

/**
 * Hook: called when a session completes successfully.
 * Compiles the session trace into a Lobster workflow and contributes it.
 */
export async function onSessionComplete(ctx: OpenClawContext): Promise<void> {
  const { browser, sessions, workspace, config, logger } = ctx;

  if (!config.get<boolean>("enabled") || !config.get<boolean>("auto_contribute")) {
    return;
  }

  const sessionId = sessions.getCurrentSessionId();
  const history = await sessions.getHistory(sessionId);

  // Only contribute successful sessions with meaningful actions
  if (history.status !== "success") return;
  if (history.actions.length < 2) return;

  const intent = history.intent;
  if (!intent) return;

  const url = await browser.getCurrentUrl();
  const domHash = await browser.getDomSkeletonHash();
  const nodeId = workspace.getNodeId();

  // Compile the trace into a Lobster workflow
  const { workflow, argCount } = compileTrace(intent, history.actions);

  // Skip trivial workflows (single step, no real logic)
  if (workflow.steps.length < 2) {
    logger.debug("[ClawMind] Workflow too trivial to contribute, skipping");
    return;
  }

  logger.info(
    `[ClawMind] Contributing workflow "${workflow.name}" (${workflow.steps.length} steps, ${argCount} args)`
  );

  const cloudEndpoint = config.get<string>("cloud_endpoint");
  const client = new CloudClient(cloudEndpoint, 5000, logger);

  // Generate intent embedding for contribution
  let intentEmbedding: number[] | undefined;
  try {
    intentEmbedding = await generateEmbedding(intent, cloudEndpoint, 2000);
  } catch (err) {
    logger.debug(`[ClawMind] Embedding generation failed: ${err}`);
  }

  // Ensure dom_skeleton_hash is not empty string
  const cleanDomHash = domHash && domHash.trim() !== "" ? domHash : undefined;

  try {
    const result = await client.contribute({
      node_id: nodeId,
      intent,
      url,
      dom_skeleton_hash: cleanDomHash,
      lobster_workflow: workflow,
      intent_embedding: intentEmbedding,
      session_id: sessionId,
    });

    if (result?.accepted) {
      logger.info(`[ClawMind] Contribution accepted: ${result.macro_id}`);
    } else {
      logger.debug(`[ClawMind] Contribution not accepted: ${result?.reason}`);
    }
  } catch (err) {
    logger.debug(`[ClawMind] Contribution failed: ${err}`);
  }
}

function mapErrorType(
  error: string
): "selector_not_found" | "timeout" | "unexpected_state" | "other" {
  const lower = error.toLowerCase();
  if (lower.includes("selector") || lower.includes("not found") || lower.includes("no element")) {
    return "selector_not_found";
  }
  if (lower.includes("timeout") || lower.includes("timed out")) {
    return "timeout";
  }
  if (lower.includes("unexpected") || lower.includes("state")) {
    return "unexpected_state";
  }
  return "other";
}
