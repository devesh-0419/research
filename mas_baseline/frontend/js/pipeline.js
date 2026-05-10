/* ════════════════════════════════════════════════════════════════════════════
   pipeline.js  —  Real backend integration
   Connects to the Flask server (server.py) and consumes SSE events
   produced by the actual LangGraph pipeline execution.
════════════════════════════════════════════════════════════════════════════ */

'use strict';

const API_BASE = window.location.origin;   // same host as the Flask server

// ─── Check backend health on load ────────────────────────────────────────────

async function checkBackend() {
  try {
    const res  = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(2000) });
    const data = await res.json();
    addLog(null, 'log-system',
      `Backend connected — LLM: ${data.llm_provider} / ${data.llm_model || 'default'}`);
    return true;
  } catch {
    addLog(null, 'log-system',
      '⚠ Backend not reachable. Start server.py first:  python server.py');
    setStatus('error');
    return false;
  }
}

// ─── Main pipeline runner ─────────────────────────────────────────────────────

async function runPipeline() {
  const query = document.getElementById('queryInput').value.trim();
  if (!query) return;

  resetPipelineUI();
  setStatus('running');

  const btn = document.getElementById('runBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="run-icon">⏳</span> RUNNING…';

  addLog(null, 'log-system', `Sending query to backend: "${query}"`);

  try {
    await streamPipeline(query);
  } catch (err) {
    addLog(null, 'log-system', `Error: ${err.message}`);
    setStatus('error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="run-icon">▶</span> RUN';
  }
}

// ─── SSE stream consumer ──────────────────────────────────────────────────────

function streamPipeline(query) {
  return new Promise((resolve, reject) => {
    const url = `${API_BASE}/api/stream?q=${encodeURIComponent(query)}`;
    const es  = new EventSource(url);

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleSSEEvent(data);

        if (data.type === 'done' || data.type === 'error') {
          es.close();
          if (data.type === 'done') {
            setStatus('done');
            resolve(data.result);
          } else {
            setStatus('error');
            reject(new Error(data.message));
          }
        }
      } catch (e) {
        console.error('SSE parse error:', e, event.data);
      }
    };

    es.onerror = (err) => {
      es.close();
      reject(new Error('SSE connection failed — is server.py running?'));
    };
  });
}

// ─── Handle each SSE event from the backend ───────────────────────────────────

function handleSSEEvent(data) {
  if (data.type === 'node_complete') {
    const { node, agent_id, messages, logs, auth_status,
            anomaly_detected, anomaly_details, final_response,
            trust_registry, current_task, data_payload } = data;

    // 1. Activate the agent node in the diagram
    activateNode(agent_id);

    // 2. Render real log entries from Python
    if (logs && logs.length) {
      logs.forEach(log => {
        const cssClass = logCssClass(agent_id, log);
        addLog(agent_id, cssClass, formatLogMsg(log));
      });
    }

    // 3. Render real A2A messages from Python
    if (messages && messages.length) {
      messages.forEach(msg => renderMessage(msg));
    }

    // 4. Update node badges based on real state
    if (auth_status && auth_status !== 'pending') {
      if (agent_id === 'authorizer_agent') {
        setNodeBadge('authorizer_agent', auth_status);
      }
    }
    if (node === 'data_manager' || node === 'data_manager_agent') {
      if (!data_payload?.error) setNodeBadge('data_manager_agent', 'done');
    }
    if (node === 'logger') {
      setNodeBadge('logger_agent', anomaly_detected ? 'denied' : 'done');
      if (anomaly_detected && anomaly_details?.length) {
        anomaly_details.forEach(a => {
          addLog('logger_agent', 'log-anomaly',
            `⚠ [${a.rule || 'ANOMALY'}] ${a.message}`);
        });
      }
    }

    // 5. Update trust registry bars if sent
    if (trust_registry) renderTrustBars(trust_registry);

    // 6. Render final output when orchestrator_assemble completes
    if (node === 'orchestrator_assemble' && final_response) {
      renderOutput(
        final_response,
        auth_status || window._lastAuthStatus || 'pending',
        current_task || window._lastTask || '',
        { anomaly: anomaly_detected, messages: window._pipelineMessages || [] }
      );
      activateOutputNode();
    }

    // Cache state for output rendering
    if (auth_status)  window._lastAuthStatus = auth_status;
    if (current_task) window._lastTask       = current_task;

    doneNode(agent_id);

  } else if (data.type === 'done') {
    // Final complete event — render output from full result
    const r = data.result;
    if (r) {
      renderOutput(
        r.final_response,
        r.auth_status,
        r.current_task,
        { anomaly: r.anomaly_detected, messages: r.messages }
      );
      activateOutputNode();
      if (r.trust_registry) renderTrustBars(r.trust_registry);
    }
    addLog(null, 'log-system', 'Pipeline complete.');

  } else if (data.type === 'error') {
    addLog(null, 'log-system', `Pipeline error: ${data.message}`);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const AGENT_CSS = {
  user_facing_agent:  'log-user',
  orchestrator_agent: 'log-orchestrator',
  authorizer_agent:   'log-authorizer',
  data_manager_agent: 'log-data',
  logger_agent:       'log-logger',
};

function logCssClass(agent_id, log) {
  // Special classes for specific events
  if (log.event === 'auth_decision') {
    const decision = log.details?.decision;
    if (decision === 'approved') return 'log-approved';
    if (decision === 'denied')   return 'log-denied';
  }
  if (log.event === 'baseline_anomaly_flag') return 'log-anomaly';
  return AGENT_CSS[agent_id] || 'log-system';
}

function formatLogMsg(log) {
  const event = log.event?.replace(/_/g, ' ') || '';
  const details = log.details || {};

  // Render specific events more readably
  if (log.event === 'received_user_query')
    return `Received: "${details.query || ''}" → intent: ${details.intent?.task || '?'}`;
  if (log.event === 'built_execution_plan')
    return `Plan: ${details.task || ''} / ${details.operation || ''} → ${JSON.stringify(details.plan?.steps || [])}`;
  if (log.event === 'auth_decision')
    return `Auth: role=${details.user_role} op=${details.operation} → ${(details.decision || '').toUpperCase()}`;
  if (log.event === 'mcp_tool_call_completed')
    return `MCP: ${details.tool}(${details.table || ''}) → ${JSON.stringify(details.result_keys || [])}`;
  if (log.event === 'audit_snapshot')
    return `Audit: ${details.message_count} messages, auth=${details.auth_status}, anomaly=${details.anomaly_detected}`;
  if (log.event === 'assembled_final_response')
    return `Response assembled: auth=${details.auth_status}`;
  if (log.event === 'baseline_anomaly_flag')
    return `[${details.severity}] Rule ${details.rule}: ${details.message}`;

  // Fallback: event name + first detail value
  const firstVal = Object.values(details)[0];
  return firstVal !== undefined
    ? `${event}: ${JSON.stringify(firstVal).slice(0, 80)}`
    : event;
}
