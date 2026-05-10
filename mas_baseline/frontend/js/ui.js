/* ════════════════════════════════════════════════════════════════════════════
   ui.js
   UI helpers: node activation, log rendering, message bus, output, trust bars
════════════════════════════════════════════════════════════════════════════ */

'use strict';

const AGENT_LABELS = {
  user_facing_agent:   'USERFACING',
  orchestrator_agent:  'ORCHESTRATOR',
  authorizer_agent:    'AUTHORIZER',
  data_manager_agent:  'DATAMANAGER',
  logger_agent:        'LOGGER',
};

const TRUST_REGISTRY = {
  user_facing_agent:   1.0,
  orchestrator_agent:  1.0,
  data_manager_agent:  1.0,
  authorizer_agent:    1.0,
  logger_agent:        1.0,
};

// ─── Node activation ─────────────────────────────────────────────────────

function activateNode(agentId) {
  // Remove active from all nodes
  document.querySelectorAll('.flow-node').forEach(n => n.classList.remove('active'));

  const node = document.getElementById(`node-${agentId}`);
  if (node) {
    node.classList.add('active');
    node.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  setNodeBadge(agentId, 'running');
  updateStatusLabel(AGENT_LABELS[agentId] || agentId.toUpperCase());
  return Promise.resolve();
}

function doneNode(agentId) {
  const node = document.getElementById(`node-${agentId}`);
  if (node) {
    node.classList.remove('active');
    node.classList.add('done');
  }
}

function activateOutputNode() {
  const node = document.getElementById('node-output');
  if (node) {
    node.classList.add('active');
    setTimeout(() => node.classList.remove('active'), 1500);
  }
}

function setNodeBadge(agentId, status) {
  const badge = document.getElementById(`badge-${agentId}`);
  if (!badge) return;
  badge.classList.remove('approved', 'denied', 'running', 'done', 'visible');

  if (!status) return;
  badge.classList.add(status, 'visible');

  const labels = { approved: 'APPROVED', denied: 'DENIED', running: '…', done: 'DONE' };
  badge.textContent = labels[status] || status.toUpperCase();
}

// ─── Status indicator ────────────────────────────────────────────────────

function setStatus(state) {
  const dot   = document.getElementById('statusDot');
  const label = document.getElementById('statusLabel');
  dot.className = 'status-dot ' + state;
  const labels = { idle: 'IDLE', running: 'RUNNING', done: 'COMPLETE', error: 'ERROR' };
  label.textContent = labels[state] || state.toUpperCase();
}

function updateStatusLabel(agent) {
  document.getElementById('statusLabel').textContent = agent;
}

// ─── Log stream ───────────────────────────────────────────────────────────

function addLog(agentId, cssClass, message) {
  const stream = document.getElementById('logStream');
  const ts     = new Date().toTimeString().slice(0,8);
  const label  = AGENT_LABELS[agentId] || agentId?.toUpperCase() || 'SYSTEM';

  const entry  = document.createElement('div');
  entry.className = `log-entry ${cssClass}`;
  entry.innerHTML = `
    <span class="log-ts">${ts}</span>
    <span class="log-agent">${label}</span>
    <span class="log-msg">${escHtml(message)}</span>
  `;
  stream.appendChild(entry);
  stream.scrollTop = stream.scrollHeight;
}

function clearLog() {
  const stream = document.getElementById('logStream');
  stream.innerHTML = `
    <div class="log-entry log-system">
      <span class="log-ts">${new Date().toTimeString().slice(0,8)}</span>
      <span class="log-agent">SYSTEM</span>
      <span class="log-msg">Log cleared.</span>
    </div>`;
}

// ─── A2A Message bus ──────────────────────────────────────────────────────

function renderMessage(msg) {
  const list = document.getElementById('messagesList');

  // Remove empty placeholder
  const empty = list.querySelector('.messages-empty');
  if (empty) empty.remove();

  const agentColors = {
    user_facing_agent:  '#b47cff',
    orchestrator_agent: '#00e5ff',
    authorizer_agent:   '#ffb300',
    data_manager_agent: '#4eaaff',
    logger_agent:       '#5a7a96',
  };
  const fromColor = agentColors[msg.sender]    || '#c9d6e3';
  const toColor   = agentColors[msg.recipient] || '#c9d6e3';

  const env = document.createElement('div');
  env.className = 'msg-envelope';

  const payloadStr = JSON.stringify(msg.payload, null, 2);
  const safeId     = msg.message_id.replace(/[^a-zA-Z0-9]/g,'_');

  env.innerHTML = `
    <div class="msg-header" onclick="toggleMsg('${safeId}')">
      <span class="msg-from" style="color:${fromColor}">${shortAgentName(msg.sender)}</span>
      <span class="msg-arrow">→</span>
      <span class="msg-to" style="color:${toColor}">${shortAgentName(msg.recipient)}</span>
      <span class="msg-type">${msg.task_type}</span>
    </div>
    <div class="msg-body" id="msgbody-${safeId}">
      <pre>${escHtml(payloadStr)}</pre>
    </div>`;

  list.appendChild(env);
  list.scrollTop = list.scrollHeight;
}

function toggleMsg(safeId) {
  const body = document.getElementById(`msgbody-${safeId}`);
  if (body) body.classList.toggle('open');
}

function shortAgentName(id) {
  return id.replace('_agent','').replace('_',' ').toUpperCase();
}

// ─── Output panel ────────────────────────────────────────────────────────

function renderOutput(response, authStatus, task, state) {
  const body = document.getElementById('outputBody');
  const meta = document.getElementById('outputMeta');

  const isApproved = authStatus === 'approved';
  const cls = isApproved ? 'output-approved' : 'output-denied';

  body.innerHTML = `
    <div class="output-result ${cls}">
      <pre style="white-space:pre-wrap;font-family:inherit">${escHtml(response || '')}</pre>
    </div>`;

  const msgCount = Array.isArray(state?.messages) ? state.messages.length
                 : (window._pipelineMessages || []).length;

  meta.innerHTML = `
    <div class="meta-item"><span class="meta-key">AUTH</span>
      <span style="color:${isApproved ? 'var(--green)' : 'var(--red)'}">${(authStatus||'?').toUpperCase()}</span>
    </div>
    <div class="meta-item"><span class="meta-key">TASK</span><span>${task || '?'}</span></div>
    <div class="meta-item"><span class="meta-key">MESSAGES</span><span>${msgCount}</span></div>
    <div class="meta-item"><span class="meta-key">ANOMALY</span>
      <span style="color:${state?.anomaly ? 'var(--red)' : 'var(--green)'}">${state?.anomaly ? 'DETECTED' : 'NONE'}</span>
    </div>`;
}

// ─── Trust registry bars ──────────────────────────────────────────────────

function renderTrustBars(registry) {
  const container = document.getElementById('trustBars');
  container.innerHTML = '';

  Object.entries(registry).forEach(([agent, score]) => {
    const pct   = Math.round(score * 100);
    const name  = shortAgentName(agent);
    const color = score >= 0.8 ? 'var(--accent)' : score >= 0.5 ? 'var(--amber)' : 'var(--red)';

    const item = document.createElement('div');
    item.className = 'trust-item';
    item.innerHTML = `
      <div class="trust-name">${name}</div>
      <div class="trust-bar-track">
        <div class="trust-bar-fill" style="width:${pct}%;background:linear-gradient(90deg,var(--accent-dim),${color})"></div>
      </div>
      <div class="trust-value" style="color:${color}">${score.toFixed(1)}</div>`;
    container.appendChild(item);
  });
}

// ─── Reset UI ─────────────────────────────────────────────────────────────

function resetPipelineUI() {
  // Reset nodes
  document.querySelectorAll('.flow-node').forEach(n => {
    n.classList.remove('active','done','error');
  });
  // Reset badges
  document.querySelectorAll('.node-badge').forEach(b => {
    b.className = 'node-badge';
    b.textContent = '';
  });
  // Clear message list
  const list = document.getElementById('messagesList');
  list.innerHTML = '<div class="messages-empty">Processing…</div>';

  // Reset output
  document.getElementById('outputBody').innerHTML = '<div class="output-empty">Running pipeline…</div>';
  document.getElementById('outputMeta').innerHTML = '';

  // Reset message counter
  window._msgCounter = 0;
  if (typeof _msgCounter !== 'undefined') _msgCounter = 0;
}

// ─── Preset query buttons ─────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Trust bars
  renderTrustBars(TRUST_REGISTRY);

  // Preset buttons
  document.querySelectorAll('.preset').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.preset').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('queryInput').value = btn.dataset.query;
    });
  });

  // Mark first preset active
  const first = document.querySelector('.preset');
  if (first) first.classList.add('active');

  // Enter key runs pipeline
  document.getElementById('queryInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') runPipeline();
  });

  setStatus('idle');
  addLog(null, 'log-system', 'Checking backend connection…');
  checkBackend();
});

// ─── Utilities ────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// Re-export sleep for pipeline.js
window.sleep = sleep;
