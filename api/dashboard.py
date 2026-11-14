"""Mission Control Web Dashboard HTML for BountySweep Agent."""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>BountySweep Agent — Mission Control</title>
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #111827;
      --panel-border: #1f2937;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --emerald: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
      --blue: #3b82f6;
      --indigo: #6366f1;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, monospace;
      padding: 24px;
      line-height: 1.5;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--panel-border);
      margin-bottom: 24px;
    }
    .title-group h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
    .title-group p { color: var(--muted); font-size: 0.875rem; }
    .badge-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .badge {
      padding: 6px 12px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-running { background: rgba(16, 185, 129, 0.15); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.4); }
    .badge-paused { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-mode { background: rgba(59, 130, 246, 0.15); color: var(--blue); border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge-autopoll { background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.4); }

    .grid-kpi {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 18px;
    }
    .kpi-label { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .kpi-value { font-size: 1.85rem; font-weight: 700; margin-top: 6px; }
    .kpi-sub { color: var(--muted); font-size: 0.78rem; margin-top: 4px; }

    .controls-card {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
    }
    .btn-group { display: flex; flex-wrap: wrap; gap: 10px; }
    button {
      cursor: pointer;
      border: 1px solid transparent;
      border-radius: 8px;
      padding: 10px 16px;
      font-size: 0.85rem;
      font-weight: 600;
      color: #fff;
      transition: opacity 0.15s ease, transform 0.1s ease;
    }
    button:hover { opacity: 0.92; }
    button:active { transform: translateY(1px); }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: var(--indigo); }
    .btn-secondary { background: #1f2937; border-color: #374151; }
    .btn-success { background: var(--emerald); color: #052e16; }
    .btn-danger { background: var(--red); }
    .btn-amber { background: var(--amber); color: #1f1300; }

    .wallet-bar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.82rem;
      word-break: break-all;
      color: #e5e7eb;
      margin-top: 6px;
    }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }

    .two-col {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }
    @media (max-width: 900px) {
      .two-col { grid-template-columns: 1fr; }
    }
    .section-title {
      font-size: 0.95rem;
      font-weight: 600;
      margin-bottom: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .feed {
      max-height: 420px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .feed-item {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 12px;
      font-size: 0.82rem;
      white-space: pre-wrap;
    }
    .feed-tag { font-weight: 700; margin-bottom: 4px; display: inline-block; }
    .tag-claimed { color: #60a5fa; }
    .tag-submitted { color: var(--emerald); }
    .tag-settled { color: #a78bfa; }
    .tag-rejected { color: var(--red); }
    .status-toast {
      font-size: 0.82rem;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="title-group">
        <h1>BountySweep Agent — Mission Control</h1>
        <p>Autonomous Escrow Discovery · Gemini 3 Triage · Air-Gapped Docker Sandbox · Immutable Cold-Wallet Settlement</p>
      </div>
      <div class="badge-row">
        <span id="stateBadge" class="badge badge-running">RUNNING</span>
        <span id="modeBadge" class="badge badge-mode">MODE</span>
        <span id="autopollBadge" class="badge badge-autopoll">AUTO-POLL: OFF</span>
      </div>
    </header>

    <div class="card controls-card">
      <div class="btn-group">
        <button id="btnLiveCycle" class="btn-primary" onclick="triggerCycle(false)">▶ Run Live Scan Cycle</button>
        <button id="btnMockCycle" class="btn-secondary" onclick="triggerCycle(true)">⚡ Run Simulated Escrow Test</button>
        <button id="btnAutopoll" class="btn-amber" onclick="toggleAutopoll()">⟳ Enable Continuous Auto-Polling</button>
      </div>
      <div class="btn-group">
        <span id="toast" class="status-toast">Auto-refreshing every 3s</span>
        <button id="btnPause" class="btn-danger" onclick="setPause(true)">⏸ Emergency Kill-Switch (/pause)</button>
        <button id="btnResume" class="btn-success" onclick="setPause(false)" style="display:none;">▶ Resume Agent (/resume)</button>
      </div>
    </div>

    <div class="grid-kpi">
      <div class="card">
        <div class="kpi-label">Bounties Claimed</div>
        <div id="kpiClaimed" class="kpi-value">0</div>
        <div class="kpi-sub">Signed by Worker Hot Wallet</div>
      </div>
      <div class="card">
        <div class="kpi-label">PRs / Solutions Passed</div>
        <div id="kpiSubmitted" class="kpi-value">0</div>
        <div class="kpi-sub">100% Baseline + Regression Gate</div>
      </div>
      <div class="card">
        <div class="kpi-label">Security / Unfunded Blocked</div>
        <div id="kpiRejected" class="kpi-value">0</div>
        <div class="kpi-sub">Prompt-Injection & Escrow Filter</div>
      </div>
      <div class="card">
        <div class="kpi-label">Settled & Swept (USDC)</div>
        <div id="kpiSwept" class="kpi-value" style="color: var(--emerald);">$0.00</div>
        <div id="kpiThreshold" class="kpi-sub">Sweep Threshold: $5.00 USDC</div>
      </div>
    </div>

    <div class="wallet-bar">
      <div class="card">
        <div class="kpi-label">Immutable Owner Cold Wallet (Whitelisted Destination Only)</div>
        <div id="coldWallet" class="mono">—</div>
        <div class="kpi-sub" style="margin-top:8px;">
          <a id="coldWalletLink" href="#" target="_blank" rel="noopener">View on BaseScan ↗</a>
        </div>
      </div>
      <div class="card">
        <div class="kpi-label">Isolated Burner Worker Hot Wallet (Gas & Claim Signing Only)</div>
        <div id="workerWallet" class="mono">—</div>
        <div class="kpi-sub" style="margin-top:8px;">
          <a id="workerWalletLink" href="#" target="_blank" rel="noopener">View on BaseScan ↗</a>
        </div>
      </div>
    </div>

    <div class="two-col">
      <div class="card">
        <div class="section-title">
          <span>Real-Time Telegram & Security Alert Feed</span>
          <span id="alertCount" class="kpi-sub">0 alerts</span>
        </div>
        <div id="alertsFeed" class="feed">
          <div class="feed-item" style="color: var(--muted);">No alerts emitted yet. Click "Run Live Scan Cycle" or "Run Simulated Escrow Test".</div>
        </div>
      </div>
      <div class="card">
        <div class="section-title">
          <span>Latest Cycle Execution Inspector</span>
          <span id="cycleCount" class="kpi-sub">0 cycles</span>
        </div>
        <div id="cycleFeed" class="feed">
          <div class="feed-item" style="color: var(--muted);">Waiting for cycle execution...</div>
        </div>
      </div>
    </div>
  </div>

  <script>
    let currentAutopoll = false;

    function setToast(msg) {
      document.getElementById('toast').textContent = msg;
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/status');
        const data = await res.json();

        const stateBadge = document.getElementById('stateBadge');
        const btnPause = document.getElementById('btnPause');
        const btnResume = document.getElementById('btnResume');
        if (data.paused) {
          stateBadge.textContent = 'PAUSED (KILL-SWITCH ACTIVE)';
          stateBadge.className = 'badge badge-paused';
          btnPause.style.display = 'none';
          btnResume.style.display = 'inline-block';
        } else {
          stateBadge.textContent = 'RUNNING';
          stateBadge.className = 'badge badge-running';
          btnPause.style.display = 'inline-block';
          btnResume.style.display = 'none';
        }

        const modeBadge = document.getElementById('modeBadge');
        modeBadge.textContent = data.dry_run_mode ? 'DRY-RUN MODE' : 'LIVE PRODUCTION (' + data.chain_network.toUpperCase() + ')';

        currentAutopoll = Boolean(data.autopoll_enabled);
        const autopollBadge = document.getElementById('autopollBadge');
        const btnAutopoll = document.getElementById('btnAutopoll');
        autopollBadge.textContent = currentAutopoll
          ? 'AUTO-POLL: ON (' + (data.poll_interval_seconds || 300) + 's)'
          : 'AUTO-POLL: OFF';
        btnAutopoll.textContent = currentAutopoll
          ? '⏹ Stop Continuous Auto-Polling'
          : '⟳ Enable Continuous Auto-Polling';

        const m = data.metrics || {};
        document.getElementById('kpiClaimed').textContent = m.bounties_claimed ?? 0;
        document.getElementById('kpiSubmitted').textContent = m.solutions_submitted ?? 0;
        document.getElementById('kpiRejected').textContent = m.bounties_rejected ?? 0;
        document.getElementById('kpiSwept').textContent = '$' + Number(m.total_usdc_swept ?? 0).toFixed(2);
        document.getElementById('kpiThreshold').textContent = 'Sweep Threshold: $' + Number(data.sweep_threshold_usdc ?? 5).toFixed(2) + ' USDC';

        const cold = data.owner_cold_wallet_address || 'Not set';
        const worker = data.worker_wallet_address || 'Not set';
        document.getElementById('coldWallet').textContent = cold;
        document.getElementById(' coldWalletLink');
        document.getElementById('coldWalletLink').href = 'https://basescan.org/address/' + cold;
        document.getElementById('workerWallet').textContent = worker;
        document.getElementById('workerWalletLink').href = 'https://basescan.org/address/' + worker;

        const alerts = (data.recent_alerts || []).slice().reverse();
        document.getElementById('alertCount').textContent = alerts.length + ' recent alerts';
        const alertsFeed = document.getElementById('alertsFeed');
        if (alerts.length > 0) {
          alertsFeed.innerHTML = alerts.map(a => {
            let cls = 'tag-claimed';
            if ((a.tag || '').includes('Submitted')) cls = 'tag-submitted';
            else if ((a.tag || '').includes('Settled')) cls = 'tag-settled';
            else if ((a.tag || '').includes('Rejection')) cls = 'tag-rejected';
            return `<div class="feed-item"><span class="feed-tag ${cls}">${a.tag || 'ALERT'}</span> <span style="color:#6b7280;font-size:0.74rem;">${a.timestamp || ''}</span>\n${a.text || ''}</div>`;
          }).join('');
        }

        document.getElementById('cycleCount').textContent = (data.cycles_executed ?? 0) + ' total cycles';
        if (data.last_cycle) {
          document.getElementById('cycleFeed').innerHTML =
            `<div class="feed-item">${JSON.stringify(data.last_cycle, null, 2)}</div>`;
        }
      } catch (err) {
        setToast('Status poll error: ' + err.message);
      }
    }

    async function setPause(pause) {
      setToast(pause ? 'Activating kill-switch...' : 'Resuming agent...');
      await fetch(pause ? '/control/pause' : '/control/resume', { method: 'POST' });
      await fetchStatus();
      setToast(pause ? 'Kill-switch engaged.' : 'Agent resumed.');
    }

    async function toggleAutopoll() {
      const endpoint = currentAutopoll ? '/control/autopoll/stop' : '/control/autopoll/start';
      setToast(currentAutopoll ? 'Stopping continuous auto-poller...' : 'Starting continuous auto-poller...');
      await fetch(endpoint, { method: 'POST' });
      await fetchStatus();
    }

    async function triggerCycle(useMock) {
      const btnLive = document.getElementById('btnLiveCycle');
      const btnMock = document.getElementById('btnMockCycle');
      btnLive.disabled = true;
      btnMock.disabled = true;
      setToast(useMock ? 'Running simulated escrow cycle...' : 'Scanning live GitHub/Algora bounties...');
      try {
        const res = await fetch('/cycle/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ use_mock_bounty: useMock })
        });
        const data = await res.json();
        document.getElementById('cycleFeed').innerHTML =
          `<div class="feed-item">${JSON.stringify(data, null, 2)}</div>`;
        setToast('Cycle finished with status: ' + data.status);
      } catch (err) {
        setToast('Cycle error: ' + err.message);
      } finally {
        btnLive.disabled = false;
        btnMock.disabled = false;
        await fetchStatus();
      }
    }

    fetchStatus();
    setInterval(fetchStatus, 3000);
  </script>
</body>
</html>
"""
