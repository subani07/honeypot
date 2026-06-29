/* ── Dashboard JS ─────────────────────────────────────────────────────────── */

const socket = io();

// ── Clock ─────────────────────────────────────────────────────────────────────
function tickClock() {
  document.getElementById('clock').textContent =
    new Date().toUTCString().replace('GMT', 'UTC');
}
setInterval(tickClock, 1000);
tickClock();

// ── Chart colour palette ──────────────────────────────────────────────────────
const PALETTE = ['#38bdf8','#818cf8','#34d399','#fb923c','#f472b6','#fbbf24','#a78bfa'];
const SVC_COLORS = { ssh:'#38bdf8', http:'#818cf8', ftp:'#34d399', telnet:'#fb923c', smtp:'#f472b6' };

// ── Timeline chart ────────────────────────────────────────────────────────────
const timelineCtx = document.getElementById('timelineChart').getContext('2d');
const timelineChart = new Chart(timelineCtx, {
  type: 'line',
  data: { labels: [], datasets: [{
    label: 'Attacks',
    data: [],
    borderColor:     '#38bdf8',
    backgroundColor: 'rgba(56,189,248,0.08)',
    borderWidth:     2,
    pointRadius:     3,
    pointBackgroundColor: '#38bdf8',
    fill:            true,
    tension:         0.4,
  }]},
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: {
      backgroundColor: '#111827',
      borderColor:     '#38bdf8',
      borderWidth:     1,
      titleColor:      '#e2e8f0',
      bodyColor:       '#94a3b8',
    }},
    scales: {
      x: { ticks: { color: '#64748b', maxTicksLimit: 8, font: { family: 'JetBrains Mono', size: 10 } },
           grid:  { color: 'rgba(99,179,237,0.06)' }},
      y: { ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
           grid:  { color: 'rgba(99,179,237,0.06)' }, beginAtZero: true },
    },
  },
});

// ── Service pie chart ─────────────────────────────────────────────────────────
const serviceCtx = document.getElementById('serviceChart').getContext('2d');
const serviceChart = new Chart(serviceCtx, {
  type: 'doughnut',
  data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 6 }]},
  options: {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '68%',
    plugins: {
      legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 }, boxWidth: 12, padding: 14 }},
      tooltip: { backgroundColor: '#111827', borderColor: '#818cf8', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' },
    },
  },
});

// ── Update charts from stats ──────────────────────────────────────────────────
function applyStats(stats) {
  // Stat cards
  animateCounter('totalEvents',  stats.total_events);
  animateCounter('uniqueIPs',    stats.unique_attackers);

  const topSvc = stats.by_service?.[0];
  document.getElementById('topService').textContent = topSvc ? topSvc.service.toUpperCase() : '—';

  // Recent (last hour from hourly data)
  const now   = new Date();
  const hStr  = now.toISOString().slice(0, 13) + ':00:00Z';
  const hr    = (stats.hourly || []).find(h => h.hour === hStr);
  animateCounter('recentCount', hr ? hr.cnt : 0);

  // Timeline chart
  const labels = (stats.hourly || []).map(h => h.hour.slice(11, 16));
  const values = (stats.hourly || []).map(h => h.cnt);
  timelineChart.data.labels                = labels;
  timelineChart.data.datasets[0].data     = values;
  timelineChart.update('active');

  // Service doughnut
  const svcLabels = (stats.by_service || []).map(s => s.service.toUpperCase());
  const svcCounts = (stats.by_service || []).map(s => s.cnt);
  serviceChart.data.labels              = svcLabels;
  serviceChart.data.datasets[0].data   = svcCounts;
  serviceChart.data.datasets[0].backgroundColor = svcLabels.map(
    (_, i) => PALETTE[i % PALETTE.length]
  );
  serviceChart.update('active');

  // Top IPs table
  renderTopIPs(stats.top_ips || []);
}

// ── Counter animation ─────────────────────────────────────────────────────────
function animateCounter(id, target) {
  const el  = document.getElementById(id);
  const cur = parseInt(el.textContent.replace(/,/g, '')) || 0;
  if (cur === target) return;
  const step = Math.ceil(Math.abs(target - cur) / 20);
  let   val  = cur;
  const iv   = setInterval(() => {
    val = val < target ? Math.min(val + step, target) : Math.max(val - step, target);
    el.textContent = val.toLocaleString();
    if (val === target) clearInterval(iv);
  }, 30);
  // Flash parent card
  const card = el.closest('.stat-card');
  if (card) {
    card.classList.remove('stat-flash');
    void card.offsetWidth; // reflow
    card.classList.add('stat-flash');
  }
}

// ── Top IPs table ─────────────────────────────────────────────────────────────
function renderTopIPs(ips) {
  const tbody  = document.getElementById('topIpBody');
  const maxCnt = ips.length ? ips[0].cnt : 1;
  tbody.innerHTML = ips.map((row, i) => `
    <tr>
      <td style="color:var(--text-muted)">${i + 1}</td>
      <td class="ip-text">${row.src_ip}</td>
      <td>${row.flag || ''} ${row.country || '—'}</td>
      <td style="color:var(--yellow);font-weight:600">${row.cnt.toLocaleString()}</td>
      <td class="bar-cell"><div class="bar-fill" style="width:${Math.round((row.cnt/maxCnt)*100)}%"></div></td>
    </tr>
  `).join('');
}

// ── Credentials table ─────────────────────────────────────────────────────────
function loadCredentials() {
  fetch('/api/credentials')
    .then(r => r.json())
    .then(creds => {
      document.getElementById('credCount').textContent = `${creds.length} captured`;
      const tbody = document.getElementById('credBody');
      tbody.innerHTML = creds.map(c => `
        <tr>
          <td style="color:var(--text-muted)">${c.timestamp.replace('T', ' ')}</td>
          <td class="ip-text">${c.src_ip}</td>
          <td>${c.flag || ''} ${c.country || '—'}</td>
          <td class="cred-user">${esc(c.username)}</td>
          <td class="cred-pass">${esc(c.password)}</td>
        </tr>
      `).join('');
    });
}

// ── Live feed ─────────────────────────────────────────────────────────────────
const MAX_FEED_ITEMS = 80;

function addFeedEntry(ev) {
  const feed = document.getElementById('liveFeed');
  const time = (ev.timestamp || '').replace('T', ' ').slice(0, 19);
  const svc  = (ev.service || '').toLowerCase();
  const cred = ev.username ? `<span class="feed-cred">${esc(ev.username)}/${esc(ev.password || '?')}</span>` : '';
  const loc  = ev.country ? `${ev.flag || ''} ${ev.city ? ev.city + ', ' : ''}${ev.country}` : '';

  const entry = document.createElement('div');
  entry.className = 'feed-entry';
  entry.innerHTML = `
    <span class="feed-time">${time}</span>
    <span class="feed-service svc-${svc}">${svc.toUpperCase()}</span>
    <span class="feed-ip">${ev.src_ip || ''}</span>
    <span class="feed-event">${esc(ev.event_type || '')}</span>
    ${cred}
    <span class="feed-flag">${loc}</span>
  `;

  feed.prepend(entry);

  // Trim old entries
  while (feed.children.length > MAX_FEED_ITEMS) {
    feed.removeChild(feed.lastChild);
  }
}

function clearFeed() {
  document.getElementById('liveFeed').innerHTML = '';
}

// ── HTML escape ───────────────────────────────────────────────────────────────
function esc(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Socket.IO event handlers ──────────────────────────────────────────────────
socket.on('connect', () => {
  document.getElementById('liveBadge').style.opacity = '1';
});

socket.on('disconnect', () => {
  document.getElementById('liveBadge').style.opacity = '0.4';
});

socket.on('stats_update', (stats) => {
  applyStats(stats);
});

socket.on('new_event', (ev) => {
  addFeedEntry(ev);
  // Re-fetch stats every 10 events to keep charts up-to-date
  _eventCount++;
  if (_eventCount % 10 === 0) refreshStats();
  // Refresh credentials if it's an auth event
  if (ev.username) loadCredentials();
});

let _eventCount = 0;

// ── Initial data load ─────────────────────────────────────────────────────────
function refreshStats() {
  fetch('/api/stats').then(r => r.json()).then(applyStats);
}

function loadRecentEvents() {
  fetch('/api/events')
    .then(r => r.json())
    .then(events => events.slice(0, 40).reverse().forEach(addFeedEntry));
}

refreshStats();
loadRecentEvents();
loadCredentials();

// Periodic refresh every 30s
setInterval(refreshStats, 30_000);
setInterval(loadCredentials, 60_000);
