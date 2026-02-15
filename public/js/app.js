// ── State ──
const STORAGE_KEY = 'tubescore_pro_token';
const SCAN_KEY = 'tubescore_scans';
let currentUser = null;

function getProToken() {
  return localStorage.getItem(STORAGE_KEY);
}

function setProToken(token) {
  localStorage.setItem(STORAGE_KEY, token);
}

// Track scans client-side as secondary check (server is source of truth)
function getLocalScans() {
  try {
    const data = JSON.parse(localStorage.getItem(SCAN_KEY) || '{}');
    const now = new Date();
    const key = `${now.getFullYear()}-${now.getMonth()}`;
    return data[key] || 0;
  } catch {
    return 0;
  }
}

function incrementLocalScans() {
  try {
    const data = JSON.parse(localStorage.getItem(SCAN_KEY) || '{}');
    const now = new Date();
    const key = `${now.getFullYear()}-${now.getMonth()}`;
    data[key] = (data[key] || 0) + 1;
    localStorage.setItem(SCAN_KEY, JSON.stringify(data));
  } catch { /* ignore */ }
}

// ── Auth ──
async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();
    currentUser = data.user;
  } catch {
    currentUser = null;
  }
  updateNavState();
}

function updateNavState() {
  const guestNav = document.getElementById('nav-guest');
  const userNav = document.getElementById('nav-user');
  if (currentUser) {
    guestNav.classList.add('hidden');
    userNav.classList.remove('hidden');
  } else {
    guestNav.classList.remove('hidden');
    userNav.classList.add('hidden');
  }
}

// ── Auth Modal ──
let authMode = 'login';

function showAuthModal(mode) {
  authMode = mode || 'login';
  updateAuthModal();
  document.getElementById('auth-modal').classList.remove('hidden');
  document.getElementById('auth-email').focus();
}

function closeAuthModal() {
  document.getElementById('auth-modal').classList.add('hidden');
  document.getElementById('auth-form').reset();
  document.getElementById('auth-error').classList.add('hidden');
}

function toggleAuthMode() {
  authMode = authMode === 'login' ? 'signup' : 'login';
  updateAuthModal();
}

function updateAuthModal() {
  const title = document.getElementById('auth-modal-title');
  const submit = document.getElementById('auth-submit');
  const toggleText = document.getElementById('auth-toggle-text');
  const toggleLink = document.getElementById('auth-toggle-link');

  if (authMode === 'login') {
    title.textContent = 'Log In';
    submit.textContent = 'Log In';
    toggleText.textContent = "Don't have an account?";
    toggleLink.textContent = 'Sign up';
  } else {
    title.textContent = 'Sign Up';
    submit.textContent = 'Create Account';
    toggleText.textContent = 'Already have an account?';
    toggleLink.textContent = 'Log in';
  }
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const email = document.getElementById('auth-email').value.trim();
  const password = document.getElementById('auth-password').value;
  const errorEl = document.getElementById('auth-error');

  errorEl.classList.add('hidden');

  const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error;
      errorEl.classList.remove('hidden');
      return;
    }

    currentUser = data.user;
    updateNavState();
    closeAuthModal();
    showError(authMode === 'signup' ? 'Account created! Welcome to TubeScore.' : 'Welcome back!', true);
  } catch {
    errorEl.textContent = 'Something went wrong. Please try again.';
    errorEl.classList.remove('hidden');
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch { /* ignore */ }
  currentUser = null;
  updateNavState();
  navigateTo('/');
  showError('You have been logged out.', true);
}

// ── Hash Router ──
function navigateTo(path) {
  if (path === '/') {
    // Clear hash and trigger route
    if (window.location.hash) {
      window.location.hash = '';
    } else {
      handleRoute();
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } else {
    window.location.hash = path;
  }
}

function handleRoute() {
  const hash = window.location.hash;
  const pages = ['page-home', 'page-history', 'page-history-detail', 'page-settings'];

  // Hide all pages
  pages.forEach(p => {
    const el = document.getElementById(p);
    if (el) el.classList.add('hidden');
  });

  if (hash === '#/history') {
    if (!currentUser) { navigateTo('/'); return; }
    document.getElementById('page-history').classList.remove('hidden');
    loadHistory();
  } else if (hash.startsWith('#/history/')) {
    if (!currentUser) { navigateTo('/'); return; }
    const id = hash.split('/')[2];
    document.getElementById('page-history-detail').classList.remove('hidden');
    loadHistoryDetail(id);
  } else if (hash === '#/settings') {
    if (!currentUser) { navigateTo('/'); return; }
    document.getElementById('page-settings').classList.remove('hidden');
    loadSettings();
  } else {
    // Home page
    document.getElementById('page-home').classList.remove('hidden');
    if (hash === '#pricing') {
      setTimeout(() => {
        document.getElementById('pricing')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    }
  }
}

window.addEventListener('hashchange', handleRoute);

// ── Stripe Return ──
async function checkStripeReturn() {
  const params = new URLSearchParams(window.location.search);
  const sessionId = params.get('session_id');
  if (!sessionId) return;

  window.history.replaceState({}, '', '/');

  try {
    const res = await fetch(`/api/verify/${sessionId}`);
    const data = await res.json();
    if (data.isPro) {
      if (currentUser) {
        await checkAuth();
      } else {
        setProToken(sessionId);
      }
      showError(`Welcome to TubeScore ${data.plan === 'agency' ? 'Agency' : 'Pro'}! You now have unlimited scans.`, true);
    }
  } catch { /* ignore */ }
}

// ── Main Analysis ──
async function handleAnalyze() {
  const input = document.getElementById('url-input');
  const btn = document.getElementById('analyze-btn');
  const url = input.value.trim();

  if (!url) {
    showError('Please paste a YouTube video URL.');
    return;
  }

  // Show loading
  hideError();
  hideScorecard();
  showLoading();
  btn.disabled = true;

  try {
    // Animate progress steps
    setStep('fetch');
    await delay(400);

    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url,
        proToken: getProToken(),
      }),
    });

    setStep('ai');

    const data = await res.json();

    if (!res.ok) {
      if (data.limitReached) {
        hideLoading();
        showUpgradeModal();
        return;
      }
      throw new Error(data.error || 'Analysis failed.');
    }

    setStep('score');
    await delay(300);

    incrementLocalScans();
    renderScorecard(data);
    hideLoading();
    showScorecard();

    // Scroll to scorecard
    document.getElementById('scorecard').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    hideLoading();
    showError(err.message);
  } finally {
    btn.disabled = false;
  }
}

// ── Render Scorecard ──
function renderScorecard(data) {
  const { video, analysis } = data;

  document.getElementById('sc-thumb').src = video.thumbnail;
  document.getElementById('sc-title').textContent = video.title;
  document.getElementById('sc-channel').textContent = video.channelTitle;
  document.getElementById('sc-views').textContent = `${formatNum(video.viewCount)} views`;
  document.getElementById('sc-likes').textContent = `${formatNum(video.likeCount)} likes`;
  document.getElementById('sc-comments').textContent = `${formatNum(video.commentCount)} comments`;

  const overall = document.getElementById('sc-overall');
  overall.textContent = analysis.overall_grade;
  overall.className = `overall-grade ${gradeClass(analysis.overall_grade)}`;

  // Categories
  const categories = [
    { key: 'title', name: 'Title' },
    { key: 'thumbnail', name: 'Thumbnail' },
    { key: 'description_tags', name: 'Description & Tags' },
    { key: 'engagement', name: 'Engagement' },
    { key: 'video_length', name: 'Video Length' },
  ];

  const container = document.getElementById('categories');
  container.innerHTML = '';

  categories.forEach(cat => {
    const catData = analysis[cat.key];
    if (!catData) return;

    const card = document.createElement('div');
    card.className = 'category-card';

    card.innerHTML = `
      <div class="category-header" onclick="this.parentElement.classList.toggle('open')">
        <span class="grade ${gradeClass(catData.grade)}">${catData.grade}</span>
        <span class="category-name">${cat.name}</span>
        <span class="category-arrow">&#9660;</span>
      </div>
      <div class="category-body">
        <h4>Issues Found</h4>
        <ul class="issues-list">
          ${(catData.issues || []).map(i => `<li>${escapeHtml(i)}</li>`).join('')}
        </ul>
        <h4>Recommended Fixes</h4>
        <ul class="fixes-list">
          ${(catData.fixes || []).map(f => `<li>${escapeHtml(f)}</li>`).join('')}
        </ul>
      </div>
    `;

    container.appendChild(card);
  });

  // Quick wins
  const winsList = document.getElementById('wins-list');
  winsList.innerHTML = '';

  (analysis.quick_wins || []).forEach(win => {
    const div = document.createElement('div');
    div.className = 'win-card';
    div.innerHTML = `
      <div class="win-change">${escapeHtml(win.change)}</div>
      <div class="win-impact">${escapeHtml(win.impact)}</div>
    `;
    winsList.appendChild(div);
  });
}

// ── Stripe Upgrade ──
async function handleUpgrade(plan) {
  closeModal();
  try {
    const res = await fetch('/api/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan: plan || 'pro' }),
    });
    const data = await res.json();
    if (data.url) {
      window.location.href = data.url;
    } else {
      showError('Failed to start checkout. Please try again.');
    }
  } catch {
    showError('Failed to start checkout. Please try again.');
  }
}

// ── History ──
async function loadHistory(page) {
  page = page || 1;
  try {
    const res = await fetch(`/api/history?page=${page}`);
    if (!res.ok) throw new Error();
    const data = await res.json();

    const grid = document.getElementById('history-grid');
    const empty = document.getElementById('history-empty');
    const pagination = document.getElementById('history-pagination');

    if (data.scans.length === 0) {
      grid.innerHTML = '';
      empty.classList.remove('hidden');
      pagination.classList.add('hidden');
      return;
    }

    empty.classList.add('hidden');
    grid.innerHTML = data.scans.map(scan => `
      <div class="history-card" onclick="navigateTo('/history/${scan.id}')">
        <img src="${escapeHtml(scan.thumbnail_url || '')}" alt="" class="history-thumb">
        <div class="history-info">
          <h4 class="history-title">${escapeHtml(scan.video_title)}</h4>
          <p class="history-channel">${escapeHtml(scan.channel_title)}</p>
          <div class="history-meta">
            <span class="grade ${gradeClass(scan.overall_grade)}" style="width:32px;height:32px;font-size:15px;">${escapeHtml(scan.overall_grade || '?')}</span>
            <span class="history-date">${new Date(scan.created_at + 'Z').toLocaleDateString()}</span>
          </div>
        </div>
      </div>
    `).join('');

    // Pagination
    if (data.totalPages > 1) {
      pagination.classList.remove('hidden');
      pagination.innerHTML = '';
      for (let i = 1; i <= data.totalPages; i++) {
        const btn = document.createElement('button');
        btn.className = `pagination-btn${i === data.page ? ' active' : ''}`;
        btn.textContent = i;
        btn.onclick = () => loadHistory(i);
        pagination.appendChild(btn);
      }
    } else {
      pagination.classList.add('hidden');
    }
  } catch {
    document.getElementById('history-grid').innerHTML = '<p style="color: var(--text-muted);">Failed to load history.</p>';
  }
}

async function loadHistoryDetail(id) {
  try {
    const res = await fetch(`/api/history/${id}`);
    if (!res.ok) throw new Error();
    const data = await res.json();

    const container = document.getElementById('history-scorecard');
    container.innerHTML = buildScorecardHTML(data.video, data.analysis);
  } catch {
    document.getElementById('history-scorecard').innerHTML = '<p style="color: var(--text-muted);">Failed to load scan details.</p>';
  }
}

function buildScorecardHTML(video, analysis) {
  const categories = [
    { key: 'title', name: 'Title' },
    { key: 'thumbnail', name: 'Thumbnail' },
    { key: 'description_tags', name: 'Description & Tags' },
    { key: 'engagement', name: 'Engagement' },
    { key: 'video_length', name: 'Video Length' },
  ];

  return `
    <div class="score-header">
      <img class="sc-thumb" src="${escapeHtml(video.thumbnail || '')}" alt="Video thumbnail">
      <div class="score-header-info">
        <h2>${escapeHtml(video.title)}</h2>
        <p class="sc-channel">${escapeHtml(video.channelTitle)}</p>
        <div class="sc-stats">
          <span>${formatNum(video.viewCount)} views</span>
          <span>${formatNum(video.likeCount)} likes</span>
          <span>${formatNum(video.commentCount)} comments</span>
        </div>
      </div>
      <div class="overall-grade-box">
        <div class="overall-label">Overall</div>
        <div class="overall-grade ${gradeClass(analysis.overall_grade)}">${escapeHtml(analysis.overall_grade)}</div>
      </div>
    </div>
    <div class="categories">
      ${categories.map(cat => {
        const catData = analysis[cat.key];
        if (!catData) return '';
        return `
          <div class="category-card">
            <div class="category-header" onclick="this.parentElement.classList.toggle('open')">
              <span class="grade ${gradeClass(catData.grade)}">${catData.grade}</span>
              <span class="category-name">${cat.name}</span>
              <span class="category-arrow">&#9660;</span>
            </div>
            <div class="category-body">
              <h4>Issues Found</h4>
              <ul class="issues-list">
                ${(catData.issues || []).map(i => `<li>${escapeHtml(i)}</li>`).join('')}
              </ul>
              <h4>Recommended Fixes</h4>
              <ul class="fixes-list">
                ${(catData.fixes || []).map(f => `<li>${escapeHtml(f)}</li>`).join('')}
              </ul>
            </div>
          </div>
        `;
      }).join('')}
    </div>
    <div class="quick-wins">
      <h3>Quick Wins</h3>
      <div class="wins-list">
        ${(analysis.quick_wins || []).map(win => `
          <div class="win-card">
            <div class="win-change">${escapeHtml(win.change)}</div>
            <div class="win-impact">${escapeHtml(win.impact)}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ── Settings ──
async function loadSettings() {
  try {
    const res = await fetch('/api/account');
    if (!res.ok) throw new Error();
    const data = await res.json();

    document.getElementById('settings-email').textContent = data.email;
    document.getElementById('settings-since').textContent = new Date(data.created_at + 'Z').toLocaleDateString();

    const planEl = document.getElementById('settings-plan');
    planEl.textContent = data.plan.charAt(0).toUpperCase() + data.plan.slice(1);
    planEl.className = `settings-value plan-badge plan-${data.plan}`;

    const scansEl = document.getElementById('settings-scans');
    if (data.scan_limit) {
      scansEl.textContent = `${data.scans_used} / ${data.scan_limit}`;
    } else {
      scansEl.textContent = `${data.scans_used} (unlimited)`;
    }

    if (data.plan !== 'free') {
      document.getElementById('settings-billing-row').classList.remove('hidden');
      document.getElementById('settings-upgrade-row').classList.add('hidden');
    } else {
      document.getElementById('settings-billing-row').classList.add('hidden');
      document.getElementById('settings-upgrade-row').classList.remove('hidden');
    }
  } catch { /* ignore */ }

  // Reset password form state
  document.getElementById('password-form').reset();
  document.getElementById('password-error').classList.add('hidden');
  document.getElementById('password-success').classList.add('hidden');
}

async function handlePasswordChange(e) {
  e.preventDefault();
  const errorEl = document.getElementById('password-error');
  const successEl = document.getElementById('password-success');
  errorEl.classList.add('hidden');
  successEl.classList.add('hidden');

  const currentPassword = document.getElementById('current-password').value;
  const newPassword = document.getElementById('new-password').value;

  try {
    const res = await fetch('/api/account/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newPassword }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error;
      errorEl.classList.remove('hidden');
      return;
    }

    successEl.textContent = 'Password updated successfully.';
    successEl.classList.remove('hidden');
    document.getElementById('password-form').reset();
  } catch {
    errorEl.textContent = 'Failed to update password.';
    errorEl.classList.remove('hidden');
  }
}

async function handleBillingPortal() {
  try {
    const res = await fetch('/api/billing-portal', { method: 'POST' });
    const data = await res.json();
    if (data.url) {
      window.location.href = data.url;
    } else {
      showError(data.error || 'Failed to open billing portal.');
    }
  } catch {
    showError('Failed to open billing portal.');
  }
}

// ── UI Helpers ──
function showLoading() { document.getElementById('loading').classList.remove('hidden'); }
function hideLoading() { document.getElementById('loading').classList.add('hidden'); }
function showScorecard() { document.getElementById('scorecard').classList.remove('hidden'); }
function hideScorecard() { document.getElementById('scorecard').classList.add('hidden'); }

function showUpgradeModal() { document.getElementById('upgrade-modal').classList.remove('hidden'); }
function closeModal() { document.getElementById('upgrade-modal').classList.add('hidden'); }

function showError(msg, isSuccess) {
  const banner = document.getElementById('error-banner');
  banner.textContent = msg;
  banner.classList.remove('hidden');
  if (isSuccess) {
    banner.style.background = 'rgba(34, 197, 94, 0.12)';
    banner.style.borderColor = 'rgba(34, 197, 94, 0.3)';
    banner.style.color = '#86efac';
  } else {
    banner.style.background = '';
    banner.style.borderColor = '';
    banner.style.color = '';
  }
}

function hideError() { document.getElementById('error-banner').classList.add('hidden'); }

function setStep(active) {
  const steps = ['fetch', 'ai', 'score'];
  const idx = steps.indexOf(active);
  steps.forEach((s, i) => {
    const el = document.getElementById(`step-${s}`);
    el.classList.remove('active', 'done');
    if (i < idx) el.classList.add('done');
    else if (i === idx) el.classList.add('active');
  });
}

function resetApp() {
  hideScorecard();
  hideError();
  document.getElementById('url-input').value = '';
  document.getElementById('url-input').focus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function gradeClass(grade) {
  const g = (grade || '').toUpperCase();
  if (g === 'A' || g === 'A+' || g === 'A-') return 'grade-a';
  if (g === 'B' || g === 'B+' || g === 'B-') return 'grade-b';
  if (g === 'C' || g === 'C+' || g === 'C-') return 'grade-c';
  if (g === 'D' || g === 'D+' || g === 'D-') return 'grade-d';
  return 'grade-f';
}

function formatNum(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function delay(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// Allow Enter key to trigger analysis
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') handleAnalyze();
});

// ── Init ──
(async function init() {
  await checkAuth();
  await checkStripeReturn();
  handleRoute();
})();
