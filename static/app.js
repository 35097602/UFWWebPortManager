const el = {
  loginCard: document.getElementById('loginCard'),
  panelCard: document.getElementById('panelCard'),
  rulesCard: document.getElementById('rulesCard'),
  logCard: document.getElementById('logCard'),
  loginNotice: document.getElementById('loginNotice'),
  username: document.getElementById('username'),
  password: document.getElementById('password'),
  loginBtn: document.getElementById('loginBtn'),
  logoutBtn: document.getElementById('logoutBtn'),
  currentUser: document.getElementById('currentUser'),
  ufwStateBadge: document.getElementById('ufwStateBadge'),
  ufwStateText: document.getElementById('ufwStateText'),
  enableUfwBtn: document.getElementById('enableUfwBtn'),
  disableUfwBtn: document.getElementById('disableUfwBtn'),
  ports: document.getElementById('ports'),
  protocol: document.getElementById('protocol'),
  openBtn: document.getElementById('openBtn'),
  closeBtn: document.getElementById('closeBtn'),
  refreshBtn: document.getElementById('refreshBtn'),
  rules: document.getElementById('rules'),
  log: document.getElementById('log'),
  chips: document.querySelectorAll('.chip'),
  ruleProtocolFilter: document.getElementById('ruleProtocolFilter'),
  rulePortSearch: document.getElementById('rulePortSearch'),
  ruleSortBtn: document.getElementById('ruleSortBtn')
};

const ruleState = {
  allRules: [],
  sortAsc: true
};

el.loginBtn.addEventListener('click', login);
el.logoutBtn.addEventListener('click', logout);
el.enableUfwBtn.addEventListener('click', () => toggleUFW('enable'));
el.disableUfwBtn.addEventListener('click', () => toggleUFW('disable'));
el.openBtn.addEventListener('click', () => submitAction('open'));
el.closeBtn.addEventListener('click', () => submitAction('close'));
el.refreshBtn.addEventListener('click', refreshRules);
el.password.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    login();
  }
});

if (el.ruleProtocolFilter) {
  el.ruleProtocolFilter.addEventListener('change', renderRulesTable);
}
if (el.rulePortSearch) {
  el.rulePortSearch.addEventListener('input', renderRulesTable);
}
if (el.ruleSortBtn) {
  el.ruleSortBtn.addEventListener('click', () => {
    ruleState.sortAsc = !ruleState.sortAsc;
    updateSortButtonText();
    renderRulesTable();
  });
}

el.chips.forEach((chip) => {
  chip.addEventListener('click', () => appendPort(chip.dataset.port));
});

updateSortButtonText();

function appendPort(port) {
  const current = el.ports.value.trim();
  if (!current) {
    el.ports.value = port;
    return;
  }
  const parts = new Set(current.split(/[\s,;]+/).filter(Boolean));
  parts.add(port);
  el.ports.value = Array.from(parts).join(',');
}

async function login() {
  const username = el.username.value.trim();
  const password = el.password.value;
  if (!username || !password) {
    showLoginNotice('\u8bf7\u8f93\u5165\u7528\u6237\u540d\u548c\u5bc6\u7801', 'error');
    return;
  }

  showLoginNotice('', '');
  setLoading(true);
  try {
    const resp = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      showLoginNotice(data.message || '\u767b\u5f55\u5931\u8d25', 'error');
      pushLog(`[\u5931\u8d25] ${data.message || `HTTP ${resp.status}`}`);
      return;
    }

    el.password.value = '';
    showLoginNotice('\u767b\u5f55\u6210\u529f\uff0c\u6b63\u5728\u8fdb\u5165\u9762\u677f...', 'success');
    setAuthUI(true, data?.data?.username || username);
    pushLog('[\u5b8c\u6210] \u767b\u5f55\u6210\u529f');
    await refreshRules();
  } catch (err) {
    showLoginNotice(`\u767b\u5f55\u8bf7\u6c42\u5931\u8d25: ${err.message}`, 'error');
    pushLog(`[\u9519\u8bef] \u767b\u5f55\u5931\u8d25: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

async function logout() {
  try {
    await fetch('/api/logout', { method: 'POST' });
  } catch (_) {
    // ignore
  }
  setAuthUI(false, '');
  showLoginNotice('\u5df2\u9000\u51fa\u767b\u5f55', 'success');
  pushLog('[\u5b8c\u6210] \u5df2\u9000\u51fa\u767b\u5f55');
}

async function toggleUFW(action) {
  setLoading(true);
  pushLog(`[\u8bf7\u6c42] UFW ${action}`);
  try {
    const resp = await fetch('/api/ufw', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    });
    const data = await resp.json();

    if (resp.status === 401) {
      setAuthUI(false, '');
      showLoginNotice('\u4f1a\u8bdd\u5df2\u5931\u6548\uff0c\u8bf7\u91cd\u65b0\u767b\u5f55', 'error');
      pushLog('[\u5931\u8d25] \u4f1a\u8bdd\u5df2\u5931\u6548\uff0c\u8bf7\u91cd\u65b0\u767b\u5f55');
      return;
    }

    if (!resp.ok || !data.ok) {
      pushLog(`[\u5931\u8d25] ${data.message || `HTTP ${resp.status}`}`);
      if (data?.data?.output) {
        pushLog(`[DETAIL] ${data.data.output}`);
      }
      return;
    }

    pushLog(`[\u5b8c\u6210] ${data.message}`);
    if (data?.data?.output) {
      pushLog(`[DETAIL] ${data.data.output}`);
    }
    updateUFWState(data?.data?.ufw_active, data?.data?.ufw_status);
    await refreshRules();
  } catch (err) {
    pushLog(`[\u9519\u8bef] UFW \u5f00\u5173\u5931\u8d25: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

async function submitAction(action) {
  const ports = el.ports.value.trim();
  if (!ports) {
    pushLog('\u8bf7\u5148\u586b\u5199\u7aef\u53e3\uff0c\u4f8b\u5982: 22,80,443');
    return;
  }

  setLoading(true);
  pushLog(`[\u8bf7\u6c42] ${action === 'open' ? '\u5f00\u653e' : '\u5173\u95ed'}\u7aef\u53e3 ${ports}, \u534f\u8bae: ${el.protocol.value}`);

  try {
    const resp = await fetch('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ports,
        protocol: el.protocol.value,
        action
      })
    });

    const data = await resp.json();
    if (resp.status === 401) {
      setAuthUI(false, '');
      showLoginNotice('\u4f1a\u8bdd\u5df2\u5931\u6548\uff0c\u8bf7\u91cd\u65b0\u767b\u5f55', 'error');
      pushLog('[\u5931\u8d25] \u4f1a\u8bdd\u5df2\u5931\u6548\uff0c\u8bf7\u91cd\u65b0\u767b\u5f55');
      return;
    }
    if (!resp.ok || !data.ok) {
      pushLog(`[\u5931\u8d25] ${data.message || `HTTP ${resp.status}`}`);
      if (data?.data?.results) {
        renderApplyResult(data.data.results);
      }
      return;
    }

    pushLog(`[\u5b8c\u6210] ${data.message}`);
    renderApplyResult(data.data.results);
    await refreshRules();
  } catch (err) {
    pushLog(`[\u9519\u8bef] ${err.message}`);
  } finally {
    setLoading(false);
  }
}

async function refreshRules() {
  try {
    const resp = await fetch('/api/status');
    const data = await resp.json();

    if (resp.status === 401) {
      setAuthUI(false, '');
      showLoginNotice('\u672a\u767b\u5f55\u6216\u4f1a\u8bdd\u5931\u6548', 'error');
      pushLog('[\u5931\u8d25] \u672a\u767b\u5f55\u6216\u4f1a\u8bdd\u5931\u6548');
      return;
    }
    if (!resp.ok || !data.ok) {
      pushLog(`[\u5931\u8d25] \u8bfb\u53d6\u89c4\u5219\u5931\u8d25: ${data.message || `HTTP ${resp.status}`}`);
      return;
    }

    updateUFWState(data?.data?.ufw_active, data?.data?.ufw_status);
    ruleState.allRules = Array.isArray(data?.data?.rules) ? data.data.rules : [];
    renderRulesTable();
  } catch (err) {
    pushLog(`[\u9519\u8bef] \u5237\u65b0\u89c4\u5219\u5931\u8d25: ${err.message}`);
  }
}

function renderRulesTable() {
  const protocolFilter = (el.ruleProtocolFilter?.value || 'all').toLowerCase();
  const keyword = (el.rulePortSearch?.value || '').trim();

  let list = [...ruleState.allRules];
  if (protocolFilter !== 'all') {
    list = list.filter((r) => (r.protocol || '').toLowerCase() === protocolFilter);
  }
  if (keyword) {
    list = list.filter((r) => String(r.port).includes(keyword));
  }

  list.sort((a, b) => {
    if (a.port === b.port) {
      return (a.protocol || '').localeCompare(b.protocol || '');
    }
    return ruleState.sortAsc ? a.port - b.port : b.port - a.port;
  });

  if (!list.length) {
    el.rules.innerHTML = '<div class="rules-empty">No matched rules.</div>';
    return;
  }

  const html = list.map((rule) => `
    <div class="rule-row">
      <div><strong>${rule.port}</strong></div>
      <div>${String(rule.protocol || '').toUpperCase()}</div>
      <div><span class="badge badge-ok">${rule.policy || ''}</span></div>
      <div>${rule.direction || ''}</div>
    </div>
  `).join('');

  el.rules.innerHTML = html;
}

function updateSortButtonText() {
  if (!el.ruleSortBtn) {
    return;
  }
  el.ruleSortBtn.textContent = ruleState.sortAsc ? 'Sort Port: ASC' : 'Sort Port: DESC';
}

function updateUFWState(active, statusText) {
  const isActive = !!active;
  const stateText = (statusText || 'unknown').toString();
  el.ufwStateBadge.textContent = isActive ? '\u5df2\u5f00\u542f' : '\u5df2\u5173\u95ed';
  el.ufwStateBadge.classList.remove('ufw-badge-on', 'ufw-badge-off');
  el.ufwStateBadge.classList.add(isActive ? 'ufw-badge-on' : 'ufw-badge-off');
  el.ufwStateText.textContent = `status: ${stateText}`;
}

function renderApplyResult(results) {
  if (!Array.isArray(results)) {
    return;
  }

  results.forEach((item) => {
    const result = `${item.port}/${item.protocol} ${item.action}`;
    if (item.exit_ok) {
      pushLog(`[OK] ${result} -> ${item.output || 'success'}`);
      return;
    }
    const detail = [item.error_text, item.output].filter(Boolean).join(' | ');
    pushLog(`[FAIL] ${result} -> ${detail}`);
  });
}

function setLoading(v) {
  [el.loginBtn, el.logoutBtn, el.enableUfwBtn, el.disableUfwBtn, el.openBtn, el.closeBtn, el.refreshBtn, el.ruleSortBtn].forEach((b) => {
    if (b) {
      b.disabled = v;
    }
  });
}

function pushLog(text) {
  const now = new Date().toLocaleTimeString();
  el.log.textContent = `[${now}] ${text}\n` + el.log.textContent;
}

function showLoginNotice(message, type) {
  if (!el.loginNotice) {
    return;
  }
  el.loginNotice.classList.remove('notice-success', 'notice-error');
  if (!message) {
    el.loginNotice.classList.add('hidden');
    el.loginNotice.textContent = '';
    return;
  }
  el.loginNotice.textContent = message;
  el.loginNotice.classList.remove('hidden');
  if (type === 'success') {
    el.loginNotice.classList.add('notice-success');
  } else {
    el.loginNotice.classList.add('notice-error');
  }
}

function setAuthUI(isAuthed, username) {
  el.loginCard.classList.toggle('hidden', isAuthed);
  el.panelCard.classList.toggle('hidden', !isAuthed);
  el.rulesCard.classList.toggle('hidden', !isAuthed);
  el.logCard.classList.toggle('hidden', !isAuthed);
  if (isAuthed) {
    el.currentUser.textContent = `\u5df2\u767b\u5f55: ${username}`;
    showLoginNotice('', '');
  }
}

async function init() {
  try {
    const resp = await fetch('/api/me');
    const data = await resp.json();
    if (resp.ok && data.ok) {
      setAuthUI(true, data?.data?.username || 'admin');
      await refreshRules();
      return;
    }
  } catch (_) {
    // ignore
  }
  setAuthUI(false, '');
}

init();