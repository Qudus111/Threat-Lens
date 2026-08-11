// ---------- Page navigation ----------
const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page');

function goToPage(pageName) {
  navItems.forEach(item => item.classList.toggle('active', item.dataset.page === pageName));
  pages.forEach(page => page.classList.toggle('active', page.id === `page-${pageName}`));
  if (pageName === 'reports' && typeof renderReports === 'function') renderReports();
}

navItems.forEach(item => {
  item.addEventListener('click', () => goToPage(item.dataset.page));
});

// Any element with data-page-link jumps to that page too (e.g. Quick Action cards)
document.querySelectorAll('[data-page-link]').forEach(el => {
  el.addEventListener('click', () => goToPage(el.dataset.pageLink));
});

// ---------- Greeting ----------
function setGreeting() {
  const hour = new Date().getHours();
  let text = 'Good Morning,';
  if (hour >= 12 && hour < 17) text = 'Good Afternoon,';
  else if (hour >= 17) text = 'Good Evening,';
  document.getElementById('greetingTime').textContent = text;
}
setGreeting();

// ---------- Dashboard stats (persisted so future stages can update them) ----------
const STORAGE_KEYS = {
  filesProtected: 'threatlens_filesProtected',
  threatsBlocked: 'threatlens_threatsBlocked',
  lastScan: 'threatlens_lastScan',
  activity: 'threatlens_activity',
  userName: 'threatlens_userName',
  protectionOn: 'threatlens_protectionOn',
};

function loadStats() {
  const filesProtected = localStorage.getItem(STORAGE_KEYS.filesProtected) || '0';
  const threatsBlocked = localStorage.getItem(STORAGE_KEYS.threatsBlocked) || '0';
  const lastScan = localStorage.getItem(STORAGE_KEYS.lastScan) || '—';
  const activity = JSON.parse(localStorage.getItem(STORAGE_KEYS.activity) || '[]');

  document.getElementById('filesProtectedValue').textContent = filesProtected;
  document.getElementById('threatsBlockedValue').textContent = threatsBlocked;
  document.getElementById('lastScanValue').textContent = lastScan;
  document.getElementById('notifBadge').textContent = threatsBlocked;

  renderActivity(activity);
}

function renderActivity(activity) {
  const list = document.getElementById('activityList');
  list.innerHTML = '';

  if (!activity.length) {
    list.innerHTML = '<li class="activity-empty">No files scanned yet — try the Scan tab.</li>';
    return;
  }

  activity.slice(0, 6).forEach(entry => {
    const li = document.createElement('li');
    li.innerHTML = `
      <div>
        <div class="activity-name">${entry.name}</div>
        <div class="activity-status ${entry.threat ? 'danger' : 'safe'}">${entry.threat ? 'Suspicious' : 'Safe'}</div>
      </div>
      <div class="activity-time">${entry.time}</div>
    `;
    list.appendChild(li);
  });
}

loadStats();

// ---------- Scan page logic ----------
const dropzone = document.getElementById('dropzone');
const dropzoneContent = document.getElementById('dropzoneContent');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const fileChip = document.getElementById('fileChip');
const fileNameEl = document.getElementById('fileName');
const clearFileBtn = document.getElementById('clearFile');
const scanBtn = document.getElementById('scanBtn');
const scanline = document.getElementById('scanline');
const terminal = document.getElementById('terminal');
const terminalBody = document.getElementById('terminalBody');
const resultCard = document.getElementById('resultCard');
const resultBadge = document.getElementById('resultBadge');
const resultTitle = document.getElementById('resultTitle');
const resultDesc = document.getElementById('resultDesc');

let selectedFile = null;
const RISKY_EXTENSIONS = ['exe', 'scr', 'bat', 'cmd', 'js', 'vbs', 'jar', 'msi'];

browseBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
  if (e.target.files.length) setFile(e.target.files[0]);
});

['dragenter', 'dragover'].forEach(evt =>
  dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add('dragover'); })
);
['dragleave', 'drop'].forEach(evt =>
  dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove('dragover'); })
);
dropzone.addEventListener('drop', (e) => {
  if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
});

function setFile(file) {
  selectedFile = file;
  fileNameEl.textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
  dropzoneContent.hidden = true;
  fileChip.hidden = false;
  scanBtn.disabled = false;
  resultCard.hidden = true;
  terminal.hidden = true;
}

clearFileBtn.addEventListener('click', () => {
  selectedFile = null;
  fileInput.value = '';
  dropzoneContent.hidden = false;
  fileChip.hidden = true;
  scanBtn.disabled = true;
  resultCard.hidden = true;
  terminal.hidden = true;
});

scanBtn.addEventListener('click', runScan);

const BACKEND_URL = 'http://localhost:3000';

function runScan() {
  if (!selectedFile) return;

  scanBtn.disabled = true;
  resultCard.hidden = true;
  terminal.hidden = false;
  terminalBody.innerHTML = '';
  scanline.classList.add('active');
  dropzone.classList.add('scanning');

  logLine(`> uploading ${selectedFile.name} to scan engine...`);

  const formData = new FormData();
  formData.append('file', selectedFile);

  fetch(`${BACKEND_URL}/api/scan`, { method: 'POST', body: formData })
    .then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Scan failed.');
      return data;
    })
    .then((data) => {
      logLine(data.cached ? '> found an existing report for this file' : '> analysis complete');
      logLine(`> ${data.stats.malicious} engines flagged malicious, ${data.stats.suspicious} suspicious, ${data.stats.harmless} clean`);
      finishScan();
      showResult(data);
      recordScan(data.fileName, data.isThreat);
    })
    .catch((err) => {
      logLine(`> ⚠ ${err.message}`);
      logLine('> is the backend server running? See setup instructions.');
      finishScan();
      scanBtn.disabled = false;
    });
}

function logLine(text) {
  const div = document.createElement('div');
  div.textContent = text;
  terminalBody.appendChild(div);
  terminalBody.scrollTop = terminalBody.scrollHeight;
}

function finishScan() {
  scanline.classList.remove('active');
  dropzone.classList.remove('scanning');
  scanBtn.disabled = false;
}

function showResult(data) {
  const isThreat = data.isThreat;
  resultCard.hidden = false;
  resultCard.className = 'result-card ' + (isThreat ? 'danger' : 'safe');
  resultBadge.textContent = isThreat ? 'THREAT DETECTED' : 'CLEAN';
  resultTitle.textContent = isThreat
    ? `${data.fileName} was flagged by ${data.stats.malicious + data.stats.suspicious} engine(s)`
    : `${data.fileName} looks safe`;
  resultDesc.textContent = isThreat
    ? 'Multiple antivirus engines on VirusTotal flagged this file. Avoid opening it and consider deleting it.'
    : `Scanned against ${data.stats.malicious + data.stats.suspicious + data.stats.harmless + data.stats.undetected} antivirus engines with no malicious detections.`;

  const link = document.getElementById('resultLink');
  link.href = data.permalink;
  link.hidden = false;
}

// Persist scan result into localStorage so the Dashboard reflects it
function recordScan(name, isThreat) {
  const filesProtected = parseInt(localStorage.getItem(STORAGE_KEYS.filesProtected) || '0', 10) + 1;
  const threatsBlocked = parseInt(localStorage.getItem(STORAGE_KEYS.threatsBlocked) || '0', 10) + (isThreat ? 1 : 0);
  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const activity = JSON.parse(localStorage.getItem(STORAGE_KEYS.activity) || '[]');
  activity.unshift({ name, threat: isThreat, time });

  localStorage.setItem(STORAGE_KEYS.filesProtected, filesProtected);
  localStorage.setItem(STORAGE_KEYS.threatsBlocked, threatsBlocked);
  localStorage.setItem(STORAGE_KEYS.lastScan, `Today, ${time}`);
  localStorage.setItem(STORAGE_KEYS.activity, JSON.stringify(activity.slice(0, 20)));

  loadStats();
}

// ---------- AI Coach (rule-based chatbot) ----------
const KNOWLEDGE_BASE = [
  {
    keywords: ['cia', 'confidentiality', 'integrity', 'availability', 'triad'],
    title: 'The CIA Triad',
    answer: 'The CIA triad is the foundation of cybersecurity — three goals every system tries to protect:',
    list: [
      'Confidentiality: only authorized people can see the data (e.g. encryption, passwords).',
      'Integrity: data stays accurate and unaltered (e.g. checksums, version control).',
      'Availability: systems and data stay accessible when needed (e.g. backups, redundancy).'
    ]
  },
  {
    keywords: ['phishing'],
    title: 'Phishing',
    answer: 'Phishing is when an attacker pretends to be a trusted source (a bank, a coworker, a well-known company) to trick you into giving up information or clicking a malicious link.',
    list: [
      'Check the sender\'s actual email address, not just the display name.',
      'Hover over links before clicking to see the real destination.',
      'Be suspicious of urgent language like "act now" or "your account will be closed."'
    ]
  },
  {
    keywords: ['ransomware'],
    title: 'Ransomware',
    answer: 'Ransomware is malware that encrypts your files and demands payment to unlock them. It usually spreads through infected attachments, malicious downloads, or compromised websites.',
    list: [
      'Keep offline or cloud backups so you never have to pay to recover.',
      'Don\'t open unexpected attachments, even from known contacts.',
      'Keep your OS and antivirus software updated.'
    ]
  },
  {
    keywords: ['password', 'passwords', 'steal password'],
    title: 'Password Security',
    answer: 'Hackers steal passwords through phishing, data breaches, guessing weak passwords, or reusing leaked credentials across sites.',
    list: [
      'Use a unique password for every account.',
      'Aim for length over complexity — a long passphrase beats a short complex one.',
      'Use a password manager so you don\'t have to remember them all.',
      'Turn on two-factor authentication wherever it\'s offered.'
    ]
  },
  {
    keywords: ['trojan'],
    title: 'Trojan',
    answer: 'A Trojan is malware disguised as a legitimate program. Once you run it, it can secretly steal data, spy on you, or open a backdoor for further attacks.',
    list: [
      'Only download software from official sources.',
      'Be cautious with cracked software or pirated installers — a common Trojan delivery method.'
    ]
  },
  {
    keywords: ['two-factor', '2fa', 'mfa', 'multi-factor', 'authentication'],
    title: 'Two-Factor Authentication (2FA)',
    answer: 'Two-factor authentication adds a second proof of identity beyond your password — usually a code from your phone, an app, or a hardware key.',
    list: [
      'Even if your password leaks, 2FA can stop an attacker from logging in.',
      'Prefer an authenticator app or hardware key over SMS codes when available.'
    ]
  },
  {
    keywords: ['social engineering'],
    title: 'Social Engineering',
    answer: 'Social engineering is manipulating people, not systems, into giving up information or access — through impersonation, urgency, or building false trust.',
    list: [
      'Verify identity through a separate channel before acting on unusual requests.',
      'Be wary of anyone creating pressure to act immediately.'
    ]
  },
  {
    keywords: ['malware'],
    title: 'Malware',
    answer: 'Malware is any software designed to damage, disrupt, or gain unauthorized access to a system — this includes viruses, worms, Trojans, ransomware, and spyware.',
    list: []
  },
  {
    keywords: ['firewall'],
    title: 'Firewalls',
    answer: 'A firewall monitors incoming and outgoing network traffic and blocks anything that doesn\'t match your security rules — it\'s a core layer of endpoint protection.',
    list: []
  },
  {
    keywords: ['backup', 'backups'],
    title: 'Backups',
    answer: 'Backups are copies of your data stored separately so you can recover if your system is compromised, lost, or hit by ransomware.',
    list: [
      'Follow the 3-2-1 rule: 3 copies, on 2 different media, with 1 stored offsite or offline.'
    ]
  },
  {
    keywords: ['wifi', 'wi-fi', 'public network'],
    title: 'Public WiFi Safety',
    answer: 'Public WiFi networks are often unencrypted, meaning others on the same network could potentially intercept your traffic.',
    list: [
      'Avoid logging into banking or sensitive accounts on public WiFi.',
      'Use a VPN if you must use public networks for sensitive tasks.',
      'Turn off auto-connect to open networks on your devices.'
    ]
  },
  {
    keywords: ['banking', 'bank account', 'financial'],
    title: 'Online Banking Safety',
    answer: 'Banking accounts are high-value targets, so they deserve extra layers of protection beyond a normal password.',
    list: [
      'Always enable two-factor authentication for financial accounts.',
      'Only access your bank through the official app or typed URL, never a link in an email.',
      'Set up transaction alerts so you notice unauthorized activity fast.'
    ]
  },
];

function matchAnswer(question) {
  const q = question.toLowerCase();
  for (const entry of KNOWLEDGE_BASE) {
    if (entry.keywords.some(k => q.includes(k))) return entry;
  }
  return {
    title: "I'm not sure about that one",
    answer: "I don't have an answer for that yet. Try asking about phishing, ransomware, passwords, the CIA triad, Trojans, 2FA, social engineering, malware, firewalls, or backups.",
    list: []
  };
}

const chatMessages = document.getElementById('chatMessages');
const chatForm = document.getElementById('chatForm');
const chatInput = document.getElementById('chatInput');

function addBubble(text, sender, title, list) {
  const bubble = document.createElement('div');
  bubble.className = `chat-bubble ${sender}`;
  let html = title ? `<strong>${title}</strong>${text}` : text;
  if (list && list.length) {
    html += '<ul>' + list.map(i => `<li>${i}</li>`).join('') + '</ul>';
  }
  bubble.innerHTML = html;
  chatMessages.appendChild(bubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;
  return bubble;
}

let chatHistory = [];

function askCoach(question) {
  addBubble(question, 'user');
  chatHistory.push({ role: 'user', content: question });

  const typingBubble = addBubble('Thinking...', 'bot');
  typingBubble.classList.add('typing');

  fetch(`${BACKEND_URL}/api/coach`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages: chatHistory }),
  })
    .then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'AI Coach request failed.');
      return data;
    })
    .then((data) => {
      typingBubble.remove();
      addBubble(data.reply, 'bot');
      chatHistory.push({ role: 'assistant', content: data.reply });
    })
    .catch(() => {
      // Fallback: answer from the local rule-based knowledge base so the coach still works offline
      typingBubble.remove();
      const entry = matchAnswer(question);
      addBubble(entry.answer, 'bot', `${entry.title} (offline mode)`, entry.list);
      chatHistory.pop(); // don't keep the failed turn in AI conversation context
    });
}

chatForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const value = chatInput.value.trim();
  if (!value) return;
  askCoach(value);
  chatInput.value = '';
});

document.querySelectorAll('.suggestion-btn').forEach(btn => {
  btn.addEventListener('click', () => askCoach(btn.dataset.q));
});

// Greeting message on load
addBubble(
  "Ask me anything about cybersecurity awareness — phishing, passwords, ransomware, the CIA triad, and more. I'm here to help you stay safe.",
  'bot',
  "Hi, I'm your ThreatLens AI Coach"
);

// ---------- Cyber Awareness page ----------
const TIPS = [
  { title: 'Never plug unknown USB drives into your computer.', desc: "It's one of the easiest ways malware spreads onto a system." },
  { title: 'Lock your screen when you step away.', desc: 'Protects confidentiality even in shared or public spaces.' },
  { title: 'Verify before you trust an urgent request.', desc: 'Social engineering relies on rushing you past your own judgment.' },
  { title: 'Keep a backup that lives offline.', desc: 'Protects availability of your data even if ransomware hits.' },
];

let tipIndex = 0;
const tipTitle = document.getElementById('tipTitle');
const tipDesc = document.getElementById('tipDesc');
const tipDots = document.getElementById('tipDots');

function renderTip() {
  tipTitle.textContent = TIPS[tipIndex].title;
  tipDesc.textContent = TIPS[tipIndex].desc;
  tipDots.innerHTML = TIPS.map((_, i) =>
    `<span class="${i === tipIndex ? 'active' : ''}" data-i="${i}"></span>`
  ).join('');
  tipDots.querySelectorAll('span').forEach(dot => {
    dot.addEventListener('click', () => { tipIndex = parseInt(dot.dataset.i, 10); renderTip(); });
  });
}
renderTip();
setInterval(() => { tipIndex = (tipIndex + 1) % TIPS.length; renderTip(); }, 6000);

const LESSONS = [
  { icon: '🔑', color: 'green', title: 'Password Security', desc: 'Build passwords that hold up.', question: 'Create strong passwords' },
  { icon: '🎭', color: 'blue', title: 'Social Engineering', desc: 'Spot manipulation tactics.', question: 'What is social engineering?' },
  { icon: '🔒', color: 'danger', title: 'Ransomware', desc: 'Know how it spreads and hits.', question: 'How do ransomware attacks work?' },
  { icon: '📶', color: 'yellow', title: 'WiFi Safety', desc: 'Stay safe on public networks.', question: 'How can I stay safe on public wifi?' },
  { icon: '🏦', color: 'purple', title: 'Online Banking', desc: 'Protect your financial accounts.', question: 'How do I keep my online banking safe?' },
  { icon: '🛡', color: 'blue', title: 'Data Privacy', desc: 'Understand the CIA triad.', question: 'What is the CIA triad?' },
];

const lessonGrid = document.getElementById('lessonGrid');
LESSONS.forEach(lesson => {
  const card = document.createElement('button');
  card.className = 'lesson-card';
  card.innerHTML = `
    <div class="lesson-icon quick-icon ${lesson.color}">${lesson.icon}</div>
    <h4>${lesson.title}</h4>
    <p>${lesson.desc}</p>
  `;
  card.addEventListener('click', () => {
    goToPage('coach');
    askCoach(lesson.question);
  });
  lessonGrid.appendChild(card);
});

// ---------- Threat Encyclopedia page (reuses the chatbot's knowledge base) ----------
const encyclopediaGrid = document.getElementById('encyclopediaGrid');
const encyclopediaSearch = document.getElementById('encyclopediaSearch');

function renderEncyclopedia(filter = '') {
  encyclopediaGrid.innerHTML = '';
  const q = filter.toLowerCase();
  const matches = KNOWLEDGE_BASE.filter(entry =>
    entry.title.toLowerCase().includes(q) ||
    entry.answer.toLowerCase().includes(q) ||
    entry.keywords.some(k => k.includes(q))
  );

  if (!matches.length) {
    encyclopediaGrid.innerHTML = '<p class="entry-empty">No matching topics. Try a different search term.</p>';
    return;
  }

  matches.forEach(entry => {
    const card = document.createElement('div');
    card.className = 'entry-card';
    card.innerHTML = `
      <h4>${entry.title}</h4>
      <p>${entry.answer}</p>
      ${entry.list.length ? '<ul>' + entry.list.map(i => `<li>${i}</li>`).join('') + '</ul>' : ''}
    `;
    encyclopediaGrid.appendChild(card);
  });
}

renderEncyclopedia();
encyclopediaSearch.addEventListener('input', (e) => renderEncyclopedia(e.target.value));

// ---------- Reports page ----------
function renderReports() {
  const activity = JSON.parse(localStorage.getItem(STORAGE_KEYS.activity) || '[]');
  const total = activity.length;
  const threats = activity.filter(a => a.threat).length;
  const clean = total - threats;

  document.getElementById('reportsTotalScans').textContent = total;
  document.getElementById('reportsCleanCount').textContent = clean;
  document.getElementById('reportsThreatCount').textContent = threats;

  const tbody = document.getElementById('reportsTableBody');
  tbody.innerHTML = '';

  if (!total) {
    tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-dim); text-align:center; padding:24px;">No scans yet — visit the Scan tab to get started.</td></tr>';
    return;
  }

  activity.forEach(entry => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${entry.name}</td>
      <td><span class="result-tag ${entry.threat ? 'danger' : 'safe'}">${entry.threat ? 'Threat' : 'Clean'}</span></td>
      <td>${entry.time}</td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById('clearHistoryBtn').addEventListener('click', () => {
  if (!confirm('Clear all scan history and reset stats? This cannot be undone.')) return;
  localStorage.removeItem(STORAGE_KEYS.filesProtected);
  localStorage.removeItem(STORAGE_KEYS.threatsBlocked);
  localStorage.removeItem(STORAGE_KEYS.lastScan);
  localStorage.removeItem(STORAGE_KEYS.activity);
  loadStats();
  renderReports();
});

// ---------- Settings page & profile ----------
function loadProfile() {
  const name = localStorage.getItem(STORAGE_KEYS.userName) || 'User';
  const protectionOn = localStorage.getItem(STORAGE_KEYS.protectionOn) !== 'false';

  document.getElementById('greetingName').textContent = `${name} 👋`;
  document.getElementById('avatarInitial').textContent = name.charAt(0).toUpperCase();
  document.getElementById('nameInput').value = name === 'User' ? '' : name;

  document.getElementById('protectionToggle').checked = protectionOn;
  document.querySelector('.protection-chip .chip-status').textContent = protectionOn ? 'ON' : 'OFF';
  document.querySelector('.protection-chip .dot').style.background = protectionOn ? 'var(--safe)' : 'var(--danger)';
}

document.getElementById('saveNameBtn').addEventListener('click', () => {
  const value = document.getElementById('nameInput').value.trim();
  localStorage.setItem(STORAGE_KEYS.userName, value || 'User');
  loadProfile();
});

document.getElementById('protectionToggle').addEventListener('change', (e) => {
  localStorage.setItem(STORAGE_KEYS.protectionOn, e.target.checked);
  loadProfile();
});

document.getElementById('resetAppBtn').addEventListener('click', () => {
  if (!confirm('This will erase all scan history, stats, and your profile name. Continue?')) return;
  Object.values(STORAGE_KEYS).forEach(key => localStorage.removeItem(key));
  loadStats();
  loadProfile();
  if (typeof renderReports === 'function') renderReports();
});

loadProfile();
