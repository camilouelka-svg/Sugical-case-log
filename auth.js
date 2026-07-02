/*
  Shared multi-account gate + client-side encryption for the surgical case log
  suite. Each surgeon creates their own account (name + password) on this
  browser. A surgeon's password is never stored — it's run through PBKDF2 to
  derive an AES-GCM key unique to them, which encrypts *their own* case data
  in localStorage under a key namespaced to their account. Other accounts on
  the same browser cannot decrypt each other's data (different derived key,
  separate storage slot).

  There is no server, so this only protects against casual/local access:
  anyone who knows an account's password (or is using this unlocked browser
  profile before that user logs out) can read that account's data. There is
  also no password recovery — forgetting a password means that account's
  encrypted case data cannot be decrypted again; only a full reset (which
  erases that account's data) is possible.
*/
(function () {
  const ACCOUNTS_KEY = 'caseLogAccounts';
  const LEGACY_ACCOUNT_KEY = 'caseLogAccount';
  const SESSION_KEY_B64 = 'caseLogSessionKeyB64';
  const SESSION_NAME = 'caseLogSessionName';
  const PBKDF2_ITERATIONS = 150000;
  const DATA_KEY_BASES = ['cardiacCases_enc', 'thoracicCases_enc', 'vascularCases_enc'];

  function bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function b64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }
  function normalizeName(name) {
    return (name || '').trim().toLowerCase();
  }

  function getAccounts() {
    try {
      return JSON.parse(localStorage.getItem(ACCOUNTS_KEY) || '{}');
    } catch (e) {
      return {};
    }
  }
  function saveAccounts(accounts) {
    localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts));
  }
  function findAccount(name) {
    const accounts = getAccounts();
    const key = normalizeName(name);
    return accounts[key] ? { key, record: accounts[key] } : null;
  }

  async function deriveKey(password, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptString(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return { ivB64: bufToB64(iv), ctB64: bufToB64(ct) };
  }

  async function decryptString(key, ivB64, ctB64) {
    const iv = new Uint8Array(b64ToBuf(ivB64));
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, b64ToBuf(ctB64));
    return new TextDecoder().decode(ptBuf);
  }

  async function encryptJSON(key, obj) {
    const { ivB64, ctB64 } = await encryptString(key, JSON.stringify(obj));
    return ivB64 + '.' + ctB64;
  }

  async function decryptJSON(key, str) {
    if (!str) return null;
    const parts = str.split('.');
    if (parts.length !== 2) return null;
    try {
      return JSON.parse(await decryptString(key, parts[0], parts[1]));
    } catch (e) {
      return null;
    }
  }

  function dataKey(base, accountKey) {
    return `${base}::${accountKey}`;
  }

  async function verifyPassword(record, password) {
    const salt = new Uint8Array(b64ToBuf(record.saltB64));
    const key = await deriveKey(password, salt);
    try {
      const check = await decryptString(key, record.verifierIvB64, record.verifierCtB64);
      if (check !== 'CASELOG_OK') return null;
      return key;
    } catch (e) {
      return null;
    }
  }

  // One-time migration from the old single-shared-account version of this
  // app: if a legacy account exists with this same name/password, reuse its
  // salt (so its already-encrypted data stays decryptable) and move its data
  // into this account's namespaced storage slots.
  async function migrateLegacyIfMatch(name, password, accountKey) {
    let legacy;
    try {
      legacy = JSON.parse(localStorage.getItem(LEGACY_ACCOUNT_KEY) || 'null');
    } catch (e) {
      legacy = null;
    }
    if (!legacy || normalizeName(legacy.name) !== normalizeName(name)) return null;
    const key = await verifyPassword(legacy, password);
    if (!key) return null;

    DATA_KEY_BASES.forEach(base => {
      const legacyBlob = localStorage.getItem(base);
      if (legacyBlob) {
        localStorage.setItem(dataKey(base, accountKey), legacyBlob);
        localStorage.removeItem(base);
      }
    });
    localStorage.removeItem(LEGACY_ACCOUNT_KEY);
    localStorage.removeItem('caseLogSessionKeyB64');

    return { saltB64: legacy.saltB64, verifierIvB64: legacy.verifierIvB64, verifierCtB64: legacy.verifierCtB64, key };
  }

  async function createAccount(name, password) {
    const accountKey = normalizeName(name);
    const migrated = await migrateLegacyIfMatch(name, password, accountKey);

    let salt, key, verifier;
    if (migrated) {
      key = migrated.key;
      const accounts = getAccounts();
      accounts[accountKey] = {
        name: name.trim(),
        saltB64: migrated.saltB64,
        verifierIvB64: migrated.verifierIvB64,
        verifierCtB64: migrated.verifierCtB64,
      };
      saveAccounts(accounts);
    } else {
      salt = crypto.getRandomValues(new Uint8Array(16));
      key = await deriveKey(password, salt);
      verifier = await encryptString(key, 'CASELOG_OK');
      const accounts = getAccounts();
      accounts[accountKey] = {
        name: name.trim(),
        saltB64: bufToB64(salt),
        verifierIvB64: verifier.ivB64,
        verifierCtB64: verifier.ctB64,
      };
      saveAccounts(accounts);
    }
    await persistSession(accountKey, name.trim(), key);
    return key;
  }

  async function login(name, password) {
    const found = findAccount(name);
    if (!found) throw new Error('Incorrect account name or password.');
    const key = await verifyPassword(found.record, password);
    if (!key) throw new Error('Incorrect account name or password.');
    await persistSession(found.key, found.record.name, key);
    return key;
  }

  async function persistSession(accountKey, displayName, key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    localStorage.setItem(SESSION_KEY_B64, bufToB64(raw));
    localStorage.setItem(SESSION_NAME, JSON.stringify({ accountKey, displayName }));
  }

  async function restoreSession() {
    const b64 = localStorage.getItem(SESSION_KEY_B64);
    const nameJson = localStorage.getItem(SESSION_NAME);
    if (!b64 || !nameJson) return null;
    try {
      const key = await crypto.subtle.importKey('raw', b64ToBuf(b64), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const { accountKey, displayName } = JSON.parse(nameJson);
      return { key, accountKey, displayName };
    } catch (e) {
      return null;
    }
  }

  function logout() {
    localStorage.removeItem(SESSION_KEY_B64);
    localStorage.removeItem(SESSION_NAME);
    location.reload();
  }

  function resetAccount(name) {
    const found = findAccount(name);
    if (!found) return;
    const accounts = getAccounts();
    delete accounts[found.key];
    saveAccounts(accounts);
    DATA_KEY_BASES.forEach(base => localStorage.removeItem(dataKey(base, found.key)));
    localStorage.removeItem(SESSION_KEY_B64);
    localStorage.removeItem(SESSION_NAME);
    location.reload();
  }

  function injectBaseStyles() {
    const style = document.createElement('style');
    style.textContent = `
      body.cla-locked > .wrap { display: none !important; }
      .cla-gate {
        position: fixed; inset: 0; z-index: 1000;
        display: flex; align-items: center; justify-content: center;
        background: var(--bg, #f5f5f7);
        padding: 24px;
      }
      .cla-gate-card {
        background: var(--card, #fff);
        border: 1px solid var(--border, #e5e5ea);
        border-radius: 16px;
        padding: 32px;
        width: 340px;
        max-width: 100%;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
      }
      .cla-gate-card h2 {
        margin: 0 0 4px;
        font-size: 18px;
        text-align: center;
        color: var(--text, #1d1d1f);
      }
      .cla-gate-sub {
        text-align: center;
        font-size: 12px;
        color: var(--muted, #86868b);
        margin-bottom: 20px;
      }
      .cla-gate-card label {
        display: block;
        font-size: 12px;
        font-weight: 600;
        color: var(--muted, #86868b);
        margin-bottom: 4px;
      }
      .cla-gate-card input {
        width: 100%;
        padding: 9px 10px;
        border: 1px solid var(--border, #e5e5ea);
        border-radius: 8px;
        font-size: 14px;
        margin-bottom: 14px;
        box-sizing: border-box;
        font-family: inherit;
        background: transparent;
        color: var(--text, #1d1d1f);
      }
      .cla-gate-card input:focus {
        outline: none;
        border-color: var(--accent, #333);
      }
      .cla-mode-hint {
        font-size: 11px;
        color: var(--muted, #86868b);
        margin: -10px 0 14px;
      }
      .cla-gate-card button {
        width: 100%;
        background: var(--accent, #333);
        color: #fff;
        border: none;
        border-radius: 8px;
        padding: 11px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
      }
      .cla-gate-error {
        color: #b3261e;
        font-size: 12px;
        margin: -6px 0 12px;
        min-height: 14px;
      }
      .cla-gate-reset {
        text-align: center;
        margin-top: 14px;
        font-size: 12px;
        color: var(--muted, #86868b);
      }
      .cla-gate-reset a {
        color: var(--accent, #333);
        text-decoration: none;
        font-weight: 600;
        cursor: pointer;
      }
      .cla-badge {
        position: fixed;
        top: 14px;
        right: 16px;
        z-index: 900;
        display: flex;
        align-items: center;
        gap: 8px;
        background: var(--card, #fff);
        border: 1px solid var(--border, #e5e5ea);
        border-radius: 999px;
        padding: 6px 12px;
        font-size: 12px;
        color: var(--muted, #86868b);
        box-shadow: 0 4px 14px rgba(0,0,0,0.06);
      }
      .cla-badge button {
        background: none;
        border: none;
        color: var(--accent, #333);
        font-weight: 700;
        font-size: 12px;
        cursor: pointer;
        padding: 0;
      }
    `;
    document.head.appendChild(style);
  }

  function renderAccountBadge(displayName) {
    const existing = document.querySelector('.cla-badge');
    if (existing) existing.remove();
    const badge = document.createElement('div');
    badge.className = 'cla-badge';
    badge.innerHTML = `<span>Logged in as <strong>${displayName || ''}</strong></span><button type="button">Switch / Log out</button>`;
    badge.querySelector('button').addEventListener('click', logout);
    document.body.appendChild(badge);
  }

  function renderGate(onUnlocked) {
    document.body.classList.add('cla-locked');
    const overlay = document.createElement('div');
    overlay.className = 'cla-gate';
    document.body.appendChild(overlay);

    overlay.innerHTML = `
      <div class="cla-gate-card">
        <h2 id="claHeading">Sign In</h2>
        <div class="cla-gate-sub">Each surgeon has their own account and their own private logbook on this device.</div>
        <form id="claForm">
          <label for="claName">Account Name</label>
          <input type="text" id="claName" autocomplete="username" required>
          <div class="cla-mode-hint" id="claModeHint">Enter your account name to continue.</div>
          <label for="claPassword">Password</label>
          <input type="password" id="claPassword" autocomplete="current-password" required>
          <div id="claConfirmWrap" style="display:none;">
            <label for="claPassword2">Confirm Password</label>
            <input type="password" id="claPassword2" autocomplete="new-password">
          </div>
          <div class="cla-gate-error" id="claError"></div>
          <button type="submit" id="claSubmitBtn">Continue</button>
        </form>
        <div class="cla-gate-reset" id="claResetWrap" style="display:none;">
          <a id="claReset">Forgot password? Reset this account &amp; erase its data</a>
        </div>
      </div>
    `;

    const nameInput = overlay.querySelector('#claName');
    const confirmWrap = overlay.querySelector('#claConfirmWrap');
    const password2 = overlay.querySelector('#claPassword2');
    const heading = overlay.querySelector('#claHeading');
    const hint = overlay.querySelector('#claModeHint');
    const submitBtn = overlay.querySelector('#claSubmitBtn');
    const errorEl = overlay.querySelector('#claError');
    const resetWrap = overlay.querySelector('#claResetWrap');

    function currentMode() {
      const name = nameInput.value.trim();
      if (!name) return null;
      return findAccount(name) ? 'login' : 'create';
    }

    function updateMode() {
      const mode = currentMode();
      if (mode === 'login') {
        heading.textContent = 'Log In';
        hint.textContent = 'Existing account — enter your password.';
        confirmWrap.style.display = 'none';
        submitBtn.textContent = 'Log In';
        resetWrap.style.display = '';
      } else if (mode === 'create') {
        heading.textContent = 'Create Account';
        hint.textContent = 'New account — choose a password (min. 4 characters).';
        confirmWrap.style.display = '';
        submitBtn.textContent = 'Create Account';
        resetWrap.style.display = 'none';
      } else {
        heading.textContent = 'Sign In';
        hint.textContent = 'Enter your account name to continue.';
        confirmWrap.style.display = 'none';
        submitBtn.textContent = 'Continue';
        resetWrap.style.display = 'none';
      }
    }

    nameInput.addEventListener('input', updateMode);

    overlay.querySelector('#claForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = nameInput.value.trim();
      const password = overlay.querySelector('#claPassword').value;
      const mode = currentMode();
      errorEl.textContent = '';

      if (mode === 'create') {
        if (password.length < 4) {
          errorEl.textContent = 'Password must be at least 4 characters.';
          return;
        }
        if (password !== password2.value) {
          errorEl.textContent = 'Passwords do not match.';
          return;
        }
        await createAccount(name, password);
      } else if (mode === 'login') {
        try {
          await login(name, password);
        } catch (err) {
          errorEl.textContent = err.message;
          return;
        }
      } else {
        errorEl.textContent = 'Enter an account name.';
        return;
      }

      overlay.remove();
      document.body.classList.remove('cla-locked');
      onUnlocked();
    });

    overlay.querySelector('#claReset').addEventListener('click', () => {
      const name = nameInput.value.trim();
      if (!name) return;
      if (confirm(`This will permanently erase the account "${name}" and all of its case data on this device. Continue?`)) {
        resetAccount(name);
      }
    });
  }

  async function protect(onReady) {
    injectBaseStyles();
    const session = await restoreSession();
    if (session) {
      await onReady(session.key, session.displayName, session.accountKey);
      renderAccountBadge(session.displayName);
      return;
    }
    document.body.classList.add('cla-locked');
    renderGate(async () => {
      const restored = await restoreSession();
      await onReady(restored.key, restored.displayName, restored.accountKey);
      renderAccountBadge(restored.displayName);
    });
  }

  window.CaseLogAuth = {
    protect,
    encryptJSON,
    decryptJSON,
    logout,
  };
})();
