/**
 * ============================================================
 *  CONFIG.JS — LendingTree Contract Portal v3.0.0
 * ============================================================
 *  Zero-footprint configuration.
 *  No navigation targets, no page references, no route maps.
 *  Backend pushes all layout content dynamically.
 * ============================================================
 */

const APP_CONFIG = {

  // ----------------------------------------------------------
  //  SUPABASE
  // ----------------------------------------------------------
  SUPABASE_URL:      'https://drjddwwllaxwuwfqpujg.supabase.co',   // e.g. https://xxxx.supabase.co
  SUPABASE_ANON_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRyamRkd3dsbGF4d3V3ZnFwdWpnIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MjI2ODkzNywiZXhwIjoyMDg3ODQ0OTM3fQ.ZUEIFsEMID0JJbH6TXq1E5CokzAnA-yuFbYjHFuOepQ',   // Safe to expose — guarded by RLS

  // ----------------------------------------------------------
  //  BACKEND (Render)
  // ----------------------------------------------------------
  BACKEND_URL:    'https://backend-sanitization-ltr33-1.onrender.com',      // e.g. https://your-app.onrender.com  (no trailing slash)
  BACKEND_WS_URL: 'wss://backend-sanitization-ltr33-1.onrender.com',     // e.g. wss://your-app.onrender.com

  // ----------------------------------------------------------
  //  CONNECTION RESILIENCE
  //  Priority: WebSocket → Supabase Realtime → SSE Long-Poll
  //  All three channels run simultaneously where possible.
  // ----------------------------------------------------------
  CHANNELS: {
    WEBSOCKET:         true,
    SUPABASE_REALTIME: true,
    SSE_POLLING:       true,
  },

  // ----------------------------------------------------------
  //  TIMING (ms)
  // ----------------------------------------------------------
  TIMING: {
    HEARTBEAT_INTERVAL:    20000,   // 20s  — ping interval
    WS_RECONNECT_BASE:      1000,   // 1s   — base reconnect delay
    WS_RECONNECT_MAX:      30000,   // 30s  — max reconnect delay
    SSE_POLL_TIMEOUT:      30000,   // 30s  — SSE long-poll timeout
    SSE_RETRY_DELAY:        5000,   // 5s   — SSE reconnect delay
    IDLE_TIMEOUT:        3540000,   // 59m  — session idle cutoff
    CRYPTO_KEY_ROTATION: 1800000,   // 30m  — re-key interval
    FRAGMENT_ACK_TIMEOUT:  10000,   // 10s  — fragment delivery ACK window
  },

  // ----------------------------------------------------------
  //  CRYPTO
  // ----------------------------------------------------------
  CRYPTO: {
    ALGORITHM:   'AES-GCM',
    KEY_LENGTH:  256,
    IV_LENGTH:   12,           // bytes
    TAG_LENGTH:  128,          // bits
    HMAC_ALGO:   'SHA-256',
  },

  // ----------------------------------------------------------
  //  APP META
  // ----------------------------------------------------------
  APP_NAME:    'LendingTree Contract Portal',
  APP_VERSION: '3.0.0',
  ENV:         'development',   // 'development' | 'production'
};

// Freeze — no runtime mutation
Object.freeze(APP_CONFIG);
Object.freeze(APP_CONFIG.CHANNELS);
Object.freeze(APP_CONFIG.TIMING);
Object.freeze(APP_CONFIG.CRYPTO);
