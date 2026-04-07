# SoSoValue Anti-Bot Detection System — Complete Analysis

> **Source**: `_app-47e90b3e747cef97.js`, Module `67404` (5,585 bytes)
> **Framework**: Custom behavioral collector class + Cloudflare Turnstile
> **Analysis Date**: 2026-04-07

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    SoSoValue Anti-Bot Stack                      │
├─────────────────┬───────────────────┬───────────────────────────┤
│  Layer 1        │  Layer 2          │  Layer 3                  │
│  Cloudflare     │  Behavioral       │  Server-Side              │
│  Turnstile      │  Collector        │  Validation               │
│  (CAPTCHA)      │  (Module 67404)   │  (Rate Limits + Checks)   │
├─────────────────┼───────────────────┼───────────────────────────┤
│ • Widget render │ • Mouse tracking  │ • Daily quiz limit (40355)│
│ • Token verify  │ • Click isTrusted │ • Deposit/Vault real check│
│ • Pre-clearance │ • Canvas FP       │ • Session validation      │
│ • cf_clearance  │ • Debugger trap   │ • JWT expiry check        │
│   cookie        │ • Webdriver detect│ • IP/account rate limit   │
│                 │ • Keyboard log    │                           │
│                 │ • Teleport detect │                           │
│                 │ • Touch tracking  │                           │
│                 │ • Env snapshot    │                           │
└─────────────────┴───────────────────┴───────────────────────────┘
```

---

## Layer 1: Cloudflare Turnstile

### Configuration
```javascript
sitekey: "0x4AAAAAAA4PZrjDa5PcluqN"
container: "#cf-turnstile-widget"
script: "https://challenges.cloudflare.com/turnstile/v0/api.js"
```

### Flow
1. Turnstile widget di-render di halaman (invisible challenge)
2. Token dikirim ke `/api/siteverify` via POST
3. Server memverifikasi token dengan Cloudflare
4. Jika valid → user mendapat `cf_clearance` cookie
5. Cookie ini **expire setelah ~30 menit**

### Verification Endpoint
```javascript
fetch("/api/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/json;charset=UTF-8" },
    body: JSON.stringify({ "cf-turnstile-response": token })
})
```

### Bypass Status
- **cf_clearance cookie** bisa di-reuse selama masih valid
- Tidak blocking untuk API calls langsung jika sudah punya valid JWT
- Turnstile hanya trigger pada **page load**, bukan per API call

---

## Layer 2: Behavioral Collector (Module 67404)

### Class Structure
Module mengexport 3 fungsi:
| Export | Internal | Function |
|--------|----------|----------|
| `pf()` | `i()` | **Init** — create singleton instance, start all listeners |
| `iW()` | `s()` | **Get Payload** — return collected behavioral data |
| `iJ()` | `a()` | **Destroy** — remove listeners, clear data |

### Constructor & Config
```javascript
new BehavioralCollector({
    checkIsTrusted: true,    // Check event.isTrusted on all interactions
    checkTeleport: true,     // Detect mouse teleportation
    checkConsole: true,      // Monitor DevTools open state
    checkDebugger: true,     // Run debugger trap interval
    sampleRate: 50           // Mouse movement sample rate (ms)
})
```

### Initialization (`init()`)
Saat dipanggil, 3 hal terjadi berurutan:
1. `collectFingerprint()` — Canvas + device fingerprint
2. `setupListeners()` — Event listeners di document
3. `startDebuggerTrap()` — Anti-debug interval (jika `checkDebugger: true`)

---

### 2.1 Canvas Fingerprint (`collectFingerprint`)

```javascript
collectFingerprint() {
    let canvas = document.createElement("canvas");
    canvas.getContext("2d").fillText("Safety_Check", 10, 10);
    
    this.payload.f = {
        cvs: canvas.toDataURL().slice(-20),  // Last 20 chars of base64
        sw: window.screen.width,              // Screen width
        sh: window.screen.height,             // Screen height
        ua: navigator.userAgent,              // User agent string
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,  // Timezone (e.g. "Asia/Jakarta")
        mobile: this._isMobile                // Boolean
    };
}
```

**Apa yang dicollect:**
| Field | Data | Contoh |
|-------|------|--------|
| `cvs` | Canvas fingerprint (last 20 chars dari base64 toDataURL) | `"AAAA/wD/AP8A/wA="` |
| `sw` | Screen width | `1920` |
| `sh` | Screen height | `1080` |
| `ua` | Full User-Agent string | `"Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."` |
| `tz` | IANA timezone | `"Asia/Jakarta"` |
| `mobile` | Is mobile device | `false` |

**Canvas Fingerprint Logic:**
- Membuat hidden canvas element
- Menulis text "Safety_Check" di posisi (10, 10)
- Convert ke data URL (base64 PNG)
- Ambil **20 karakter terakhir** sebagai hash
- Ini unik per browser/GPU karena rendering differences

**Cara bypass:**
- Canvas fingerprint consistent per browser profile
- Jika pakai GenLogin/anti-detect browser, setiap profile punya fingerprint berbeda
- Tidak perlu di-spoof jika session consistency terjaga

---

### 2.2 Mobile Detection (`isMobile`)

```javascript
isMobile() {
    if ("undefined" == typeof navigator) return false;
    
    let hasTouch = "ontouchstart" in window || 
                   navigator.maxTouchPoints && navigator.maxTouchPoints > 0;
    
    let hasMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|mobile/i
                      .test(navigator.userAgent || "");
    
    // Both touch AND mobile UA → definitely mobile
    if (hasTouch && hasMobileUA) return true;
    
    // Touch only → check screen width or ontouchstart
    return hasTouch && (window.screen.width <= 768 || "ontouchstart" in window);
}
```

**Detection criteria:**
1. Touch support (`ontouchstart` atau `maxTouchPoints > 0`)
2. Mobile User-Agent regex match
3. Screen width ≤ 768px
4. Gabungan — butuh touch + salah satu (mobile UA atau small screen)

**Kenapa penting:**
- Menentukan apakah system track **mouse events** atau **touch events**
- Mobile path track: `touchstart`, `touchmove`, `touchend`
- Desktop path track: `mousemove`, `mousedown`, `click`

---

### 2.3 Mouse Movement Tracking (`_pushMove`)

```javascript
_pushMove(x, y, timestamp) {
    let last = this._lastMove || { x: 0, y: 0, t: 0 };
    
    if (timestamp - last.t > this.config.sampleRate) {  // 50ms throttle
        let distance = Math.sqrt(
            Math.pow(x - last.x, 2) + Math.pow(y - last.y, 2)
        );
        
        // TELEPORT DETECTION:
        // Distance > 500px AND time delta < 100ms = teleport!
        let isTeleport = distance > 500 && timestamp - last.t < 100;
        
        this.payload.m.push({
            x: Math.round(x),
            y: Math.round(y),
            distance: Math.round(distance),
            teleport: isTeleport ? 1 : 0    // 🚩 FLAG
        });
        
        this._lastMove = { x: x, y: y, t: timestamp };
    }
}
```

**Payload field `m` (movements) format:**
```json
[
    { "x": 542, "y": 318, "distance": 0, "teleport": 0 },
    { "x": 548, "y": 320, "distance": 7, "teleport": 0 },
    { "x": 890, "y": 50, "distance": 421, "teleport": 0 },
    { "x": 100, "y": 800, "distance": 1042, "teleport": 1 }  // ⚠️ FLAGGED
]
```

**Teleport Detection Rules:**
| Condition | Value | Meaning |
|-----------|-------|---------|
| Distance threshold | > 500 pixels | Jarak euclidean antara 2 sample |
| Time threshold | < 100 ms | Waktu antara 2 sample |
| Combined | distance > 500 AND dt < 100ms | Mouse "teleported" = bot behavior |
| Sample rate | 50ms | Minimum interval antar recording |

**Apa yang dianggap bot:**
- Selenium/Puppeteer `.click(x, y)` → cursor teleport instant ke target
- `document.elementFromPoint()` + `dispatchEvent()` → no movement trail
- Script yang set cursor position tanpa natural curve

**Cara menghindari:**
- Gunakan smooth mouse movement interpolation (Bezier curve)
- Jaga distance antar sample < 500px
- Jaga time antar sample ≥ 100ms
- Atau gunakan browser asli (mcp chrome-devtools) yang generate real events

---

### 2.4 Click & Mouse Tracking (Desktop)

```javascript
// Click listener (captures BOTH mousedown AND click)
this._onTrackClick = (event) => {
    // isTrusted check
    if (this.config.checkIsTrusted && !event.isTrusted) {
        this.payload.untrustedEventCount = 
            (this.payload.untrustedEventCount || 0) + 1;  // 🚩 INCREMENT COUNTER
    }
    
    if ("click" === event.type) {
        this.payload.a.push({
            x: event.clientX,
            y: event.clientY,
            isTrusted: event.isTrusted ? 1 : 0,  // 🚩 PER-EVENT FLAG
            ts: Date.now(),
            source: "mouse"
        });
    }
};

// Registered on BOTH mousedown and click with capture=true
document.addEventListener("mousedown", this._onTrackClick, true);
document.addEventListener("click", this._onTrackClick, true);
```

**Payload field `a` (actions/clicks) format:**
```json
[
    { "x": 542, "y": 318, "isTrusted": 1, "ts": 1712547123456, "source": "mouse" },
    { "x": 200, "y": 400, "isTrusted": 0, "ts": 1712547123500, "source": "mouse" }
]
```

**`isTrusted` Detection:**
| Scenario | `isTrusted` | Detection |
|----------|-------------|-----------|
| User physically clicks mouse | `true` (1) | ✅ Legitimate |
| `element.click()` from script | `false` (0) | 🚩 **Bot detected** |
| `element.dispatchEvent(new MouseEvent(...))` | `false` (0) | 🚩 **Bot detected** |
| Puppeteer `page.click()` | `true` (1) | ✅ Bypasses check |
| Playwright `page.click()` | `true` (1) | ✅ Bypasses check |
| CDP `Input.dispatchMouseEvent` | `true` (1) | ✅ Bypasses check |

**Penting:** Puppeteer/Playwright/CDP generate events dengan `isTrusted: true` karena mereka menggunakan browser's input pipeline. Hanya JavaScript `dispatchEvent()` yang di-flag.

---

### 2.5 Touch Tracking (Mobile)

```javascript
// Touch events tracked: touchstart, touchmove, touchend
this._onTouchStart = (event) => {
    if (this.config.checkIsTrusted && !event.isTrusted) {
        this.payload.untrustedEventCount++;
    }
    
    let touches = [];
    for (let i = 0; i < event.touches.length; i++) {
        touches.push({
            clientX: event.touches[i].clientX,
            clientY: event.touches[i].clientY,
            identifier: event.touches[i].identifier
        });
    }
    
    this.payload.t.push({
        type: "touchstart",
        touches: touches,
        changedTouches: [...],
        isTrusted: event.isTrusted ? 1 : 0,
        ts: Date.now()
    });
};
```

**Payload field `t` (touch events) format:**
```json
[
    {
        "type": "touchstart",
        "touches": [{ "clientX": 180, "clientY": 420, "identifier": 0 }],
        "changedTouches": [{ "clientX": 180, "clientY": 420, "identifier": 0 }],
        "isTrusted": 1,
        "ts": 1712547200000
    }
]
```

**Multi-touch support:** System melacak semua `identifier` — jadi pinch/zoom gestures juga di-record.

---

### 2.6 Keyboard Tracking

```javascript
this._onKeyDown = (event) => {
    // isTrusted check
    if (this.config.checkIsTrusted && !event.isTrusted) {
        this.payload.untrustedEventCount++;
    }
    
    let target = event.target;
    
    // SAFETY: Skip password fields!
    if (target && "INPUT" === target.tagName && "password" === target.type) return;
    
    // Only track keystrokes in text-input elements
    if (target && (
        "INPUT" === target.tagName || 
        "TEXTAREA" === target.tagName || 
        "true" === target.getAttribute("contenteditable")
    )) {
        this.payload.b.push({
            key: event.key,          // e.g. "a", "Enter", "Backspace"
            isTrusted: event.isTrusted ? 1 : 0,
            ts: Date.now()
        });
    }
};
```

**Payload field `b` (keyboard/behavior) format:**
```json
[
    { "key": "h", "isTrusted": 1, "ts": 1712547300000 },
    { "key": "e", "isTrusted": 1, "ts": 1712547300080 },
    { "key": "l", "isTrusted": 1, "ts": 1712547300150 },
    { "key": "l", "isTrusted": 1, "ts": 1712547300200 },
    { "key": "o", "isTrusted": 1, "ts": 1712547300280 }
]
```

**Apa yang dilacak:**
- Setiap keystroke di `<input>`, `<textarea>`, atau `contenteditable`
- **KECUALI** password fields (`input[type=password]`)
- Timestamp per key → bisa analisis typing speed/pattern
- `isTrusted` flag per keystroke

**Typing pattern analysis:**
- Manusia: interval antar key 50-300ms, irregular
- Bot: interval uniform (misalnya persis 100ms setiap key)
- Script `element.value = "text"`: tidak trigger keydown event sama sekali

---

### 2.7 Environment Snapshot (`_collectEnvSnapshot`)

```javascript
_collectEnvSnapshot() {
    return {
        webdriver: navigator.webdriver,      // 🚩 true = Selenium/Puppeteer
        userAgent: navigator.userAgent,
        outerWidth: window.outerWidth,       // Browser window total width
        outerHeight: window.outerHeight,     // Browser window total height
        innerWidth: window.innerWidth,       // Viewport width
        innerHeight: window.innerHeight,     // Viewport height
        pluginsLength: navigator.plugins.length,  // Installed plugins count
        languages: Array.from(navigator.languages),
        
        // 🚩 DevTools Detection:
        consoleDeltaWidth: window.outerWidth - window.innerWidth,
        consoleDeltaHeight: window.outerHeight - window.innerHeight,
        
        untrustedEventCount: this.payload.untrustedEventCount || 0
    };
}
```

**Payload field `x` (environment) format:**
```json
{
    "webdriver": false,
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
    "outerWidth": 1920,
    "outerHeight": 1040,
    "innerWidth": 1920,
    "innerHeight": 937,
    "pluginsLength": 5,
    "languages": ["en-US", "en"],
    "consoleDeltaWidth": 0,
    "consoleDeltaHeight": 103,
    "untrustedEventCount": 0
}
```

**Detection Signals:**

| Signal | Normal | Bot/Suspicious |
|--------|--------|----------------|
| `webdriver` | `false` / `undefined` | `true` (Selenium, unpatched Puppeteer) |
| `pluginsLength` | 3-10 | `0` (headless browser) |
| `consoleDeltaWidth` | `0` | `> 300` (DevTools docked right) |
| `consoleDeltaHeight` | `0-103` (toolbar) | `> 200` (DevTools docked bottom) |
| `untrustedEventCount` | `0` | `> 0` (scripted events detected) |
| `languages` | `["en-US", "en"]` | `[]` (headless default) |

**DevTools Detection Logic:**
```
consoleDeltaWidth  = outerWidth  - innerWidth   // > 0 = side panel open
consoleDeltaHeight = outerHeight - innerHeight  // > ~103 = bottom panel open
```
- Toolbar/scrollbar normally creates ~0-103px delta
- DevTools docked bottom → `consoleDeltaHeight` jumps to 200-400px
- DevTools docked right → `consoleDeltaWidth` jumps to 300-600px
- DevTools undocked/separate window → no delta change

---

### 2.8 Debugger Trap (`startDebuggerTrap`)

```javascript
startDebuggerTrap() {
    this._debuggerInterval = setInterval(function() {
        (function() {}).constructor("debugger")();
    }, 2000);  // Every 2 seconds
}
```

**Bagaimana cara kerjanya:**
1. Setiap 2 detik, execute `Function("debugger")()`
2. Jika DevTools **tertutup** → statement diabaikan, cost ~0ms
3. Jika DevTools **terbuka** → execution pauses di debugger breakpoint
4. Ini memperlambat/mengganggu reverse engineering
5. User harus manually resume execution setiap 2 detik

**Cara bypass:**
- Di DevTools: klik kanan pada breakpoint → "Never pause here"
- Atau: Settings → Preferences → centang "Disable JavaScript" sementara
- Atau: Override `Function.prototype.constructor` sebelum module load
- Atau: Gunakan browser extension yang auto-skip debugger statements

---

## Layer 3: Server-Side Validation

### Rate Limiting
| Endpoint | Limit | Error Code |
|----------|-------|------------|
| `quiz/get` | Per account per day | `40355` |
| `quiz/submit` | Per account per day | `40355` |
| `quiz/refresh-language` | **Tidak di-rate limit!** | Validation errors only |
| `rpv/v1/upgrade` | No visible limit | Business logic errors |
| `task/support/changeTaskStatus` | No visible limit | `code: 0` success |

### Session Validation
| Check | Error Code | Message |
|-------|------------|---------|
| Invalid/expired session | `40352` | "Session expired or invalid" |
| Quiz not completed | `1006` | "请先完成RPV答题验证" |
| Deposit insufficient | `1007` | "入金不足" |
| Trade volume insufficient | `1008` | "交易量不足" |
| Vault balance insufficient | `1009` | "Vault质押不足" |
| SSI holdings insufficient | `1010` | "SSI持仓不足" |
| Email not bound | `1004` | "请先绑定邮箱" |

---

## 📦 Complete Payload Structure

Ketika `getPayload()` dipanggil, data berikut dikumpulkan:

```json
{
    "a": [                          // Clicks/Actions
        { "x": 542, "y": 318, "isTrusted": 1, "ts": 1712547123456, "source": "mouse" }
    ],
    "b": [                          // Keyboard (non-password)
        { "key": "h", "isTrusted": 1, "ts": 1712547300000 }
    ],
    "m": [                          // Mouse Movements
        { "x": 548, "y": 320, "distance": 7, "teleport": 0 }
    ],
    "t": [                          // Touch Events (mobile only)
        { "type": "touchstart", "touches": [...], "isTrusted": 1, "ts": ... }
    ],
    "f": {                          // Fingerprint (collected once)
        "cvs": "base64_last_20_chars",
        "sw": 1920,
        "sh": 1080,
        "ua": "Mozilla/5.0...",
        "tz": "Asia/Jakarta",
        "mobile": false
    },
    "x": {                          // Environment Snapshot (collected on getPayload)
        "webdriver": false,
        "userAgent": "Mozilla/5.0...",
        "outerWidth": 1920,
        "outerHeight": 1040,
        "innerWidth": 1920,
        "innerHeight": 937,
        "pluginsLength": 5,
        "languages": ["en-US", "en"],
        "consoleDeltaWidth": 0,
        "consoleDeltaHeight": 103,
        "untrustedEventCount": 0
    }
}
```

---

## 🎯 Di Mana Payload Ini Dikirim?

Berdasarkan analisis kode:

1. **Module di-init saat app load** via `pf()` (singleton pattern)
2. **Payload diambil** via `iW()` / `getPayload()` 
3. **Kemungkinan besar dikirim bersama `quiz/submit`** — meskipun dari analisis API call langsung, endpoint hanya menerima `{quizType, questionId, answer, sessionId}`
4. **Payload TIDAK dikirim ke `rpv/v1/upgrade`** — endpoint ini hanya menerima `{exemptCheck, upgradeToLevel, verifyOption, verifyMethod}`
5. **Kemungkinan dikirim sebagai header atau cookie** — perlu monitoring network tab saat quiz submit aktif

**Status**: Payload dikumpulkan tapi **belum terkonfirmasi** kapan/kemana dikirim karena quiz daily limit menghalangi testing submit flow.

---

## 🛡️ Bypass Cheatsheet

| Detection | Bypass Method |
|-----------|---------------|
| Canvas fingerprint | Konsisten per session, tidak perlu spoof |
| `isTrusted` check | Gunakan CDP/Puppeteer/Playwright (generate trusted events) |
| Teleport detection | Smooth mouse interpolation, distance < 500px per step |
| Webdriver flag | `Object.defineProperty(navigator, 'webdriver', {get: () => false})` |
| DevTools detection | Gunakan undocked DevTools window |
| Debugger trap | Right-click breakpoint → "Never pause here" |
| Console delta | Undock DevTools ke separate window → delta = 0 |
| Typing pattern | Random delay 50-300ms antar keystroke |
| `untrustedEventCount` | Gunakan CDP events, bukan `dispatchEvent()` |
| Plugins length | Anti-detect browser profiles sudah handle ini |
| Cloudflare Turnstile | Reuse `cf_clearance` cookie, atau solve via Turnstile API |

---

## ⚠️ Yang TIDAK Di-Detect

| Aspect | Status |
|--------|--------|
| TLS fingerprint (JA3/JA4) | Tidak ada client-side check (handled by Cloudflare) |
| IP reputation | Tidak ada client-side check (handled by Cloudflare) |
| Request timing patterns | Tidak ada client-side check |
| Header consistency (Sec-CH-UA) | Tidak ada client-side check |
| Cookie freshness | Hanya `cf_clearance` expiry check |
| WebGL fingerprint | Tidak dicollect |
| Audio fingerprint | Tidak dicollect |
| Font enumeration | Tidak dicollect |
| Battery API | Tidak dicollect |
| Connection/Network API | Tidak dicollect |
