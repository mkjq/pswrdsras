// ================================================================
//  MKQ.ONE — MKQ Vault  v3  (Headless Serial Dongle)
//  Hardware Password Manager | ESP32-S3
//  mkq.one
//
//  Architecture:
//   - No screen, no buttons, no Wi-Fi, no HID keyboard
//   - Communicates exclusively via USB CDC Serial
//   - PIN-based lock/unlock (Challenge-Response)
//   - JSON Serial API for all data operations
//   - NVS storage for Passwords + TOTP (up to 12 each)
//   - TOTP time supplied by host app via SET_TIME command
// ================================================================

#include <Preferences.h>
#include <TOTP.h>

// ================================================================
//  Configuration — change before first flash
// ================================================================
#define SERIAL_BAUD       115200
#define DEFAULT_PIN       "1234"      // initial PIN (change after first boot)
#define MAX_FAIL_LOCKOUT  5           // wrong PINs before 30-s lockout
#define LOCKOUT_DURATION  30000UL     // 30 seconds in ms
#define MAX_ITEMS         12

// ================================================================
//  NVS namespaces
// ================================================================
#define NS_PIN    "mkq_pin"
#define NS_PW     "mkq_pw"
#define NS_TOTP   "mkq_totp"

// ================================================================
//  Global state
// ================================================================
Preferences prefs;

enum DeviceState { STATE_LOCKED, STATE_UNLOCKED };
DeviceState devState = STATE_LOCKED;

int           failCount       = 0;
unsigned long lockoutUntil    = 0;
time_t        deviceUnixTime  = 0;          // set by host via SET_TIME
unsigned long lastMillis      = 0;          // for software clock increment

// ================================================================
//  Password storage
// ================================================================
int  pwCount = 0;
char pwName    [MAX_ITEMS][32]  = {};
char pwUser    [MAX_ITEMS][128] = {};
char pwPass    [MAX_ITEMS][128] = {};

// ================================================================
//  TOTP storage
// ================================================================
int     totpCount                  = 0;
char    totpName   [MAX_ITEMS][32] = {};
char    totpB32    [MAX_ITEMS][65] = {};
uint8_t totpBytes  [MAX_ITEMS][64] = {};
size_t  totpLens   [MAX_ITEMS]     = {};
TOTP*   totpObj    [MAX_ITEMS]     = {};

// ================================================================
//  Base32 decoder
// ================================================================
int b32val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

size_t decodeBase32(const char* in, uint8_t* out, size_t maxLen) {
  int buf = 0, bits = 0; size_t len = 0;
  while (*in) {
    char c = *in++;
    if (c==' '||c=='='||c=='-') continue;
    int v = b32val(c); if (v<0) continue;
    buf = (buf<<5)|v; bits += 5;
    if (bits >= 8) { bits -= 8; if (len>=maxLen) return 0; out[len++]=(buf>>bits)&0xFF; }
  }
  return len;
}

// ================================================================
//  TOTP — reinit all objects from stored B32 strings
// ================================================================
void initAllTotp() {
  for (int i = 0; i < MAX_ITEMS; i++) {
    if (totpObj[i]) { delete totpObj[i]; totpObj[i] = nullptr; }
  }
  for (int i = 0; i < totpCount; i++) {
    totpLens[i] = decodeBase32(totpB32[i], totpBytes[i], 64);
    if (totpLens[i] > 0) totpObj[i] = new TOTP(totpBytes[i], totpLens[i]);
  }
}

// ================================================================
//  NVS — PIN
// ================================================================
String loadPin() {
  prefs.begin(NS_PIN, true);
  String p = prefs.getString("pin", DEFAULT_PIN);
  prefs.end();
  return p;
}

void savePin(const String& pin) {
  prefs.begin(NS_PIN, false);
  prefs.putString("pin", pin);
  prefs.end();
}

// ================================================================
//  NVS — Passwords
// ================================================================
void loadPasswords() {
  prefs.begin(NS_PW, true);
  pwCount = constrain(prefs.getInt("count", 0), 0, MAX_ITEMS);
  for (int i = 0; i < pwCount; i++) {
    prefs.getString(("n"+String(i)).c_str(),"").toCharArray(pwName[i], 32);
    prefs.getString(("u"+String(i)).c_str(),"").toCharArray(pwUser[i], 128);
    prefs.getString(("p"+String(i)).c_str(),"").toCharArray(pwPass[i], 128);
  }
  prefs.end();
}

void savePasswords() {
  prefs.begin(NS_PW, false); prefs.clear();
  prefs.putInt("count", pwCount);
  for (int i = 0; i < pwCount; i++) {
    prefs.putString(("n"+String(i)).c_str(), pwName[i]);
    prefs.putString(("u"+String(i)).c_str(), pwUser[i]);
    prefs.putString(("p"+String(i)).c_str(), pwPass[i]);
  }
  prefs.end();
}

// ================================================================
//  NVS — TOTP
// ================================================================
void loadTotp() {
  prefs.begin(NS_TOTP, true);
  totpCount = constrain(prefs.getInt("count", 0), 0, MAX_ITEMS);
  for (int i = 0; i < totpCount; i++) {
    prefs.getString(("n"+String(i)).c_str(),"").toCharArray(totpName[i], 32);
    prefs.getString(("s"+String(i)).c_str(),"").toCharArray(totpB32[i],  65);
  }
  prefs.end();
  initAllTotp();
}

void saveTotp() {
  prefs.begin(NS_TOTP, false); prefs.clear();
  prefs.putInt("count", totpCount);
  for (int i = 0; i < totpCount; i++) {
    prefs.putString(("n"+String(i)).c_str(), totpName[i]);
    prefs.putString(("s"+String(i)).c_str(), totpB32[i]);
  }
  prefs.end();
}

// ================================================================
//  Software clock — incremented every loop tick using millis delta
// ================================================================
void tickClock() {
  unsigned long now = millis();
  unsigned long delta = now - lastMillis;
  if (delta >= 1000) {
    deviceUnixTime += delta / 1000;
    lastMillis += (delta / 1000) * 1000;
  }
}

// ================================================================
//  JSON helpers — simple builders (no external library needed)
// ================================================================

// Escape double quotes and backslashes in a string
String jsonStr(const char* s) {
  String r = "\"";
  while (*s) {
    if (*s=='"')  r += "\\\"";
    else if (*s=='\\') r += "\\\\";
    else r += *s;
    s++;
  }
  r += "\"";
  return r;
}

// Send a simple status response
void sendOk(const String& msg = "") {
  if (msg.length()) Serial.println("{\"ok\":true,\"msg\":" + jsonStr(msg.c_str()) + "}");
  else              Serial.println("{\"ok\":true}");
}

void sendErr(const String& msg) {
  Serial.println("{\"ok\":false,\"err\":" + jsonStr(msg.c_str()) + "}");
}

// ================================================================
//  Command parser helpers
// ================================================================

// Extract value after first ':' in a command string
//   e.g.  "GET_TOTP:2"  →  "2"
//   e.g.  "UNLOCK:1234" →  "1234"
String afterColon(const String& cmd) {
  int idx = cmd.indexOf(':');
  if (idx < 0) return "";
  return cmd.substring(idx + 1);
}

// Extract Nth field (0-based) from a pipe-separated payload
//   e.g.  "Gmail|user@g.com|secret123"  field 1  →  "user@g.com"
String pipeField(const String& payload, int n) {
  int start = 0, cur = 0;
  while (cur < n) {
    int pos = payload.indexOf('|', start);
    if (pos < 0) return "";
    start = pos + 1;
    cur++;
  }
  int end = payload.indexOf('|', start);
  return (end < 0) ? payload.substring(start) : payload.substring(start, end);
}

// ================================================================
//  Command handlers
// ================================================================

// ---- AUTH ----

void cmdUnlock(const String& pin) {
  // Lockout check
  if (millis() < lockoutUntil) {
    long remaining = (lockoutUntil - millis()) / 1000 + 1;
    sendErr("LOCKED_OUT:" + String(remaining) + "s");
    return;
  }

  String stored = loadPin();
  if (pin == stored) {
    devState  = STATE_UNLOCKED;
    failCount = 0;
    Serial.println("{\"ok\":true,\"auth\":\"AUTH_OK\"}");
  } else {
    failCount++;
    if (failCount >= MAX_FAIL_LOCKOUT) {
      lockoutUntil = millis() + LOCKOUT_DURATION;
      failCount    = 0;
      sendErr("AUTH_FAILED:LOCKOUT");
    } else {
      sendErr("AUTH_FAILED:attempts_left=" + String(MAX_FAIL_LOCKOUT - failCount));
    }
  }
}

void cmdLock() {
  devState = STATE_LOCKED;
  sendOk("LOCKED");
}

void cmdChangePin(const String& payload) {
  // Payload: "oldPIN|newPIN"
  String oldPin = pipeField(payload, 0);
  String newPin = pipeField(payload, 1);
  if (oldPin != loadPin()) { sendErr("PIN_MISMATCH"); return; }
  if (newPin.length() < 4) { sendErr("PIN_TOO_SHORT"); return; }
  savePin(newPin);
  sendOk("PIN_CHANGED");
}

// ---- TIME ----

void cmdSetTime(const String& unixStr) {
  // Host sends Unix timestamp as decimal string
  time_t t = (time_t)unixStr.toInt();
  if (t < 1000000000L) { sendErr("INVALID_TIME"); return; }
  deviceUnixTime = t;
  lastMillis     = millis();
  sendOk("TIME_SET:" + String((long)deviceUnixTime));
}

void cmdGetTime() {
  Serial.println("{\"ok\":true,\"unix\":" + String((long)deviceUnixTime) + "}");
}

// ---- PASSWORDS ----

void cmdListPasswords() {
  String r = "{\"ok\":true,\"passwords\":[";
  for (int i = 0; i < pwCount; i++) {
    if (i) r += ",";
    r += "{\"idx\":" + String(i) +
         ",\"name\":"  + jsonStr(pwName[i]) +
         ",\"user\":"  + jsonStr(pwUser[i]) +
         "}";
    // Note: password value intentionally omitted from list — use GET_PW:<idx> to retrieve
  }
  r += "]}";
  Serial.println(r);
}

void cmdGetPassword(const String& idxStr) {
  int idx = idxStr.toInt();
  if (idx < 0 || idx >= pwCount) { sendErr("INVALID_INDEX"); return; }
  String r = "{\"ok\":true,\"idx\":" + String(idx) +
             ",\"name\":"  + jsonStr(pwName[idx]) +
             ",\"user\":"  + jsonStr(pwUser[idx]) +
             ",\"pass\":"  + jsonStr(pwPass[idx]) + "}";
  Serial.println(r);
}

void cmdAddPassword(const String& payload) {
  // Payload: "name|username|password"
  if (pwCount >= MAX_ITEMS) { sendErr("STORAGE_FULL"); return; }
  String name = pipeField(payload, 0);
  String user = pipeField(payload, 1);
  String pass = pipeField(payload, 2);
  if (name.length() == 0 || pass.length() == 0) { sendErr("MISSING_FIELDS"); return; }
  name.toCharArray(pwName[pwCount], 32);
  user.toCharArray(pwUser[pwCount], 128);
  pass.toCharArray(pwPass[pwCount], 128);
  pwCount++;
  savePasswords();
  sendOk("PW_ADDED:idx=" + String(pwCount - 1));
}

void cmdEditPassword(const String& payload) {
  // Payload: "idx|name|username|password"  (leave password empty to keep current)
  int idx = pipeField(payload, 0).toInt();
  if (idx < 0 || idx >= pwCount) { sendErr("INVALID_INDEX"); return; }
  String name = pipeField(payload, 1);
  String user = pipeField(payload, 2);
  String pass = pipeField(payload, 3);
  if (name.length() > 0) name.toCharArray(pwName[idx], 32);
  if (user.length() > 0) user.toCharArray(pwUser[idx], 128);
  if (pass.length() > 0) pass.toCharArray(pwPass[idx], 128);
  savePasswords();
  sendOk("PW_UPDATED:idx=" + String(idx));
}

void cmdDeletePassword(const String& idxStr) {
  int idx = idxStr.toInt();
  if (idx < 0 || idx >= pwCount) { sendErr("INVALID_INDEX"); return; }
  for (int i = idx; i < pwCount - 1; i++) {
    strlcpy(pwName[i], pwName[i+1], 32);
    strlcpy(pwUser[i], pwUser[i+1], 128);
    strlcpy(pwPass[i], pwPass[i+1], 128);
  }
  pwCount = max(0, pwCount - 1);
  savePasswords();
  sendOk("PW_DELETED:idx=" + String(idx));
}

// ---- TOTP ----

void cmdListTotp() {
  String r = "{\"ok\":true,\"totp\":[";
  for (int i = 0; i < totpCount; i++) {
    if (i) r += ",";
    r += "{\"idx\":" + String(i) + ",\"name\":" + jsonStr(totpName[i]) + "}";
  }
  r += "]}";
  Serial.println(r);
}

void cmdGetTotp(const String& idxStr) {
  int idx = idxStr.toInt();
  if (idx < 0 || idx >= totpCount)    { sendErr("INVALID_INDEX"); return; }
  if (deviceUnixTime < 1000000000L)   { sendErr("TIME_NOT_SET — send SET_TIME first"); return; }
  if (!totpObj[idx])                  { sendErr("TOTP_INIT_FAILED"); return; }

  tickClock(); // make sure time is fresh
  char* code    = totpObj[idx]->getCode(deviceUnixTime);
  int   secsLeft = 30 - (int)(deviceUnixTime % 30);
  if (secsLeft == 30) secsLeft = 0;

  String r = "{\"ok\":true,\"idx\":" + String(idx) +
             ",\"name\":" + jsonStr(totpName[idx]) +
             ",\"code\":\"" + String(code) + "\"" +
             ",\"expires_in\":" + String(secsLeft) + "}";
  Serial.println(r);
}

void cmdAddTotp(const String& payload) {
  // Payload: "name|base32secret"
  if (totpCount >= MAX_ITEMS) { sendErr("STORAGE_FULL"); return; }
  String name   = pipeField(payload, 0);
  String secret = pipeField(payload, 1);
  if (name.length() == 0 || secret.length() == 0) { sendErr("MISSING_FIELDS"); return; }
  name.toCharArray(totpName[totpCount],   32);
  secret.toCharArray(totpB32[totpCount], 65);
  totpCount++;
  initAllTotp();
  saveTotp();
  sendOk("TOTP_ADDED:idx=" + String(totpCount - 1));
}

void cmdEditTotp(const String& payload) {
  // Payload: "idx|name|base32secret"  (leave fields empty to keep current)
  int idx = pipeField(payload, 0).toInt();
  if (idx < 0 || idx >= totpCount) { sendErr("INVALID_INDEX"); return; }
  String name   = pipeField(payload, 1);
  String secret = pipeField(payload, 2);
  if (name.length()   > 0) name.toCharArray(totpName[idx],   32);
  if (secret.length() > 0) secret.toCharArray(totpB32[idx], 65);
  initAllTotp();
  saveTotp();
  sendOk("TOTP_UPDATED:idx=" + String(idx));
}

void cmdDeleteTotp(const String& idxStr) {
  int idx = idxStr.toInt();
  if (idx < 0 || idx >= totpCount) { sendErr("INVALID_INDEX"); return; }
  if (totpObj[idx]) { delete totpObj[idx]; totpObj[idx] = nullptr; }
  for (int i = idx; i < totpCount - 1; i++) {
    strlcpy(totpName[i], totpName[i+1], 32);
    strlcpy(totpB32[i],  totpB32[i+1],  65);
  }
  totpCount = max(0, totpCount - 1);
  initAllTotp();
  saveTotp();
  sendOk("TOTP_DELETED:idx=" + String(idx));
}

// ---- BACKUP / RESTORE ----

void cmdExportJson() {
  // Exports all data as a single JSON line
  // Passwords are included in full — handle this output securely on the host
  String r = "{\"ok\":true,\"backup\":{\"ver\":3,\"passwords\":[";
  for (int i = 0; i < pwCount; i++) {
    if (i) r += ",";
    r += "{\"n\":" + jsonStr(pwName[i]) +
         ",\"u\":" + jsonStr(pwUser[i]) +
         ",\"p\":" + jsonStr(pwPass[i]) + "}";
  }
  r += "],\"totp\":[";
  for (int i = 0; i < totpCount; i++) {
    if (i) r += ",";
    r += "{\"n\":" + jsonStr(totpName[i]) +
         ",\"s\":" + jsonStr(totpB32[i]) + "}";
  }
  r += "]}}";
  Serial.println(r);
}

// Minimal in-place JSON string extractor (no heap alloc)
// Finds  "KEY":"VALUE"  and copies VALUE into buf
bool jsonExtractStr(const String& json, const char* key, char* buf, size_t bufLen) {
  String search = String("\"") + key + "\":\"";
  int start = json.indexOf(search);
  if (start < 0) return false;
  start += search.length();
  int end = json.indexOf("\"", start);
  if (end < 0) return false;
  String val = json.substring(start, end);
  // unescape \" and \\
  val.replace("\\\"", "\""); val.replace("\\\\", "\\");
  val.toCharArray(buf, bufLen);
  return true;
}

void cmdImportJson(const String& payload) {
  // Full JSON string passed as payload after IMPORT_JSON:
  // Replaces all data — host must confirm before sending

  // Reset current data
  pwCount    = 0;
  totpCount  = 0;

  // Parse passwords
  int pwStart = payload.indexOf("\"passwords\":[");
  if (pwStart >= 0) {
    pwStart += 13;
    int pwEnd = payload.indexOf("]", pwStart);
    String arr = payload.substring(pwStart, pwEnd);
    int pos = 0;
    while (pwCount < MAX_ITEMS) {
      int ob = arr.indexOf("{", pos); if (ob<0) break;
      int cb = arr.indexOf("}", ob);  if (cb<0) break;
      String obj = arr.substring(ob, cb+1);
      char n[32]="", u[128]="", p[128]="";
      jsonExtractStr(obj,"n",n,32);
      jsonExtractStr(obj,"u",u,128);
      jsonExtractStr(obj,"p",p,128);
      if (strlen(n)>0) {
        strlcpy(pwName[pwCount], n, 32);
        strlcpy(pwUser[pwCount], u, 128);
        strlcpy(pwPass[pwCount], p, 128);
        pwCount++;
      }
      pos = cb+1;
    }
  }

  // Parse TOTP
  int tStart = payload.indexOf("\"totp\":[");
  if (tStart >= 0) {
    tStart += 8;
    int tEnd = payload.indexOf("]", tStart);
    String arr = payload.substring(tStart, tEnd);
    int pos = 0;
    while (totpCount < MAX_ITEMS) {
      int ob = arr.indexOf("{", pos); if (ob<0) break;
      int cb = arr.indexOf("}", ob);  if (cb<0) break;
      String obj = arr.substring(ob, cb+1);
      char n[32]="", s[65]="";
      jsonExtractStr(obj,"n",n,32);
      jsonExtractStr(obj,"s",s,65);
      if (strlen(n)>0 && strlen(s)>0) {
        strlcpy(totpName[totpCount], n, 32);
        strlcpy(totpB32[totpCount],  s, 65);
        totpCount++;
      }
      pos = cb+1;
    }
  }

  savePasswords();
  initAllTotp();
  saveTotp();
  sendOk("IMPORT_OK:pw=" + String(pwCount) + ",totp=" + String(totpCount));
}

// ---- DEVICE INFO ----

void cmdInfo() {
  String r = String("{\"ok\":true") +
    ",\"fw\":\"MKQ Vault v3\"" +
    ",\"mkq\":\"mkq.one\"" +
    ",\"state\":\"" + (devState==STATE_UNLOCKED?"UNLOCKED":"LOCKED") + "\"" +
    ",\"pw_count\":"   + String(pwCount) +
    ",\"totp_count\":" + String(totpCount) +
    ",\"unix\":"       + String((long)deviceUnixTime) +
    "}";
  Serial.println(r);
}

// ================================================================
//  Main command dispatcher
// ================================================================
void dispatchCommand(const String& raw) {
  String cmd = raw; cmd.trim();
  if (cmd.length() == 0) return;

  // Extract verb (before ':') and payload (after ':')
  int    colonIdx = cmd.indexOf(':');
  String verb     = (colonIdx >= 0) ? cmd.substring(0, colonIdx) : cmd;
  String payload  = (colonIdx >= 0) ? cmd.substring(colonIdx + 1) : "";
  verb.toUpperCase();

  // ---- Commands available in LOCKED state ----
  if (verb == "UNLOCK")   { cmdUnlock(payload); return; }
  if (verb == "INFO")     { cmdInfo();           return; }
  if (verb == "SET_TIME") { cmdSetTime(payload); return; } // Allow so host can set time before unlock
  if (verb == "GET_TIME") { cmdGetTime();         return; }

  // ---- Guard: everything below requires UNLOCKED ----
  if (devState != STATE_UNLOCKED) {
    sendErr("LOCKED — send UNLOCK:<pin> first");
    return;
  }

  // ---- Password commands ----
  if (verb == "LIST_PW")    { cmdListPasswords();       return; }
  if (verb == "GET_PW")     { cmdGetPassword(payload);  return; }
  if (verb == "ADD_PW")     { cmdAddPassword(payload);  return; }
  if (verb == "EDIT_PW")    { cmdEditPassword(payload); return; }
  if (verb == "DEL_PW")     { cmdDeletePassword(payload); return; }

  // ---- TOTP commands ----
  if (verb == "LIST_TOTP")  { cmdListTotp();        return; }
  if (verb == "GET_TOTP")   { cmdGetTotp(payload);  return; }
  if (verb == "ADD_TOTP")   { cmdAddTotp(payload);  return; }
  if (verb == "EDIT_TOTP")  { cmdEditTotp(payload); return; }
  if (verb == "DEL_TOTP")   { cmdDeleteTotp(payload); return; }

  // ---- Auth management ----
  if (verb == "LOCK")       { cmdLock();              return; }
  if (verb == "CHANGE_PIN") { cmdChangePin(payload);  return; }

  // ---- Backup / Restore ----
  if (verb == "EXPORT_JSON") { cmdExportJson();        return; }
  if (verb == "IMPORT_JSON") { cmdImportJson(payload); return; }

  sendErr("UNKNOWN_COMMAND:" + verb);
}

// ================================================================
//  Serial line buffer
// ================================================================
String serialBuf = "";

void readSerial() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (serialBuf.length() > 0) {
        dispatchCommand(serialBuf);
        serialBuf = "";
      }
    } else {
      if (serialBuf.length() < 2048) serialBuf += c; // guard against overflow
    }
  }
}

// ================================================================
//  Setup
// ================================================================
void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(500); // let USB CDC enumerate

  loadPasswords();
  loadTotp();
  lastMillis = millis();

  // Ready banner
  Serial.println("{\"ok\":true,\"boot\":\"MKQ Vault v3\",\"state\":\"LOCKED\",\"mkq\":\"mkq.one\"}");
}

// ================================================================
//  Loop
// ================================================================
void loop() {
  tickClock();
  readSerial();
  delay(5);
}
