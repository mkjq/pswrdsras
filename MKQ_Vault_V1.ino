// ============================================================
//  MKQ.ONE — MKQ Vault
//  Hardware Password Manager | ESP32-S3
//  mkq.one
// ============================================================

// ===== Wi-Fi / TOTP Config (edit before flashing) =====
const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* GMAIL_TOTP_BASE32 = "aaaa bbbb cccc dddd eeee ffff gggg hhhh";

#include <TFT_eSPI.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <time.h>
#include <TOTP.h>
#include "USB.h"
#include "USBHIDKeyboard.h"

TFT_eSPI       tft = TFT_eSPI();
USBHIDKeyboard Keyboard;
WebServer      server(80);
DNSServer      dnsServer;
Preferences    prefs;

// ===== Hardware Pins =====
#define BTN_OK_UP  0
#define BTN_DOWN   14

// ===== NTP / Time =====
const char* NTP_SERVER_1       = "pool.ntp.org";
const char* NTP_SERVER_2       = "time.google.com";
const long  GMT_OFFSET_SEC     = 3 * 3600; // GMT+3 (Arabia Standard Time)
const int   DAYLIGHT_OFFSET_SEC = 0;

// ===== TOTP =====
uint8_t  gmailTotpSecret[64];
size_t   gmailTotpSecretLen = 0;
TOTP*    gmailTotp          = nullptr;

// ===== Timing Constants =====
const unsigned long DEBOUNCE_MS       = 180;
const unsigned long HOLD_TIME_MS      = 700;
const unsigned long USB_STARTUP_DELAY = 800;
const byte          DNS_PORT          = 53;

// ===== Menu Types =====
enum ItemType {
  ITEM_SUBMENU,
  ITEM_TEXT,
  ITEM_TOTP,
  ITEM_INFO
};

struct MenuItem {
  const char* name;
  ItemType    type;
  const char* textValue;
  TOTP*       totp;
};

enum MenuScreen {
  SCREEN_MAIN,
  SCREEN_PASSWORDS,
  SCREEN_PASSWORD_ACTIONS,
  SCREEN_TOTP,
  SCREEN_TOTP_VIEW,
  SCREEN_SETTINGS
};

MenuScreen currentScreen   = SCREEN_MAIN;
int        selectedIndex   = 0;
int        menuScrollOffset = 0;

MenuItem mainMenuItems[] = {
  {"Passwords", ITEM_SUBMENU, nullptr, nullptr},
  {"TOTP",      ITEM_SUBMENU, nullptr, nullptr},
  {"Settings",  ITEM_SUBMENU, nullptr, nullptr}
};

const int MAX_PASSWORD_ITEMS = 12;
MenuItem  passwordMenuItems[MAX_PASSWORD_ITEMS];
int       passwordMenuCount = 4;

char passwordNameValues[MAX_PASSWORD_ITEMS][32] = {
  "Gmail", "GitHub", "AWS", "Bank"
};

MenuItem passwordActionMenuItems[] = {
  {"Username",    ITEM_INFO, nullptr, nullptr},
  {"Password",    ITEM_INFO, nullptr, nullptr},
  {"User+Tab+Pass", ITEM_INFO, nullptr, nullptr}
};

MenuItem totpMenuItems[] = {
  {"Google TOTP", ITEM_TOTP, nullptr, nullptr}
};

MenuItem settingsMenuItems[] = {};

// ===== Active State =====
bool          timeSynced          = false;
int           activeTotpIndex     = 0;
unsigned long lastTotpRedraw      = 0;
bool          settingsPortalActive = false;
String        settingsApPassword;
int           activePasswordIndex  = 0;

char passwordTextValues[MAX_PASSWORD_ITEMS][128] = {
  "MyGmailPassword123",
  "MyGitHubPassword456",
  "MyAwsPassword789",
  "MyBankPassword000"
};

char passwordUsernameValues[MAX_PASSWORD_ITEMS][128] = {
  "user.alpha01",   "bluefalcon77",  "cloud.user23",
  "banking_hero",   "gamma.node",    "pixel.rider",
  "tiger_login",    "neo.account",   "orbit.user",
  "delta.signin",   "fastlane.id",   "quantum.user"
};

// ===== Button State =====
bool          lastDownState    = HIGH;
bool          btnPressed       = false;
bool          holdTriggered    = false;
unsigned long btnPressStart    = 0;
unsigned long lastDownPress    = 0;
bool          downHoldHandled  = false;

// ============================================================
//  Helpers — Menu Routing
// ============================================================

MenuItem* getCurrentMenuItems() {
  switch (currentScreen) {
    case SCREEN_PASSWORDS:        return passwordMenuItems;
    case SCREEN_PASSWORD_ACTIONS: return passwordActionMenuItems;
    case SCREEN_TOTP:             return totpMenuItems;
    case SCREEN_SETTINGS:         return settingsMenuItems;
    default:                      return mainMenuItems;
  }
}

int getCurrentMenuCount() {
  switch (currentScreen) {
    case SCREEN_PASSWORDS:        return passwordMenuCount;
    case SCREEN_PASSWORD_ACTIONS: return sizeof(passwordActionMenuItems) / sizeof(passwordActionMenuItems[0]);
    case SCREEN_TOTP:             return sizeof(totpMenuItems)           / sizeof(totpMenuItems[0]);
    case SCREEN_SETTINGS:         return 0;
    default:                      return sizeof(mainMenuItems)           / sizeof(mainMenuItems[0]);
  }
}

const char* getScreenTitle() {
  switch (currentScreen) {
    case SCREEN_PASSWORDS:        return "Passwords";
    case SCREEN_PASSWORD_ACTIONS: return "Send As";
    case SCREEN_TOTP:             return "TOTP";
    case SCREEN_TOTP_VIEW:        return "TOTP";
    case SCREEN_SETTINGS:         return "Settings";
    default:                      return "MKQ Vault";
  }
}

// ============================================================
//  Base32 Decoder (for TOTP secrets)
// ============================================================

int base32Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

size_t decodeBase32(const char* input, uint8_t* output, size_t maxLen) {
  int    buffer   = 0;
  int    bitsLeft = 0;
  size_t outLen   = 0;

  while (*input) {
    char c = *input++;
    if (c == ' ' || c == '=' || c == '-') continue;
    int val = base32Value(c);
    if (val < 0) continue;
    buffer    = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      if (outLen >= maxLen) return 0;
      output[outLen++] = (buffer >> bitsLeft) & 0xFF;
    }
  }
  return outLen;
}

bool initTotp() {
  gmailTotpSecretLen = decodeBase32(GMAIL_TOTP_BASE32, gmailTotpSecret, sizeof(gmailTotpSecret));
  if (gmailTotpSecretLen == 0) return false;
  gmailTotp = new TOTP(gmailTotpSecret, gmailTotpSecretLen);
  return true;
}

// ============================================================
//  Display — Menu
// ============================================================

void drawMenu() {
  tft.fillScreen(TFT_BLACK);

  // Title bar
  tft.setTextColor(0xFD20, TFT_BLACK); // Amber/gold accent
  tft.setTextSize(3);
  tft.setCursor(12, 10);
  tft.println(getScreenTitle());

  // Thin separator line
  tft.drawFastHLine(8, 46, tft.width() - 16, 0x39C4);

  tft.setTextSize(2);

  MenuItem* items      = getCurrentMenuItems();
  int       itemCount  = getCurrentMenuCount();

  const int startY      = 55;
  const int lineHeight  = 28;
  const int visibleItems = 4;

  // Scroll clamping
  if (selectedIndex < menuScrollOffset)
    menuScrollOffset = selectedIndex;
  if (selectedIndex >= menuScrollOffset + visibleItems)
    menuScrollOffset = selectedIndex - visibleItems + 1;
  if (menuScrollOffset < 0) menuScrollOffset = 0;
  if (itemCount <= visibleItems) menuScrollOffset = 0;

  int endIndex = min(menuScrollOffset + visibleItems, itemCount);

  int y = startY;
  for (int i = menuScrollOffset; i < endIndex; i++) {
    if (i == selectedIndex) {
      tft.fillRect(8, y - 3, tft.width() - 16, 24, 0x1082); // Dark blue highlight
      tft.setTextColor(0xFD20, 0x1082);                       // Gold text on highlight
      tft.setCursor(14, y);
      tft.print("> ");
      tft.println(items[i].name);
    } else {
      tft.setTextColor(TFT_WHITE, TFT_BLACK);
      tft.setCursor(14, y);
      tft.print("  ");
      tft.println(items[i].name);
    }
    y += lineHeight;
  }

  // Scroll indicators
  tft.setTextSize(1);
  if (menuScrollOffset > 0) {
    tft.setTextColor(0xFD20, TFT_BLACK);
    tft.setCursor(tft.width() - 14, 48);
    tft.print("^");
  }
  if (endIndex < itemCount) {
    tft.setTextColor(0xFD20, TFT_BLACK);
    tft.setCursor(tft.width() - 14, 120);
    tft.print("v");
  }

  // Brand watermark bottom-right
  tft.setTextSize(1);
  tft.setTextColor(0x39C4, TFT_BLACK);
  tft.setCursor(tft.width() - 58, tft.height() - 12);
  tft.print("MKQ.ONE");
}

// ============================================================
//  Display — Sending Screen
// ============================================================

void showSendingScreen(const char* label) {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(0x07FF, TFT_BLACK); // Cyan
  tft.setTextSize(2);
  tft.setCursor(20, 40);
  tft.println("Sending...");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(20, 75);
  tft.println(label);
}

// ============================================================
//  Display — Status / Loading Screen
// ============================================================

void showStatusScreen(const char* title, const char* line2) {
  tft.fillScreen(TFT_BLACK);

  int titleWidth = strlen(title) * 12;
  int titleX     = max(0, (tft.width() - titleWidth) / 2);
  int titleY     = tft.height() / 2 - 20;
  int dotsY      = titleY + 30;

  tft.setTextColor(0xFD20, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(titleX, titleY);
  tft.println(title);

  // Animated dots
  const char* dots   = "..........";
  int dotsLen        = strlen(dots);
  int phase          = (millis() / 180) % ((dotsLen * 2) - 2);
  int visibleCount   = (phase < dotsLen) ? (phase + 1) : ((dotsLen * 2) - phase - 1);
  int dotsWidth      = visibleCount * 12;
  int dotsX          = max(0, (tft.width() - dotsWidth) / 2);

  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(dotsX, dotsY);
  for (int i = 0; i < visibleCount; i++) tft.print('.');
}

// ============================================================
//  Display — TOTP Code Screen
// ============================================================

void showTotpCodeScreen(const char* title, const char* code, int secondsRemaining) {
  const int period    = 30;
  int       barWidth  = 180;
  int       barX      = (tft.width() - barWidth) / 2;
  int       progWidth = constrain((secondsRemaining * barWidth) / period, 0, barWidth - 4);

  tft.fillScreen(TFT_BLACK);

  // Service name
  const char* displayTitle = (strcmp(title, "Google TOTP") == 0) ? "Google" : title;
  int titleX = max(0, (tft.width() - (int)(strlen(displayTitle) * 12)) / 2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(titleX, 12);
  tft.println(displayTitle);

  // Code box
  int boxW = 200, boxH = 54;
  int boxX = (tft.width() - boxW) / 2;
  int boxY = 42;
  tft.drawRoundRect(boxX, boxY, boxW, boxH, 10, 0x39C4);

  tft.setTextColor(0xFD20, TFT_BLACK); // Gold code
  tft.setTextSize(4);
  int codeW = strlen(code) * 24;
  tft.setCursor(boxX + (boxW - codeW) / 2, boxY + (boxH - 32) / 2);
  tft.println(code);

  // Progress bar
  int barY = 112;
  tft.drawRoundRect(barX, barY, barWidth, 12, 6, 0x39C4);
  if (progWidth > 0) {
    uint16_t barColor = (secondsRemaining > 10) ? TFT_GREEN : TFT_RED;
    tft.fillRoundRect(barX + 2, barY + 2, progWidth, 8, 4, barColor);
  }

  // Countdown
  char timeText[6];
  sprintf(timeText, "%ds", secondsRemaining);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(barX + barWidth + 8, barY - 2);
  tft.print(timeText);

  // Watermark
  tft.setTextSize(1);
  tft.setTextColor(0x39C4, TFT_BLACK);
  tft.setCursor(tft.width() - 58, tft.height() - 12);
  tft.print("MKQ.ONE");
}

// ============================================================
//  Display — Boot Screen
// ============================================================

void drawBootScreen() {
  tft.fillScreen(TFT_BLACK);

  // Brand name large
  tft.setTextColor(0xFD20, TFT_BLACK);
  tft.setTextSize(3);
  const char* brand = "MKQ Vault";
  int bx = (tft.width() - (int)(strlen(brand) * 18)) / 2;
  tft.setCursor(max(0, bx), tft.height() / 2 - 20);
  tft.println(brand);

  // Subtitle
  tft.setTextSize(1);
  tft.setTextColor(0x39C4, TFT_BLACK);
  const char* sub = "mkq.one  |  secure by design";
  int sx = (tft.width() - (int)(strlen(sub) * 6)) / 2;
  tft.setCursor(max(0, sx), tft.height() / 2 + 12);
  tft.println(sub);
}

// ============================================================
//  Display — Settings Portal Screen
// ============================================================

void drawSettingsPortalScreen() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(0xFD20, TFT_BLACK);
  tft.setTextSize(2);
  const char* title = "Settings Portal";
  int tx = max(0, (tft.width() - (int)(strlen(title) * 12)) / 2);
  tft.setCursor(tx, 10);
  tft.println(title);

  tft.drawFastHLine(8, 36, tft.width() - 16, 0x39C4);

  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(16, 44);  tft.println("SSID:");
  tft.setCursor(78, 44);  tft.println("MKQ Vault");
  tft.setCursor(16, 72);  tft.println("PASS:");
  tft.setCursor(78, 72);  tft.println("Press OK");

  tft.setTextSize(1);
  tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(16, 102); tft.println("Connect to WiFi, open any page.");
  tft.setCursor(16, 114); tft.println("Hold BACK to close portal.");

  tft.setTextColor(0x39C4, TFT_BLACK);
  tft.setCursor(tft.width() - 58, tft.height() - 12);
  tft.print("MKQ.ONE");
}

// ============================================================
//  Wi-Fi — Time Sync (NTP)
// ============================================================

bool syncTimeOverWiFi() {
  WiFi.mode(WIFI_STA);
  while (true) {
    WiFi.disconnect(true);
    delay(200);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    unsigned long t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000)
      delay(250);

    if (WiFi.status() == WL_CONNECTED) {
      configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER_1, NTP_SERVER_2);
      struct tm timeinfo;
      t0 = millis();
      while (millis() - t0 < 20000) {
        if (getLocalTime(&timeinfo)) {
          WiFi.disconnect(true);
          WiFi.mode(WIFI_OFF);
          return true;
        }
        delay(250);
      }
    }
    WiFi.disconnect(true);
    delay(500);
  }
}

bool getCurrentUnixTime(time_t &unixTime) {
  time(&unixTime);
  return unixTime > 1700000000UL;
}

// ============================================================
//  Password Storage — NVS (Preferences)
// ============================================================

void refreshPasswordMenuItems() {
  for (int i = 0; i < passwordMenuCount; i++) {
    passwordMenuItems[i].name      = passwordNameValues[i];
    passwordMenuItems[i].type      = ITEM_TEXT;
    passwordMenuItems[i].textValue = passwordTextValues[i];
    passwordMenuItems[i].totp      = nullptr;
  }
}

void loadSavedPasswords() {
  prefs.begin("mkq_vault", true); // namespace changed to mkq_vault
  int storedCount = prefs.getInt("count", 4);
  storedCount     = constrain(storedCount, 1, MAX_PASSWORD_ITEMS);
  passwordMenuCount = storedCount;

  for (int i = 0; i < passwordMenuCount; i++) {
    String nk = "name" + String(i);
    String uk = "user" + String(i);
    String pk = "pass" + String(i);

    prefs.getString(nk.c_str(), passwordNameValues[i]).toCharArray(passwordNameValues[i],     sizeof(passwordNameValues[i]));
    prefs.getString(uk.c_str(), passwordUsernameValues[i]).toCharArray(passwordUsernameValues[i], sizeof(passwordUsernameValues[i]));
    prefs.getString(pk.c_str(), passwordTextValues[i]).toCharArray(passwordTextValues[i],     sizeof(passwordTextValues[i]));
  }

  prefs.end();
  refreshPasswordMenuItems();
}

void savePasswordsToPreferences() {
  prefs.begin("mkq_vault", false);
  prefs.clear();
  prefs.putInt("count", passwordMenuCount);
  for (int i = 0; i < passwordMenuCount; i++) {
    prefs.putString(("name" + String(i)).c_str(), passwordNameValues[i]);
    prefs.putString(("user" + String(i)).c_str(), passwordUsernameValues[i]);
    prefs.putString(("pass" + String(i)).c_str(), passwordTextValues[i]);
  }
  prefs.end();
}

// ============================================================
//  Settings Portal — Web UI
// ============================================================

String htmlEscape(const char* input) {
  String s = input ? input : "";
  s.replace("&", "&amp;");
  s.replace("<", "&lt;");
  s.replace(">", "&gt;");
  s.replace("\"", "&quot;");
  return s;
}

String generateApPassword() {
  const char charset[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
  String result = "";
  result.reserve(16);
  for (int i = 0; i < 16; i++)
    result += charset[esp_random() % (sizeof(charset) - 1)];
  return result;
}

void handlePortalSave();
void handlePortalDeleteNow();

void handlePortalRoot() {
  int  editIndex = -1;
  bool isEdit    = false;

  if (server.hasArg("edit")) {
    editIndex = server.arg("edit").toInt();
    if (editIndex < 0 || editIndex >= passwordMenuCount) editIndex = -1;
  }
  isEdit = (editIndex >= 0);

  String formName = "", formUser = "", formPass = "";

  if (isEdit) {
    formName = htmlEscape(passwordNameValues[editIndex]);
    formUser = htmlEscape(passwordUsernameValues[editIndex]);
  } else {
    const char cs[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    for (int i = 0; i < 16; i++)
      formPass += cs[esp_random() % (sizeof(cs) - 1)];
  }

  // ---- HTML — MKQ.ONE branded dark portal ----
  String html = "";
  html += "<!doctype html><html lang='en'><head>";
  html += "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>MKQ Vault — Settings</title>";
  html += "<style>";
  html += ":root{--bg:#080810;--surface:#0f0f1a;--border:#1e1e36;--accent:#f5c518;--accent2:#00c8ff;--text:#f0f0f0;--muted:#6b7280;--danger:#ef4444;--radius:14px;}";
  html += "*{box-sizing:border-box;margin:0;padding:0;}";
  html += "body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;min-height:100vh;padding:24px 16px;}";
  html += ".wrap{max-width:960px;margin:0 auto;}";
  // Header
  html += ".hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;border-bottom:1px solid var(--border);padding-bottom:16px;}";
  html += ".logo{font-size:22px;font-weight:700;letter-spacing:.08em;color:var(--accent);}";
  html += ".logo span{color:var(--accent2);}";
  html += ".badge{font-size:11px;color:var(--muted);border:1px solid var(--border);padding:4px 10px;border-radius:20px;}";
  // Cards
  html += ".card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px;}";
  html += ".card-title{font-size:14px;font-weight:700;letter-spacing:.12em;color:var(--accent);text-transform:uppercase;margin-bottom:18px;display:flex;align-items:center;gap:8px;}";
  html += ".card-title::before{content:'';display:inline-block;width:3px;height:14px;background:var(--accent);border-radius:2px;}";
  // Form
  html += "label{display:block;font-size:11px;font-weight:700;letter-spacing:.1em;color:var(--muted);text-transform:uppercase;margin:16px 0 6px;}";
  html += "input[type=text]{width:100%;background:#06060e;border:1px solid var(--border);color:var(--text);padding:12px 14px;border-radius:10px;font-family:inherit;font-size:14px;outline:none;transition:border .2s;}";
  html += "input[type=text]:focus{border-color:var(--accent2);}";
  html += "input[type=range]{width:100%;accent-color:var(--accent);}";
  html += ".actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px;}";
  html += ".btn{padding:11px 20px;border:none;border-radius:10px;font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;letter-spacing:.06em;text-decoration:none;display:inline-block;}";
  html += ".btn-primary{background:var(--accent);color:#000;}";
  html += ".btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border);}";
  html += ".btn-regen{background:#1a1a2e;color:var(--accent2);border:1px solid var(--accent2);}";
  // Table
  html += "table{width:100%;border-collapse:collapse;}";
  html += "th{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;}";
  html += "td{padding:14px 12px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:middle;}";
  html += "tr:last-child td{border-bottom:none;}";
  html += ".act{display:flex;gap:8px;}";
  html += ".btn-edit{padding:7px 14px;background:#1a1a2e;color:var(--accent2);border:1px solid var(--accent2);border-radius:8px;font-family:inherit;font-size:12px;text-decoration:none;font-weight:700;}";
  html += ".btn-del{padding:7px 14px;background:#1f0a0a;color:var(--danger);border:1px solid var(--danger);border-radius:8px;font-family:inherit;font-size:12px;text-decoration:none;font-weight:700;}";
  html += ".empty{color:var(--muted);font-size:13px;padding:16px 0;}";
  // Footer
  html += ".footer{text-align:center;margin-top:32px;font-size:11px;color:var(--muted);letter-spacing:.08em;}";
  html += ".footer a{color:var(--accent);text-decoration:none;}";
  html += "@media(max-width:600px){.hdr{flex-direction:column;gap:10px;} td,th{padding:10px 8px;font-size:13px;} .act{flex-direction:column;}}";
  html += "</style></head><body><div class='wrap'>";

  // Header
  html += "<div class='hdr'>";
  html += "<div class='logo'>MKQ<span>.ONE</span> &mdash; Vault</div>";
  html += "<div class='badge'>Settings Portal</div>";
  html += "</div>";

  // Add / Edit card
  html += "<div class='card'>";
  html += "<div class='card-title'>" + String(isEdit ? "Edit Entry" : "Add Entry") + "</div>";
  html += "<form method='POST' action='/save'>";
  if (isEdit) html += "<input type='hidden' name='edit_index' value='" + String(editIndex) + "'>";

  html += "<label>Name</label><input type='text' name='item_name' placeholder='e.g. Gmail' value='" + formName + "'>";
  html += "<label>Username</label><input type='text' name='item_user' placeholder='username or email' value='" + formUser + "'>";
  html += "<label>Password</label><input type='text' id='pwd' name='item_pass' placeholder='" + String(isEdit ? "Leave blank to keep current" : "Enter or generate") + "' value='" + formPass + "'>";

  // Generator
  html += "<div style='margin-top:14px;'>";
  html += "<div style='font-size:12px;color:var(--muted);margin-bottom:6px;'>Length: <span id='lv'>16</span></div>";
  html += "<input type='range' id='lr' min='4' max='64' value='16'>";
  html += "<div style='display:flex;justify-content:space-between;font-size:10px;color:var(--muted);margin-top:2px;'><span>4</span><span>64</span></div>";
  html += "</div>";

  html += "<div class='actions'>";
  html += "<button class='btn btn-primary' type='submit'>" + String(isEdit ? "Save Changes" : "Add Password") + "</button>";
  html += "<button class='btn btn-regen' type='button' onclick='gen()'>&#8635; Regenerate</button>";
  if (isEdit) html += "<a class='btn btn-ghost' href='/'>Cancel</a>";
  html += "</div></form></div>";

  // Saved passwords table
  html += "<div class='card'><div class='card-title'>Saved Passwords</div>";
  if (passwordMenuCount == 0) {
    html += "<p class='empty'>No entries yet.</p>";
  } else {
    html += "<table><tr><th>Name</th><th>Username</th><th>Actions</th></tr>";
    for (int i = 0; i < passwordMenuCount; i++) {
      html += "<tr><td>" + htmlEscape(passwordNameValues[i]) + "</td>";
      html += "<td>" + htmlEscape(passwordUsernameValues[i]) + "</td>";
      html += "<td><div class='act'>";
      html += "<a class='btn-edit' href='/?edit=" + String(i) + "'>Edit</a>";
      html += "<a class='btn-del' href='/delete_now?index=" + String(i) + "&ts=" + String(millis()) + "'>Delete</a>";
      html += "</div></td></tr>";
    }
    html += "</table>";
  }
  html += "</div>";

  // Footer
  html += "<div class='footer'><a href='https://mkq.one'>mkq.one</a> &nbsp;&mdash;&nbsp; Secure by design</div>";

  html += "</div>"; // wrap

  // Inline JS
  html += "<script>";
  html += "const cs='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';";
  html += "function gen(){var l=parseInt(document.getElementById('lr').value)||16;var s='';for(var i=0;i<l;i++){s+=cs[Math.floor(Math.random()*cs.length)];}document.getElementById('pwd').value=s;document.getElementById('lv').textContent=l;}";
  html += "document.addEventListener('DOMContentLoaded',function(){var r=document.getElementById('lr'),v=document.getElementById('lv');if(r&&v){v.textContent=r.value;r.addEventListener('input',function(){v.textContent=this.value;});}});";
  html += "</script></body></html>";

  server.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  server.sendHeader("Pragma",        "no-cache");
  server.sendHeader("Expires",       "-1");
  server.send(200, "text/html", html);
}

void handlePortalSave() {
  String name = server.arg("item_name"); name.trim();
  String user = server.arg("item_user"); user.trim();
  String pass = server.arg("item_pass"); pass.trim();

  if (name.length() == 0) {
    server.send(200, "text/html",
      "<!doctype html><html><body style='background:#080810;color:#f0f0f0;font-family:monospace;padding:24px;'>"
      "<h2 style='color:#ef4444;'>Name is required</h2><p><a href='/' style='color:#f5c518;'>Go back</a></p></body></html>");
    return;
  }

  int target = -1;
  if (server.hasArg("edit_index")) {
    target = server.arg("edit_index").toInt();
    if (target < 0 || target >= passwordMenuCount) target = -1;
  }

  if (target >= 0) {
    name.toCharArray(passwordNameValues[target], sizeof(passwordNameValues[target]));
    user.toCharArray(passwordUsernameValues[target], sizeof(passwordUsernameValues[target]));
    if (pass.length() > 0)
      pass.toCharArray(passwordTextValues[target], sizeof(passwordTextValues[target]));
  } else {
    if (pass.length() == 0) {
      server.send(200, "text/html",
        "<!doctype html><html><body style='background:#080810;color:#f0f0f0;font-family:monospace;padding:24px;'>"
        "<h2 style='color:#ef4444;'>Password required for new entry</h2><p><a href='/' style='color:#f5c518;'>Go back</a></p></body></html>");
      return;
    }
    if (passwordMenuCount >= MAX_PASSWORD_ITEMS) {
      server.send(200, "text/html",
        "<!doctype html><html><body style='background:#080810;color:#f0f0f0;font-family:monospace;padding:24px;'>"
        "<h2 style='color:#ef4444;'>Storage full (max 12 entries)</h2><p><a href='/' style='color:#f5c518;'>Go back</a></p></body></html>");
      return;
    }
    name.toCharArray(passwordNameValues[passwordMenuCount], sizeof(passwordNameValues[passwordMenuCount]));
    user.toCharArray(passwordUsernameValues[passwordMenuCount], sizeof(passwordUsernameValues[passwordMenuCount]));
    pass.toCharArray(passwordTextValues[passwordMenuCount], sizeof(passwordTextValues[passwordMenuCount]));
    passwordMenuCount++;
  }

  refreshPasswordMenuItems();
  savePasswordsToPreferences();
  handlePortalRoot();
}

void handlePortalDeleteNow() {
  if (!server.hasArg("index")) { handlePortalRoot(); return; }
  int idx = server.arg("index").toInt();
  if (idx < 0 || idx >= passwordMenuCount) { handlePortalRoot(); return; }

  for (int i = idx; i < passwordMenuCount - 1; i++) {
    strlcpy(passwordNameValues[i],     passwordNameValues[i+1],     sizeof(passwordNameValues[i]));
    strlcpy(passwordUsernameValues[i], passwordUsernameValues[i+1], sizeof(passwordUsernameValues[i]));
    strlcpy(passwordTextValues[i],     passwordTextValues[i+1],     sizeof(passwordTextValues[i]));
  }
  passwordMenuCount = max(0, passwordMenuCount - 1);

  selectedIndex = constrain(selectedIndex, 0, max(0, passwordMenuCount - 1));
  refreshPasswordMenuItems();
  savePasswordsToPreferences();
  handlePortalRoot();
}

// ============================================================
//  Settings Portal — Start / Stop
// ============================================================

void stopSettingsPortal() {
  if (!settingsPortalActive) return;
  dnsServer.stop();
  server.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  settingsPortalActive = false;
}

void startSettingsPortal() {
  stopSettingsPortal();
  WiFi.disconnect(true, true);
  WiFi.softAPdisconnect(true);
  delay(200);
  WiFi.mode(WIFI_AP);
  delay(100);

  bool ok = WiFi.softAP("MKQ Vault", settingsApPassword.c_str());
  delay(300);

  if (!ok) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.setTextSize(2);
    tft.setCursor(20, 40); tft.println("AP Start Failed");
    tft.setTextSize(1);
    tft.setCursor(20, 75); tft.println("Check AP password length");
    delay(1200);
    currentScreen = SCREEN_MAIN;
    drawMenu();
    return;
  }

  server.stop();
  dnsServer.stop();
  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());

  server.on("/",                     HTTP_GET,  handlePortalRoot);
  server.on("/generate_204",         HTTP_GET,  handlePortalRoot);
  server.on("/hotspot-detect.html",  HTTP_GET,  handlePortalRoot);
  server.on("/ncsi.txt",             HTTP_GET,  handlePortalRoot);
  server.on("/save",                 HTTP_POST, handlePortalSave);
  server.on("/delete_now",           HTTP_GET,  handlePortalDeleteNow);
  server.onNotFound(handlePortalRoot);
  server.begin();

  settingsPortalActive = true;
  drawSettingsPortalScreen();
}

void processSettingsPortal() {
  if (!settingsPortalActive) return;
  dnsServer.processNextRequest();
  server.handleClient();
}

// ============================================================
//  Navigation
// ============================================================

void moveUp() {
  int n = getCurrentMenuCount();
  selectedIndex = (selectedIndex - 1 + n) % n;
  drawMenu();
}

void moveDown() {
  int n = getCurrentMenuCount();
  selectedIndex = (selectedIndex + 1) % n;
  drawMenu();
}

void sendSelectedItem() {
  MenuItem* items = getCurrentMenuItems();
  MenuItem& item  = items[selectedIndex];

  // TOTP view — send code
  if (currentScreen == SCREEN_TOTP_VIEW) {
    time_t now;
    if (!getCurrentUnixTime(now)) return;
    Keyboard.print(totpMenuItems[activeTotpIndex].totp->getCode(now));
    return;
  }

  // Settings portal — send AP password
  if (settingsPortalActive) {
    Keyboard.print(settingsApPassword);
    return;
  }

  // Password actions — send credentials
  if (currentScreen == SCREEN_PASSWORD_ACTIONS) {
    showSendingScreen(passwordMenuItems[activePasswordIndex].name);
    delay(250);
    switch (selectedIndex) {
      case 0: // Username only
        Keyboard.print(passwordUsernameValues[activePasswordIndex]);
        break;
      case 1: // Password only
        Keyboard.print(passwordTextValues[activePasswordIndex]);
        break;
      case 2: // User + Tab + Pass
        Keyboard.print(passwordUsernameValues[activePasswordIndex]);
        Keyboard.write(KEY_TAB);
        Keyboard.print(passwordTextValues[activePasswordIndex]);
        break;
    }
    delay(400);
    drawMenu();
    return;
  }

  // Main menu navigation
  if (item.type == ITEM_SUBMENU && currentScreen == SCREEN_MAIN) {
    if (selectedIndex == 0) {
      currentScreen = SCREEN_PASSWORDS;
      selectedIndex = menuScrollOffset = 0;
      drawMenu();
    } else if (selectedIndex == 1) {
      if (!timeSynced) {
        showStatusScreen("Connecting WiFi", "TOTP");
        syncTimeOverWiFi();
        timeSynced = true;
      }
      activeTotpIndex = 0;
      currentScreen   = SCREEN_TOTP_VIEW;
      lastTotpRedraw  = 0;
    } else if (selectedIndex == 2) {
      selectedIndex = menuScrollOffset = 0;
      startSettingsPortal();
    }
    return;
  }

  // Password list — enter actions
  if (item.type == ITEM_TEXT) {
    activePasswordIndex = selectedIndex;
    currentScreen       = SCREEN_PASSWORD_ACTIONS;
    selectedIndex       = menuScrollOffset = 0;
    drawMenu();
    return;
  }

  // TOTP entry
  if (item.type == ITEM_TOTP) {
    if (!timeSynced) {
      showStatusScreen("Connecting WiFi", item.name);
      syncTimeOverWiFi();
      timeSynced = true;
    }
    activeTotpIndex = selectedIndex;
    currentScreen   = SCREEN_TOTP_VIEW;
    lastTotpRedraw  = 0;
  }
}

// ============================================================
//  Arduino Entry Points
// ============================================================

void setup() {
  pinMode(BTN_OK_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN,  INPUT_PULLUP);

  settingsApPassword = generateApPassword();
  loadSavedPasswords();

  tft.init();
  tft.setRotation(1);

  if (!initTotp()) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_RED, TFT_BLACK);
    tft.setTextSize(2);
    tft.setCursor(20, 40); tft.println("TOTP Init Error");
    tft.setTextSize(1);
    tft.setCursor(20, 75); tft.println("Check Base32 secret");
    while (true) delay(1000);
  }

  totpMenuItems[0].totp = gmailTotp;

  drawBootScreen();
  delay(1400);
  drawMenu();

  Keyboard.begin();
  USB.begin();
  delay(USB_STARTUP_DELAY);
}

void loop() {
  processSettingsPortal();

  bool okUpState = digitalRead(BTN_OK_UP);
  bool downState = digitalRead(BTN_DOWN);
  unsigned long nowMs = millis();

  // ---- TOTP live refresh ----
  if (currentScreen == SCREEN_TOTP_VIEW) {
    time_t now;
    if (getCurrentUnixTime(now)) {
      int secsLeft = 30 - (int)(now % 30);
      if (secsLeft == 30) secsLeft = 0;
      if (lastTotpRedraw != (unsigned long)now) {
        char* code = totpMenuItems[activeTotpIndex].totp->getCode(now);
        showTotpCodeScreen(totpMenuItems[activeTotpIndex].name, code, secsLeft);
        lastTotpRedraw = (unsigned long)now;
      }
    }
  }

  // ---- OK/UP button ----
  if (okUpState == LOW) {
    if (!btnPressed) {
      btnPressed     = true;
      btnPressStart  = nowMs;
      holdTriggered  = false;
    } else if (!holdTriggered && (nowMs - btnPressStart >= HOLD_TIME_MS)) {
      holdTriggered = true;
      sendSelectedItem();
    }
  } else {
    if (btnPressed && !holdTriggered) {
      if (currentScreen != SCREEN_TOTP_VIEW && !settingsPortalActive)
        moveDown();
    }
    btnPressed    = false;
    holdTriggered = false;
  }

  // ---- DOWN/BACK button ----
  if (downState == LOW) {
    if (lastDownState == HIGH) {
      lastDownPress   = nowMs;
      downHoldHandled = false;
    }
    if (!downHoldHandled && (nowMs - lastDownPress >= HOLD_TIME_MS)) {
      downHoldHandled = true;
      // Hold = go back
      if (currentScreen == SCREEN_TOTP_VIEW) {
        currentScreen = SCREEN_TOTP;
        selectedIndex = menuScrollOffset = 0;
        drawMenu();
      } else if (currentScreen == SCREEN_PASSWORD_ACTIONS) {
        currentScreen = SCREEN_PASSWORDS;
        selectedIndex = activePasswordIndex;
        drawMenu();
      } else if (settingsPortalActive) {
        stopSettingsPortal();
        currentScreen = SCREEN_MAIN;
        selectedIndex = menuScrollOffset = 0;
        drawMenu();
      } else if (currentScreen != SCREEN_MAIN) {
        currentScreen = SCREEN_MAIN;
        selectedIndex = menuScrollOffset = 0;
        drawMenu();
      }
    }
  } else {
    if (lastDownState == LOW && !downHoldHandled && (nowMs - lastDownPress < HOLD_TIME_MS)) {
      if (currentScreen != SCREEN_TOTP_VIEW && !settingsPortalActive)
        moveUp();
    }
    downHoldHandled = false;
  }

  lastDownState = downState;
  delay(20);
}
