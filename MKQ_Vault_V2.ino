// ============================================================
//  MKQ.ONE — MKQ Vault  v2
//  Hardware Password Manager | ESP32-S3
//  mkq.one
//
//  Features:
//   - Multi-TOTP (up to 12 entries, stored in NVS)
//   - Backup & Restore via JSON over Wi-Fi portal
//   - Bluetooth HID keyboard (BLE) in addition to USB HID
// ============================================================

// ===== Wi-Fi Config (used only for NTP time sync) =====
const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// ===== Libraries =====
#include <TFT_eSPI.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <time.h>
#include <TOTP.h>
#include "USB.h"
#include "USBHIDKeyboard.h"
// Bluetooth HID — uses NimBLE-Arduino (install via Library Manager)
#include <NimBLEDevice.h>
#include <NimBLEHIDDevice.h>
#include <NimBLECharacteristic.h>

// ============================================================
//  Global Objects
// ============================================================
TFT_eSPI       tft = TFT_eSPI();
USBHIDKeyboard UsbKeyboard;
WebServer      server(80);
DNSServer      dnsServer;
Preferences    prefs;

// BLE HID
NimBLEHIDDevice*       bleHid        = nullptr;
NimBLECharacteristic*  bleInput      = nullptr;
NimBLECharacteristic*  bleInputMedia = nullptr;
bool                   bleConnected  = false;

// ============================================================
//  Hardware Pins
// ============================================================
#define BTN_OK_UP  0
#define BTN_DOWN   14

// ============================================================
//  NTP / Time
// ============================================================
const char* NTP_SERVER_1        = "pool.ntp.org";
const char* NTP_SERVER_2        = "time.google.com";
const long  GMT_OFFSET_SEC      = 3 * 3600;   // GMT+3
const int   DAYLIGHT_OFFSET_SEC = 0;

// ============================================================
//  Timing
// ============================================================
const unsigned long HOLD_TIME_MS      = 700;
const unsigned long USB_STARTUP_DELAY = 800;
const byte          DNS_PORT          = 53;

// ============================================================
//  Limits
// ============================================================
const int MAX_PASSWORD_ITEMS = 12;
const int MAX_TOTP_ITEMS     = 12;

// ============================================================
//  Password Storage
// ============================================================
int  passwordMenuCount = 0;
char passwordNameValues    [MAX_PASSWORD_ITEMS][32]  = {};
char passwordUsernameValues[MAX_PASSWORD_ITEMS][128] = {};
char passwordTextValues    [MAX_PASSWORD_ITEMS][128] = {};

// ============================================================
//  TOTP Storage
// ============================================================
int    totpCount = 0;
char   totpNames  [MAX_TOTP_ITEMS][32]  = {};
char   totpSecretB32[MAX_TOTP_ITEMS][65] = {};  // raw base32 strings saved

uint8_t totpSecretBytes[MAX_TOTP_ITEMS][64] = {};
size_t  totpSecretLens [MAX_TOTP_ITEMS]     = {};
TOTP*   totpObjects    [MAX_TOTP_ITEMS]     = {};

// ============================================================
//  Menu System
// ============================================================
enum ItemType {
  ITEM_SUBMENU,
  ITEM_TEXT,
  ITEM_TOTP,
  ITEM_INFO
};

struct MenuItem {
  const char* name;
  ItemType    type;
  TOTP*       totp;
};

enum MenuScreen {
  SCREEN_MAIN,
  SCREEN_PASSWORDS,
  SCREEN_PASSWORD_ACTIONS,
  SCREEN_TOTP,
  SCREEN_TOTP_VIEW,
  SCREEN_SETTINGS,
  SCREEN_SEND_MODE   // USB vs BT selection
};

MenuScreen currentScreen    = SCREEN_MAIN;
int        selectedIndex    = 0;
int        menuScrollOffset = 0;

// Send mode: 0 = USB, 1 = Bluetooth
int sendMode = 0;

MenuItem mainMenuItems[] = {
  {"Passwords", ITEM_SUBMENU, nullptr},
  {"TOTP",      ITEM_SUBMENU, nullptr},
  {"Settings",  ITEM_SUBMENU, nullptr}
};

MenuItem passwordMenuItems   [MAX_PASSWORD_ITEMS];
MenuItem totpMenuItems       [MAX_TOTP_ITEMS];

MenuItem passwordActionMenuItems[] = {
  {"Username",      ITEM_INFO, nullptr},
  {"Password",      ITEM_INFO, nullptr},
  {"User+Tab+Pass", ITEM_INFO, nullptr}
};

MenuItem sendModeMenuItems[] = {
  {"USB  (wired)",     ITEM_INFO, nullptr},
  {"Bluetooth (BLE)",  ITEM_INFO, nullptr}
};

MenuItem settingsMenuItems[] = {};

// ============================================================
//  Active State
// ============================================================
bool          timeSynced           = false;
int           activeTotpIndex      = 0;
unsigned long lastTotpRedraw       = 0;
bool          settingsPortalActive = false;
String        settingsApPassword;
int           activePasswordIndex  = 0;

// ============================================================
//  Button State
// ============================================================
bool          lastDownState   = HIGH;
bool          btnPressed      = false;
bool          holdTriggered   = false;
unsigned long btnPressStart   = 0;
unsigned long lastDownPress   = 0;
bool          downHoldHandled = false;

// ============================================================
//  Menu Routing
// ============================================================
MenuItem* getCurrentMenuItems() {
  switch (currentScreen) {
    case SCREEN_PASSWORDS:        return passwordMenuItems;
    case SCREEN_PASSWORD_ACTIONS: return passwordActionMenuItems;
    case SCREEN_TOTP:             return totpMenuItems;
    case SCREEN_SETTINGS:         return settingsMenuItems;
    case SCREEN_SEND_MODE:        return sendModeMenuItems;
    default:                      return mainMenuItems;
  }
}

int getCurrentMenuCount() {
  switch (currentScreen) {
    case SCREEN_PASSWORDS:        return passwordMenuCount;
    case SCREEN_PASSWORD_ACTIONS: return 3;
    case SCREEN_TOTP:             return totpCount;
    case SCREEN_SETTINGS:         return 0;
    case SCREEN_SEND_MODE:        return 2;
    default:                      return 3; // main: Passwords / TOTP / Settings
  }
}

const char* getScreenTitle() {
  switch (currentScreen) {
    case SCREEN_PASSWORDS:        return "Passwords";
    case SCREEN_PASSWORD_ACTIONS: return "Send As";
    case SCREEN_TOTP:             return "TOTP";
    case SCREEN_TOTP_VIEW:        return "TOTP";
    case SCREEN_SETTINGS:         return "Settings";
    case SCREEN_SEND_MODE:        return "Send Via";
    default:                      return "MKQ Vault";
  }
}

// ============================================================
//  Base32 Decoder
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

// ============================================================
//  TOTP — Init from stored secrets
// ============================================================
void initAllTotp() {
  for (int i = 0; i < totpCount; i++) {
    if (totpObjects[i]) { delete totpObjects[i]; totpObjects[i] = nullptr; }
    totpSecretLens[i] = decodeBase32(totpSecretB32[i], totpSecretBytes[i], 64);
    if (totpSecretLens[i] > 0) {
      totpObjects[i] = new TOTP(totpSecretBytes[i], totpSecretLens[i]);
      totpMenuItems[i].name = totpNames[i];
      totpMenuItems[i].type = ITEM_TOTP;
      totpMenuItems[i].totp = totpObjects[i];
    }
  }
}

// ============================================================
//  NVS — Load / Save Passwords
// ============================================================
void refreshPasswordMenuItems() {
  for (int i = 0; i < passwordMenuCount; i++) {
    passwordMenuItems[i].name = passwordNameValues[i];
    passwordMenuItems[i].type = ITEM_TEXT;
    passwordMenuItems[i].totp = nullptr;
  }
}

void loadSavedPasswords() {
  prefs.begin("mkq_pw", true);
  int n = constrain(prefs.getInt("count", 0), 0, MAX_PASSWORD_ITEMS);
  passwordMenuCount = n;
  for (int i = 0; i < n; i++) {
    prefs.getString(("n" + String(i)).c_str(), "").toCharArray(passwordNameValues[i],     32);
    prefs.getString(("u" + String(i)).c_str(), "").toCharArray(passwordUsernameValues[i], 128);
    prefs.getString(("p" + String(i)).c_str(), "").toCharArray(passwordTextValues[i],     128);
  }
  prefs.end();
  refreshPasswordMenuItems();
}

void savePasswords() {
  prefs.begin("mkq_pw", false);
  prefs.clear();
  prefs.putInt("count", passwordMenuCount);
  for (int i = 0; i < passwordMenuCount; i++) {
    prefs.putString(("n" + String(i)).c_str(), passwordNameValues[i]);
    prefs.putString(("u" + String(i)).c_str(), passwordUsernameValues[i]);
    prefs.putString(("p" + String(i)).c_str(), passwordTextValues[i]);
  }
  prefs.end();
}

// ============================================================
//  NVS — Load / Save TOTP
// ============================================================
void loadSavedTotp() {
  prefs.begin("mkq_totp", true);
  int n = constrain(prefs.getInt("count", 0), 0, MAX_TOTP_ITEMS);
  totpCount = n;
  for (int i = 0; i < n; i++) {
    prefs.getString(("n" + String(i)).c_str(), "").toCharArray(totpNames[i],      32);
    prefs.getString(("s" + String(i)).c_str(), "").toCharArray(totpSecretB32[i],  65);
  }
  prefs.end();
  initAllTotp();
}

void saveTotp() {
  prefs.begin("mkq_totp", false);
  prefs.clear();
  prefs.putInt("count", totpCount);
  for (int i = 0; i < totpCount; i++) {
    prefs.putString(("n" + String(i)).c_str(), totpNames[i]);
    prefs.putString(("s" + String(i)).c_str(), totpSecretB32[i]);
  }
  prefs.end();
}

// ============================================================
//  Bluetooth HID
// ============================================================

// HID report descriptor — standard keyboard
static const uint8_t hidReportDesc[] = {
  0x05, 0x01,  // Usage Page (Generic Desktop)
  0x09, 0x06,  // Usage (Keyboard)
  0xA1, 0x01,  // Collection (Application)
  0x85, 0x01,  //   Report ID 1
  0x05, 0x07,  //   Usage Page (Key Codes)
  0x19, 0xe0,  //   Usage Minimum (224)
  0x29, 0xe7,  //   Usage Maximum (231)
  0x15, 0x00,  //   Logical Minimum (0)
  0x25, 0x01,  //   Logical Maximum (1)
  0x75, 0x01,  //   Report Size (1)
  0x95, 0x08,  //   Report Count (8)
  0x81, 0x02,  //   Input (Data, Variable, Absolute) -- modifier keys
  0x95, 0x01,  //   Report Count (1)
  0x75, 0x08,  //   Report Size (8)
  0x81, 0x01,  //   Input (Constant) -- reserved
  0x95, 0x06,  //   Report Count (6)
  0x75, 0x08,  //   Report Size (8)
  0x15, 0x00,  //   Logical Minimum (0)
  0x25, 0x65,  //   Logical Maximum (101)
  0x05, 0x07,  //   Usage Page (Key Codes)
  0x19, 0x00,  //   Usage Minimum (0)
  0x29, 0x65,  //   Usage Maximum (101)
  0x81, 0x00,  //   Input (Data, Array) -- key codes
  0xC0         // End Collection
};

// Map ASCII printable chars to HID keycodes (US layout)
struct HidKey { uint8_t mod; uint8_t key; };

HidKey asciiToHid(char c) {
  // lowercase a-z
  if (c >= 'a' && c <= 'z') return {0x00, (uint8_t)(0x04 + c - 'a')};
  // uppercase A-Z
  if (c >= 'A' && c <= 'Z') return {0x02, (uint8_t)(0x04 + c - 'A')};
  // digits 1-9, 0
  if (c >= '1' && c <= '9') return {0x00, (uint8_t)(0x1E + c - '1')};
  if (c == '0') return {0x00, 0x27};
  // common symbols
  switch (c) {
    case ' ':  return {0x00, 0x2C};
    case '\t': return {0x00, 0x2B};
    case '\n': return {0x00, 0x28};
    case '!':  return {0x02, 0x1E};
    case '@':  return {0x02, 0x1F};
    case '#':  return {0x02, 0x20};
    case '$':  return {0x02, 0x21};
    case '%':  return {0x02, 0x22};
    case '^':  return {0x02, 0x23};
    case '&':  return {0x02, 0x24};
    case '*':  return {0x02, 0x25};
    case '(':  return {0x02, 0x26};
    case ')':  return {0x02, 0x27};
    case '-':  return {0x00, 0x2D};
    case '_':  return {0x02, 0x2D};
    case '=':  return {0x00, 0x2E};
    case '+':  return {0x02, 0x2E};
    case '[':  return {0x00, 0x2F};
    case '{':  return {0x02, 0x2F};
    case ']':  return {0x00, 0x30};
    case '}':  return {0x02, 0x30};
    case '\\': return {0x00, 0x31};
    case '|':  return {0x02, 0x31};
    case ';':  return {0x00, 0x33};
    case ':':  return {0x02, 0x33};
    case '\'': return {0x00, 0x34};
    case '"':  return {0x02, 0x34};
    case '`':  return {0x00, 0x35};
    case '~':  return {0x02, 0x35};
    case ',':  return {0x00, 0x36};
    case '<':  return {0x02, 0x36};
    case '.':  return {0x00, 0x37};
    case '>':  return {0x02, 0x37};
    case '/':  return {0x00, 0x38};
    case '?':  return {0x02, 0x38};
    default:   return {0x00, 0x00};
  }
}

void bleSendChar(char c) {
  if (!bleConnected || !bleInput) return;
  HidKey k = asciiToHid(c);
  if (k.key == 0x00 && k.mod == 0x00) return;
  uint8_t report[8] = {k.mod, 0x00, k.key, 0,0,0,0,0};
  bleInput->setValue(report, 8);
  bleInput->notify();
  delay(8);
  uint8_t release[8] = {0};
  bleInput->setValue(release, 8);
  bleInput->notify();
  delay(8);
}

void bleSendTab() {
  if (!bleConnected || !bleInput) return;
  uint8_t report[8]  = {0x00, 0x00, 0x2B, 0,0,0,0,0};
  uint8_t release[8] = {0};
  bleInput->setValue(report, 8);   bleInput->notify(); delay(8);
  bleInput->setValue(release, 8);  bleInput->notify(); delay(8);
}

void blePrint(const char* str) {
  while (*str) bleSendChar(*str++);
}

// ---- BLE server callbacks ----
class BleServerCallbacks : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* s)    override { bleConnected = true;  }
  void onDisconnect(NimBLEServer* s) override {
    bleConnected = false;
    NimBLEDevice::startAdvertising();
  }
};

void initBLE() {
  NimBLEDevice::init("MKQ Vault");
  NimBLEDevice::setSecurityAuth(true, true, true);
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  NimBLEServer* bleServer = NimBLEDevice::createServer();
  bleServer->setCallbacks(new BleServerCallbacks());

  bleHid = new NimBLEHIDDevice(bleServer);
  bleHid->manufacturer("MKQ.ONE");
  bleHid->pnp(0x02, 0x045E, 0x0750, 0x0300);
  bleHid->hidInfo(0x00, 0x02);

  bleInput = bleHid->inputReport(1);
  bleHid->reportMap((uint8_t*)hidReportDesc, sizeof(hidReportDesc));
  bleHid->startServices();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->setAppearance(HID_KEYBOARD);
  adv->addServiceUUID(bleHid->hidService()->getUUID());
  adv->start();
}

// ============================================================
//  Keyboard Send (routes to USB or BLE based on sendMode)
// ============================================================
void kbPrint(const char* str) {
  if (sendMode == 1) blePrint(str);
  else               UsbKeyboard.print(str);
}

void kbTab() {
  if (sendMode == 1) bleSendTab();
  else               UsbKeyboard.write(KEY_TAB);
}

// ============================================================
//  Display Helpers
// ============================================================
void drawWatermark() {
  tft.setTextSize(1);
  tft.setTextColor(0x39C4, TFT_BLACK);
  tft.setCursor(tft.width() - 58, tft.height() - 12);
  tft.print("MKQ.ONE");
}

void drawMenu() {
  tft.fillScreen(TFT_BLACK);

  // Mode indicator top-right
  tft.setTextSize(1);
  tft.setTextColor(sendMode == 1 ? 0x07FF : 0xFD20, TFT_BLACK);
  tft.setCursor(tft.width() - 30, 8);
  tft.print(sendMode == 1 ? "BLE" : "USB");

  // Title
  tft.setTextColor(0xFD20, TFT_BLACK);
  tft.setTextSize(3);
  tft.setCursor(12, 10);
  tft.println(getScreenTitle());
  tft.drawFastHLine(8, 46, tft.width() - 16, 0x39C4);
  tft.setTextSize(2);

  MenuItem* items     = getCurrentMenuItems();
  int       itemCount = getCurrentMenuCount();

  const int startY      = 55;
  const int lineHeight  = 28;
  const int visibleItems = 4;

  if (selectedIndex < menuScrollOffset) menuScrollOffset = selectedIndex;
  if (selectedIndex >= menuScrollOffset + visibleItems) menuScrollOffset = selectedIndex - visibleItems + 1;
  if (menuScrollOffset < 0) menuScrollOffset = 0;
  if (itemCount <= visibleItems) menuScrollOffset = 0;

  int endIndex = min(menuScrollOffset + visibleItems, itemCount);
  int y = startY;

  for (int i = menuScrollOffset; i < endIndex; i++) {
    if (i == selectedIndex) {
      tft.fillRect(8, y - 3, tft.width() - 16, 24, 0x1082);
      tft.setTextColor(0xFD20, 0x1082);
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

  tft.setTextSize(1);
  if (menuScrollOffset > 0) { tft.setTextColor(0xFD20, TFT_BLACK); tft.setCursor(tft.width()-14, 48);  tft.print("^"); }
  if (endIndex < itemCount) { tft.setTextColor(0xFD20, TFT_BLACK); tft.setCursor(tft.width()-14, 120); tft.print("v"); }
  drawWatermark();
}

void showSendingScreen(const char* label) {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(0x07FF, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(20, 30);
  tft.println("Sending...");
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(1);
  tft.setCursor(20, 60);
  tft.println(label);
  tft.setCursor(20, 76);
  tft.setTextColor(sendMode == 1 ? 0x07FF : 0xFD20, TFT_BLACK);
  tft.print(sendMode == 1 ? "via Bluetooth" : "via USB");
  drawWatermark();
}

void showStatusScreen(const char* title, const char* sub) {
  tft.fillScreen(TFT_BLACK);
  int tw = strlen(title) * 12;
  int tx = max(0, (tft.width() - tw) / 2);
  tft.setTextColor(0xFD20, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(tx, tft.height()/2 - 20);
  tft.println(title);
  const char* dots = "..........";
  int dl = strlen(dots);
  int phase = (millis()/180) % ((dl*2)-2);
  int vis = (phase < dl) ? (phase+1) : ((dl*2)-phase-1);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setCursor(max(0,(tft.width()-vis*12)/2), tft.height()/2+10);
  for (int i=0;i<vis;i++) tft.print('.');
}

void showTotpCodeScreen(const char* title, const char* code, int secsLeft) {
  int barW = 180, barX = (tft.width()-barW)/2;
  int progW = constrain((secsLeft * barW) / 30, 0, barW-4);

  tft.fillScreen(TFT_BLACK);

  // Truncate title for display
  char disp[14]; strncpy(disp, title, 13); disp[13] = 0;
  int tx = max(0, (tft.width()-(int)(strlen(disp)*12))/2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setTextSize(2);
  tft.setCursor(tx, 12); tft.println(disp);

  int boxW=200, boxH=54, boxX=(tft.width()-boxW)/2, boxY=42;
  tft.drawRoundRect(boxX, boxY, boxW, boxH, 10, 0x39C4);
  tft.setTextColor(0xFD20, TFT_BLACK); tft.setTextSize(4);
  int cw = strlen(code)*24;
  tft.setCursor(boxX+(boxW-cw)/2, boxY+(boxH-32)/2); tft.println(code);

  int barY = 112;
  tft.drawRoundRect(barX, barY, barW, 12, 6, 0x39C4);
  if (progW > 0) tft.fillRoundRect(barX+2, barY+2, progW, 8, 4, secsLeft>10?TFT_GREEN:TFT_RED);

  char tt[6]; sprintf(tt,"%ds",secsLeft);
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setTextSize(2);
  tft.setCursor(barX+barW+8, barY-2); tft.print(tt);
  drawWatermark();
}

void drawBootScreen() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(0xFD20, TFT_BLACK); tft.setTextSize(3);
  const char* brand = "MKQ Vault";
  int bx = max(0,(tft.width()-(int)(strlen(brand)*18))/2);
  tft.setCursor(bx, tft.height()/2-20); tft.println(brand);
  tft.setTextSize(1); tft.setTextColor(0x39C4, TFT_BLACK);
  const char* sub = "mkq.one  |  secure by design";
  int sx = max(0,(tft.width()-(int)(strlen(sub)*6))/2);
  tft.setCursor(sx, tft.height()/2+12); tft.println(sub);
}

void drawSettingsPortalScreen() {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(0xFD20, TFT_BLACK); tft.setTextSize(2);
  const char* title = "Settings Portal";
  tft.setCursor(max(0,(tft.width()-(int)(strlen(title)*12))/2), 10); tft.println(title);
  tft.drawFastHLine(8,36,tft.width()-16,0x39C4);
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setTextSize(2);
  tft.setCursor(16,44); tft.println("SSID:"); tft.setCursor(78,44); tft.println("MKQ Vault");
  tft.setCursor(16,72); tft.println("PASS:"); tft.setCursor(78,72); tft.println("Press OK");
  tft.setTextSize(1); tft.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  tft.setCursor(16,102); tft.println("Connect to WiFi, open any page.");
  tft.setCursor(16,114); tft.println("Hold BACK to close portal.");
  drawWatermark();
}

// ============================================================
//  Wi-Fi — NTP Time Sync
// ============================================================
bool syncTimeOverWiFi() {
  WiFi.mode(WIFI_STA);
  while (true) {
    WiFi.disconnect(true); delay(200);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    unsigned long t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis()-t0 < 20000) delay(250);
    if (WiFi.status() == WL_CONNECTED) {
      configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER_1, NTP_SERVER_2);
      struct tm ti; t0 = millis();
      while (millis()-t0 < 20000) {
        if (getLocalTime(&ti)) { WiFi.disconnect(true); WiFi.mode(WIFI_OFF); return true; }
        delay(250);
      }
    }
    WiFi.disconnect(true); delay(500);
  }
}

bool getCurrentUnixTime(time_t &t) {
  time(&t); return t > 1700000000UL;
}

// ============================================================
//  Helpers
// ============================================================
String htmlEscape(const char* s) {
  String r = s ? s : "";
  r.replace("&","&amp;"); r.replace("<","&lt;"); r.replace(">","&gt;"); r.replace("\"","&quot;");
  return r;
}

String generateApPassword() {
  const char cs[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
  String r = ""; r.reserve(16);
  for (int i=0;i<16;i++) r += cs[esp_random()%(sizeof(cs)-1)];
  return r;
}

// ============================================================
//  Portal — common CSS + header helper (reduces html string duplication)
// ============================================================
String portalCSS() {
  String s = "";
  s += ":root{--bg:#080810;--surface:#0f0f1a;--border:#1e1e36;--accent:#f5c518;--accent2:#00c8ff;--text:#f0f0f0;--muted:#6b7280;--danger:#ef4444;--radius:14px;}";
  s += "*{box-sizing:border-box;margin:0;padding:0;}";
  s += "body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;min-height:100vh;padding:24px 16px;}";
  s += ".wrap{max-width:980px;margin:0 auto;}";
  s += ".hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;border-bottom:1px solid var(--border);padding-bottom:16px;}";
  s += ".logo{font-size:22px;font-weight:700;letter-spacing:.08em;color:var(--accent);}.logo span{color:var(--accent2);}";
  s += ".badge{font-size:11px;color:var(--muted);border:1px solid var(--border);padding:4px 10px;border-radius:20px;}";
  s += ".nav{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap;}";
  s += ".nav a{padding:9px 16px;border-radius:9px;font-size:13px;font-weight:700;text-decoration:none;border:1px solid var(--border);color:var(--muted);}";
  s += ".nav a.active{background:var(--accent);color:#000;border-color:var(--accent);}";
  s += ".card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:20px;}";
  s += ".card-title{font-size:14px;font-weight:700;letter-spacing:.12em;color:var(--accent);text-transform:uppercase;margin-bottom:18px;display:flex;align-items:center;gap:8px;}";
  s += ".card-title::before{content:'';display:inline-block;width:3px;height:14px;background:var(--accent);border-radius:2px;}";
  s += "label{display:block;font-size:11px;font-weight:700;letter-spacing:.1em;color:var(--muted);text-transform:uppercase;margin:14px 0 6px;}";
  s += "input[type=text],textarea{width:100%;background:#06060e;border:1px solid var(--border);color:var(--text);padding:12px 14px;border-radius:10px;font-family:inherit;font-size:14px;outline:none;transition:border .2s;}";
  s += "input[type=text]:focus,textarea:focus{border-color:var(--accent2);}textarea{min-height:80px;resize:vertical;}";
  s += "input[type=range]{width:100%;accent-color:var(--accent);}";
  s += ".actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px;}";
  s += ".btn{padding:11px 20px;border:none;border-radius:10px;font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;letter-spacing:.06em;text-decoration:none;display:inline-block;}";
  s += ".btn-primary{background:var(--accent);color:#000;}.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border);}";
  s += ".btn-regen{background:#1a1a2e;color:var(--accent2);border:1px solid var(--accent2);}";
  s += ".btn-danger{background:#1f0a0a;color:var(--danger);border:1px solid var(--danger);}";
  s += "table{width:100%;border-collapse:collapse;}th{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:10px 12px;border-bottom:1px solid var(--border);text-align:left;}";
  s += "td{padding:14px 12px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:middle;}tr:last-child td{border-bottom:none;}";
  s += ".act{display:flex;gap:8px;}.btn-edit{padding:7px 14px;background:#1a1a2e;color:var(--accent2);border:1px solid var(--accent2);border-radius:8px;font-family:inherit;font-size:12px;text-decoration:none;font-weight:700;}";
  s += ".btn-del{padding:7px 14px;background:#1f0a0a;color:var(--danger);border:1px solid var(--danger);border-radius:8px;font-family:inherit;font-size:12px;text-decoration:none;font-weight:700;}";
  s += ".empty{color:var(--muted);font-size:13px;padding:16px 0;}";
  s += ".footer{text-align:center;margin-top:32px;font-size:11px;color:var(--muted);letter-spacing:.08em;}.footer a{color:var(--accent);text-decoration:none;}";
  s += ".info-box{background:#06060e;border:1px solid var(--border);border-radius:10px;padding:16px;font-size:13px;color:var(--muted);margin-bottom:12px;word-break:break-all;}";
  s += "@media(max-width:600px){.hdr{flex-direction:column;gap:10px;} td,th{padding:10px 8px;font-size:13px;} .act{flex-direction:column;} .nav a{font-size:12px;padding:7px 12px;}}";
  return s;
}

String portalHeader(const char* activePage) {
  String h = "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  h += "<title>MKQ Vault</title><style>" + portalCSS() + "</style></head><body><div class='wrap'>";
  h += "<div class='hdr'><div class='logo'>MKQ<span>.ONE</span></div><div class='badge'>Settings Portal</div></div>";
  h += "<nav class='nav'>";
  h += String("<a href='/' class='") + (strcmp(activePage,"pw")==0?"active":"") + "'>Passwords</a>";
  h += String("<a href='/totp' class='") + (strcmp(activePage,"totp")==0?"active":"") + "'>TOTP</a>";
  h += String("<a href='/backup' class='") + (strcmp(activePage,"backup")==0?"active":"") + "'>Backup</a>";
  h += "</nav>";
  return h;
}

String portalFooter() {
  return "<div class='footer'><a href='https://mkq.one'>mkq.one</a> &mdash; Secure by design</div></div></body></html>";
}

// ============================================================
//  Portal — Passwords page
// ============================================================
void handlePortalRoot() {
  int editIndex = -1;
  if (server.hasArg("edit")) {
    editIndex = server.arg("edit").toInt();
    if (editIndex < 0 || editIndex >= passwordMenuCount) editIndex = -1;
  }
  bool isEdit = (editIndex >= 0);
  String formName="", formUser="", formPass="";
  if (isEdit) {
    formName = htmlEscape(passwordNameValues[editIndex]);
    formUser = htmlEscape(passwordUsernameValues[editIndex]);
  } else {
    const char cs[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    for (int i=0;i<16;i++) formPass += cs[esp_random()%(sizeof(cs)-1)];
  }

  String html = portalHeader("pw");
  html += "<div class='card'><div class='card-title'>" + String(isEdit?"Edit Entry":"Add Entry") + "</div>";
  html += "<form method='POST' action='/save'>";
  if (isEdit) html += "<input type='hidden' name='edit_index' value='" + String(editIndex) + "'>";
  html += "<label>Name</label><input type='text' name='item_name' placeholder='e.g. Gmail' value='" + formName + "'>";
  html += "<label>Username</label><input type='text' name='item_user' placeholder='username or email' value='" + formUser + "'>";
  html += "<label>Password</label><input type='text' id='pwd' name='item_pass' placeholder='" + String(isEdit?"Leave blank to keep":"Enter or generate") + "' value='" + formPass + "'>";
  html += "<div style='margin-top:14px;'><div style='font-size:12px;color:var(--muted);margin-bottom:6px;'>Length: <span id='lv'>16</span></div>";
  html += "<input type='range' id='lr' min='4' max='64' value='16'></div>";
  html += "<div class='actions'><button class='btn btn-primary' type='submit'>" + String(isEdit?"Save Changes":"Add Password") + "</button>";
  html += "<button class='btn btn-regen' type='button' onclick='gen()'>&#8635; Regenerate</button>";
  if (isEdit) html += "<a class='btn btn-ghost' href='/'>Cancel</a>";
  html += "</div></form></div>";

  html += "<div class='card'><div class='card-title'>Saved Passwords</div>";
  if (passwordMenuCount == 0) { html += "<p class='empty'>No entries yet.</p>"; }
  else {
    html += "<table><tr><th>Name</th><th>Username</th><th>Actions</th></tr>";
    for (int i=0;i<passwordMenuCount;i++) {
      html += "<tr><td>" + htmlEscape(passwordNameValues[i]) + "</td><td>" + htmlEscape(passwordUsernameValues[i]) + "</td>";
      html += "<td><div class='act'><a class='btn-edit' href='/?edit=" + String(i) + "'>Edit</a>";
      html += "<a class='btn-del' href='/delete_pw?index=" + String(i) + "'>Delete</a></div></td></tr>";
    }
    html += "</table>";
  }
  html += "</div>" + portalFooter();
  html += "<script>const cs='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';";
  html += "function gen(){var l=+document.getElementById('lr').value||16,s='';for(var i=0;i<l;i++)s+=cs[Math.floor(Math.random()*cs.length)];document.getElementById('pwd').value=s;document.getElementById('lv').textContent=l;}";
  html += "document.addEventListener('DOMContentLoaded',function(){var r=document.getElementById('lr'),v=document.getElementById('lv');if(r&&v){v.textContent=r.value;r.addEventListener('input',function(){v.textContent=this.value;});}});</script>";

  server.sendHeader("Cache-Control","no-store"); server.send(200,"text/html",html);
}

void handlePortalSave() {
  String name=server.arg("item_name"); name.trim();
  String user=server.arg("item_user"); user.trim();
  String pass=server.arg("item_pass"); pass.trim();
  if (name.length()==0) { server.send(400,"text/plain","Name required"); return; }
  int target=-1;
  if (server.hasArg("edit_index")) { target=server.arg("edit_index").toInt(); if(target<0||target>=passwordMenuCount)target=-1; }
  if (target>=0) {
    name.toCharArray(passwordNameValues[target],32);
    user.toCharArray(passwordUsernameValues[target],128);
    if (pass.length()>0) pass.toCharArray(passwordTextValues[target],128);
  } else {
    if (pass.length()==0||passwordMenuCount>=MAX_PASSWORD_ITEMS) { server.send(400,"text/plain","Error"); return; }
    name.toCharArray(passwordNameValues[passwordMenuCount],32);
    user.toCharArray(passwordUsernameValues[passwordMenuCount],128);
    pass.toCharArray(passwordTextValues[passwordMenuCount],128);
    passwordMenuCount++;
  }
  refreshPasswordMenuItems(); savePasswords(); handlePortalRoot();
}

void handleDeletePw() {
  if (!server.hasArg("index")) { handlePortalRoot(); return; }
  int idx=server.arg("index").toInt();
  if (idx<0||idx>=passwordMenuCount) { handlePortalRoot(); return; }
  for (int i=idx;i<passwordMenuCount-1;i++) {
    strlcpy(passwordNameValues[i],    passwordNameValues[i+1],32);
    strlcpy(passwordUsernameValues[i],passwordUsernameValues[i+1],128);
    strlcpy(passwordTextValues[i],    passwordTextValues[i+1],128);
  }
  passwordMenuCount=max(0,passwordMenuCount-1);
  selectedIndex=constrain(selectedIndex,0,max(0,passwordMenuCount-1));
  refreshPasswordMenuItems(); savePasswords(); handlePortalRoot();
}

// ============================================================
//  Portal — TOTP page
// ============================================================
void handlePortalTotp() {
  int editIndex=-1;
  if (server.hasArg("edit")) { editIndex=server.arg("edit").toInt(); if(editIndex<0||editIndex>=totpCount)editIndex=-1; }
  bool isEdit=(editIndex>=0);
  String formName="", formSecret="";
  if (isEdit) { formName=htmlEscape(totpNames[editIndex]); formSecret=htmlEscape(totpSecretB32[editIndex]); }

  String html = portalHeader("totp");
  html += "<div class='card'><div class='card-title'>" + String(isEdit?"Edit TOTP":"Add TOTP") + "</div>";
  html += "<form method='POST' action='/save_totp'>";
  if (isEdit) html += "<input type='hidden' name='edit_index' value='" + String(editIndex) + "'>";
  html += "<label>Name</label><input type='text' name='totp_name' placeholder='e.g. GitHub' value='" + formName + "'>";
  html += "<label>Base32 Secret</label><input type='text' name='totp_secret' placeholder='JBSWY3DPEHPK3PXP' value='" + formSecret + "'>";
  html += "<p style='font-size:11px;color:var(--muted);margin-top:8px;'>Find this in your app/service 2FA setup page. Spaces are OK.</p>";
  html += "<div class='actions'><button class='btn btn-primary' type='submit'>" + String(isEdit?"Save Changes":"Add TOTP") + "</button>";
  if (isEdit) html += "<a class='btn btn-ghost' href='/totp'>Cancel</a>";
  html += "</div></form></div>";

  html += "<div class='card'><div class='card-title'>Saved TOTP Entries</div>";
  if (totpCount==0) { html+="<p class='empty'>No TOTP entries yet.</p>"; }
  else {
    html += "<table><tr><th>Name</th><th>Secret</th><th>Actions</th></tr>";
    for (int i=0;i<totpCount;i++) {
      String s = totpSecretB32[i]; if(s.length()>12) s=s.substring(0,12)+"...";
      html += "<tr><td>" + htmlEscape(totpNames[i]) + "</td><td style='font-size:12px;color:var(--muted);'>" + htmlEscape(s.c_str()) + "</td>";
      html += "<td><div class='act'><a class='btn-edit' href='/totp?edit=" + String(i) + "'>Edit</a>";
      html += "<a class='btn-del' href='/delete_totp?index=" + String(i) + "'>Delete</a></div></td></tr>";
    }
    html += "</table>";
  }
  html += "</div>" + portalFooter();
  server.sendHeader("Cache-Control","no-store"); server.send(200,"text/html",html);
}

void handleSaveTotp() {
  String name=server.arg("totp_name"); name.trim();
  String secret=server.arg("totp_secret"); secret.trim();
  if (name.length()==0||secret.length()==0) { server.send(400,"text/plain","Name and secret required"); return; }
  int target=-1;
  if (server.hasArg("edit_index")) { target=server.arg("edit_index").toInt(); if(target<0||target>=totpCount)target=-1; }
  if (target>=0) {
    name.toCharArray(totpNames[target],32);
    secret.toCharArray(totpSecretB32[target],65);
  } else {
    if (totpCount>=MAX_TOTP_ITEMS) { server.send(400,"text/plain","TOTP storage full"); return; }
    name.toCharArray(totpNames[totpCount],32);
    secret.toCharArray(totpSecretB32[totpCount],65);
    totpCount++;
  }
  initAllTotp(); saveTotp();
  server.sendHeader("Location","/totp"); server.send(302,"text/plain","");
}

void handleDeleteTotp() {
  if (!server.hasArg("index")) { server.sendHeader("Location","/totp"); server.send(302,"text/plain",""); return; }
  int idx=server.arg("index").toInt();
  if (idx<0||idx>=totpCount) { server.sendHeader("Location","/totp"); server.send(302,"text/plain",""); return; }
  for (int i=idx;i<totpCount-1;i++) {
    strlcpy(totpNames[i],      totpNames[i+1],32);
    strlcpy(totpSecretB32[i],  totpSecretB32[i+1],65);
  }
  if (totpObjects[totpCount-1]) { delete totpObjects[totpCount-1]; totpObjects[totpCount-1]=nullptr; }
  totpCount=max(0,totpCount-1);
  initAllTotp(); saveTotp();
  server.sendHeader("Location","/totp"); server.send(302,"text/plain","");
}

// ============================================================
//  Portal — Backup / Restore page
// ============================================================

// Build JSON export (passwords + TOTP)
// Format: {"passwords":[{"n":"..","u":"..","p":".."},...], "totp":[{"n":"..","s":".."},...],"ver":2}
String buildBackupJson() {
  String j = "{\"ver\":2,\"passwords\":[";
  for (int i=0;i<passwordMenuCount;i++) {
    if (i) j+=",";
    j+="{\"n\":\""; j+=htmlEscape(passwordNameValues[i]);
    j+="\",\"u\":\""; j+=htmlEscape(passwordUsernameValues[i]);
    j+="\",\"p\":\""; j+=htmlEscape(passwordTextValues[i]); j+="\"}";
  }
  j+="],\"totp\":[";
  for (int i=0;i<totpCount;i++) {
    if (i) j+=",";
    j+="{\"n\":\""; j+=htmlEscape(totpNames[i]);
    j+="\",\"s\":\""; j+=htmlEscape(totpSecretB32[i]); j+="\"}";
  }
  j+="]}";
  return j;
}

void handleBackupPage() {
  String backupJson = buildBackupJson();

  String html = portalHeader("backup");
  html += "<div class='card'><div class='card-title'>Export Backup</div>";
  html += "<p style='color:var(--muted);font-size:13px;margin-bottom:12px;'>Copy the JSON below and save it somewhere safe. It contains all your passwords and TOTP secrets in plain text — store it carefully.</p>";
  html += "<div class='info-box'><pre style='white-space:pre-wrap;font-size:12px;'>" + backupJson + "</pre></div>";
  html += "<div class='actions'><a class='btn btn-primary' href='/export_json'>&#8595; Download JSON</a></div></div>";

  html += "<div class='card'><div class='card-title'>Import / Restore</div>";
  html += "<p style='color:var(--muted);font-size:13px;margin-bottom:12px;'>";
  html += "Paste a previously exported JSON below. <strong style='color:var(--danger);'>This will REPLACE all current data.</strong></p>";
  html += "<form method='POST' action='/import_json'>";
  html += "<label>JSON Data</label><textarea name='json_data' placeholder='Paste JSON here...'></textarea>";
  html += "<div class='actions'><button class='btn btn-danger' type='submit' onclick=\"return confirm('This will replace ALL current data. Continue?')\">&#8593; Import &amp; Replace</button></div>";
  html += "</form></div>" + portalFooter();

  server.sendHeader("Cache-Control","no-store"); server.send(200,"text/html",html);
}

void handleExportJson() {
  server.sendHeader("Content-Disposition","attachment; filename=\"mkq_vault_backup.json\"");
  server.sendHeader("Cache-Control","no-store");
  server.send(200,"application/json", buildBackupJson());
}

// Minimal JSON parser — extract string value after a key like "n":"VALUE"
String jsonExtract(const String& json, const String& key) {
  String search = "\"" + key + "\":\"";
  int start = json.indexOf(search);
  if (start < 0) return "";
  start += search.length();
  int end = json.indexOf("\"", start);
  if (end < 0) return "";
  String val = json.substring(start, end);
  // unescape basic HTML entities put there by htmlEscape during export
  val.replace("&amp;","&"); val.replace("&lt;","<"); val.replace("&gt;",">");val.replace("&quot;","\"");
  return val;
}

void handleImportJson() {
  if (!server.hasArg("json_data")) { server.sendHeader("Location","/backup"); server.send(302,"text/plain",""); return; }
  String raw = server.arg("json_data"); raw.trim();
  if (raw.length() < 10) { server.sendHeader("Location","/backup"); server.send(302,"text/plain",""); return; }

  // Clear existing
  passwordMenuCount = 0; totpCount = 0;
  for (int i=0;i<MAX_TOTP_ITEMS;i++) { if(totpObjects[i]){delete totpObjects[i];totpObjects[i]=nullptr;} }

  // Parse passwords array
  int arrStart = raw.indexOf("\"passwords\":[");
  if (arrStart >= 0) {
    arrStart += 13;
    int arrEnd = raw.indexOf("]", arrStart);
    String arr = raw.substring(arrStart, arrEnd);
    int pos = 0;
    while (passwordMenuCount < MAX_PASSWORD_ITEMS) {
      int ob = arr.indexOf("{", pos); if (ob<0) break;
      int cb = arr.indexOf("}", ob);  if (cb<0) break;
      String obj = arr.substring(ob, cb+1);
      String n = jsonExtract(obj,"n"); String u = jsonExtract(obj,"u"); String p = jsonExtract(obj,"p");
      if (n.length()>0) {
        n.toCharArray(passwordNameValues[passwordMenuCount],32);
        u.toCharArray(passwordUsernameValues[passwordMenuCount],128);
        p.toCharArray(passwordTextValues[passwordMenuCount],128);
        passwordMenuCount++;
      }
      pos = cb+1;
    }
  }

  // Parse totp array
  int tarrStart = raw.indexOf("\"totp\":[");
  if (tarrStart >= 0) {
    tarrStart += 8;
    int tarrEnd = raw.indexOf("]", tarrStart);
    String arr = raw.substring(tarrStart, tarrEnd);
    int pos = 0;
    while (totpCount < MAX_TOTP_ITEMS) {
      int ob = arr.indexOf("{", pos); if (ob<0) break;
      int cb = arr.indexOf("}", ob);  if (cb<0) break;
      String obj = arr.substring(ob, cb+1);
      String n = jsonExtract(obj,"n"); String s = jsonExtract(obj,"s");
      if (n.length()>0 && s.length()>0) {
        n.toCharArray(totpNames[totpCount],32);
        s.toCharArray(totpSecretB32[totpCount],65);
        totpCount++;
      }
      pos = cb+1;
    }
  }

  refreshPasswordMenuItems(); savePasswords();
  initAllTotp(); saveTotp();
  server.sendHeader("Location","/backup"); server.send(302,"text/plain","");
}

// ============================================================
//  Settings Portal — Start / Stop
// ============================================================
void stopSettingsPortal() {
  if (!settingsPortalActive) return;
  dnsServer.stop(); server.stop();
  WiFi.softAPdisconnect(true); WiFi.mode(WIFI_OFF);
  settingsPortalActive = false;
}

void startSettingsPortal() {
  stopSettingsPortal();
  WiFi.disconnect(true,true); WiFi.softAPdisconnect(true); delay(200);
  WiFi.mode(WIFI_AP); delay(100);
  if (!WiFi.softAP("MKQ Vault", settingsApPassword.c_str())) {
    tft.fillScreen(TFT_BLACK); tft.setTextColor(TFT_RED,TFT_BLACK); tft.setTextSize(2);
    tft.setCursor(20,40); tft.println("AP Start Failed");
    delay(1200); currentScreen=SCREEN_MAIN; drawMenu(); return;
  }
  delay(300); server.stop(); dnsServer.stop();
  dnsServer.start(DNS_PORT,"*",WiFi.softAPIP());

  server.on("/",                    HTTP_GET,  handlePortalRoot);
  server.on("/generate_204",        HTTP_GET,  handlePortalRoot);
  server.on("/hotspot-detect.html", HTTP_GET,  handlePortalRoot);
  server.on("/ncsi.txt",            HTTP_GET,  handlePortalRoot);
  server.on("/save",                HTTP_POST, handlePortalSave);
  server.on("/delete_pw",           HTTP_GET,  handleDeletePw);
  server.on("/totp",                HTTP_GET,  handlePortalTotp);
  server.on("/save_totp",           HTTP_POST, handleSaveTotp);
  server.on("/delete_totp",         HTTP_GET,  handleDeleteTotp);
  server.on("/backup",              HTTP_GET,  handleBackupPage);
  server.on("/export_json",         HTTP_GET,  handleExportJson);
  server.on("/import_json",         HTTP_POST, handleImportJson);
  server.onNotFound(handlePortalRoot);
  server.begin();
  settingsPortalActive = true;
  drawSettingsPortalScreen();
}

void processSettingsPortal() {
  if (!settingsPortalActive) return;
  dnsServer.processNextRequest(); server.handleClient();
}

// ============================================================
//  Navigation
// ============================================================
void moveUp()   { int n=getCurrentMenuCount(); selectedIndex=(selectedIndex-1+n)%n; drawMenu(); }
void moveDown() { int n=getCurrentMenuCount(); selectedIndex=(selectedIndex+1)%n;   drawMenu(); }

void sendSelectedItem() {
  MenuItem* items = getCurrentMenuItems();
  MenuItem& item  = items[selectedIndex];

  // TOTP view — type code
  if (currentScreen == SCREEN_TOTP_VIEW) {
    time_t now; if (!getCurrentUnixTime(now)) return;
    if (totpObjects[activeTotpIndex]) kbPrint(totpObjects[activeTotpIndex]->getCode(now));
    return;
  }

  // Settings portal — type AP password
  if (settingsPortalActive) { kbPrint(settingsApPassword.c_str()); return; }

  // Send mode selection screen
  if (currentScreen == SCREEN_SEND_MODE) {
    sendMode = selectedIndex; // 0=USB, 1=BLE
    currentScreen = SCREEN_MAIN; selectedIndex = menuScrollOffset = 0; drawMenu(); return;
  }

  // Password actions
  if (currentScreen == SCREEN_PASSWORD_ACTIONS) {
    showSendingScreen(passwordMenuItems[activePasswordIndex].name); delay(250);
    switch (selectedIndex) {
      case 0: kbPrint(passwordUsernameValues[activePasswordIndex]); break;
      case 1: kbPrint(passwordTextValues[activePasswordIndex]);     break;
      case 2:
        kbPrint(passwordUsernameValues[activePasswordIndex]);
        kbTab();
        kbPrint(passwordTextValues[activePasswordIndex]); break;
    }
    delay(400); drawMenu(); return;
  }

  // Main menu
  if (item.type == ITEM_SUBMENU && currentScreen == SCREEN_MAIN) {
    if (selectedIndex == 0) {
      currentScreen=SCREEN_PASSWORDS; selectedIndex=menuScrollOffset=0; drawMenu();
    } else if (selectedIndex == 1) {
      if (totpCount == 0) { showStatusScreen("No TOTP","Add via portal"); delay(1500); drawMenu(); return; }
      if (!timeSynced) { showStatusScreen("Connecting WiFi","TOTP"); syncTimeOverWiFi(); timeSynced=true; }
      currentScreen=SCREEN_TOTP; selectedIndex=menuScrollOffset=0; drawMenu();
    } else if (selectedIndex == 2) {
      selectedIndex=menuScrollOffset=0; startSettingsPortal();
    }
    return;
  }

  // Password list → actions
  if (item.type == ITEM_TEXT) {
    activePasswordIndex=selectedIndex; currentScreen=SCREEN_PASSWORD_ACTIONS; selectedIndex=menuScrollOffset=0; drawMenu(); return;
  }

  // TOTP list → view code
  if (item.type == ITEM_TOTP) {
    if (!timeSynced) { showStatusScreen("Connecting WiFi",item.name); syncTimeOverWiFi(); timeSynced=true; }
    activeTotpIndex=selectedIndex; currentScreen=SCREEN_TOTP_VIEW; lastTotpRedraw=0; return;
  }
}

// ============================================================
//  Setup
// ============================================================
void setup() {
  pinMode(BTN_OK_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN,  INPUT_PULLUP);

  settingsApPassword = generateApPassword();
  loadSavedPasswords();
  loadSavedTotp();

  tft.init();
  tft.setRotation(1);

  drawBootScreen();
  delay(1400);
  drawMenu();

  // USB HID
  UsbKeyboard.begin();
  USB.begin();
  delay(USB_STARTUP_DELAY);

  // Bluetooth HID
  initBLE();
}

// ============================================================
//  Loop
// ============================================================
void loop() {
  processSettingsPortal();

  bool okUpState = digitalRead(BTN_OK_UP);
  bool downState = digitalRead(BTN_DOWN);
  unsigned long nowMs = millis();

  // TOTP live display
  if (currentScreen == SCREEN_TOTP_VIEW && activeTotpIndex < totpCount && totpObjects[activeTotpIndex]) {
    time_t now;
    if (getCurrentUnixTime(now)) {
      int secsLeft = 30 - (int)(now % 30);
      if (secsLeft == 30) secsLeft = 0;
      if (lastTotpRedraw != (unsigned long)now) {
        showTotpCodeScreen(totpNames[activeTotpIndex], totpObjects[activeTotpIndex]->getCode(now), secsLeft);
        lastTotpRedraw = (unsigned long)now;
      }
    }
  }

  // OK/UP button
  if (okUpState == LOW) {
    if (!btnPressed) { btnPressed=true; btnPressStart=nowMs; holdTriggered=false; }
    else if (!holdTriggered && (nowMs-btnPressStart >= HOLD_TIME_MS)) { holdTriggered=true; sendSelectedItem(); }
  } else {
    if (btnPressed && !holdTriggered)
      if (currentScreen!=SCREEN_TOTP_VIEW && !settingsPortalActive) moveDown();
    btnPressed=false; holdTriggered=false;
  }

  // DOWN/BACK button
  if (downState == LOW) {
    if (lastDownState==HIGH) { lastDownPress=nowMs; downHoldHandled=false; }
    if (!downHoldHandled && (nowMs-lastDownPress>=HOLD_TIME_MS)) {
      downHoldHandled=true;
      if      (currentScreen==SCREEN_TOTP_VIEW)            { currentScreen=SCREEN_TOTP; selectedIndex=menuScrollOffset=0; drawMenu(); }
      else if (currentScreen==SCREEN_PASSWORD_ACTIONS)     { currentScreen=SCREEN_PASSWORDS; selectedIndex=activePasswordIndex; drawMenu(); }
      else if (currentScreen==SCREEN_SEND_MODE)            { currentScreen=SCREEN_MAIN; selectedIndex=menuScrollOffset=0; drawMenu(); }
      else if (settingsPortalActive)                       { stopSettingsPortal(); currentScreen=SCREEN_MAIN; selectedIndex=menuScrollOffset=0; drawMenu(); }
      else if (currentScreen!=SCREEN_MAIN)                 { currentScreen=SCREEN_MAIN; selectedIndex=menuScrollOffset=0; drawMenu(); }
    }
  } else {
    if (lastDownState==LOW && !downHoldHandled && (nowMs-lastDownPress<HOLD_TIME_MS))
      if (currentScreen!=SCREEN_TOTP_VIEW && !settingsPortalActive) moveUp();
    downHoldHandled=false;
  }

  lastDownState = downState;
  delay(20);
}
