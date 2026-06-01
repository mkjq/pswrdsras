[README.md](https://github.com/user-attachments/files/28483497/README.md)
# MKQ Vault 🔐

<p align="center">
  <img src="assets/device.jpg" width="300"/>
</p>

<p align="center">
  <b>Open-source hardware password manager & 2FA generator — built on ESP32-S3</b><br/>
  <a href="https://mkq.one">mkq.one</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-ESP32--S3-blue?style=flat-square&logo=espressif"/>
  <img src="https://img.shields.io/badge/Latest-V3.0-gold?style=flat-square"/>
  <img src="https://img.shields.io/badge/Storage-Local%20NVS-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Custom%20Non--Commercial-red?style=flat-square"/>
</p>

---

## 🧠 Concept

MKQ Vault is a **physical, offline password manager** inspired by hardware crypto wallets.

Your passwords and 2FA secrets never leave the device — no cloud, no sync, no third-party exposure. Everything is stored locally in the ESP32-S3's NVS flash. The device only acts when you tell it to.

---

## 📦 Version Overview

This repository contains three firmware versions. Each version builds on the previous one and targets a different setup.

| | V1 | V2 | V3 |
|---|---|---|---|
| **Hardware** | ESP32-S3 + TFT screen | ESP32-S3 + TFT screen | Any ESP32-S3 (no screen) |
| **Output** | USB HID keyboard | USB HID + Bluetooth HID | USB CDC Serial API |
| **TOTP accounts** | 1 (hardcoded) | Up to 12 | Up to 12 |
| **Settings** | Wi-Fi portal | Wi-Fi portal | Serial commands |
| **Backup / Restore** | ❌ | ✅ JSON via browser | ✅ JSON via Serial |
| **PIN lock** | ❌ | ❌ | ✅ Challenge-Response |
| **Bluetooth** | ❌ | ✅ | ❌ |
| **Needs screen** | ✅ | ✅ | ❌ |

---

## 🔖 V1 — The Original

> **Status:** Stable prototype
> **File:** `MKQ_Vault_V1.ino`

V1 is the starting point. It turns an ESP32-S3 with a TFT screen into a standalone password manager that types your credentials automatically over USB — just like a keyboard.

### How it works

You navigate the menu using two physical buttons on the device. When you select an account and press OK, the device types the password directly into whatever is focused on your computer — no software needed on the host side.

For TOTP (2FA), the device connects to Wi-Fi once at startup to sync the time via NTP, then generates codes locally without any internet connection afterward.

The settings portal runs as a local Wi-Fi hotspot. You connect from your phone or laptop, open any browser, and manage your accounts from a simple web page.

### V1 Features

- 🔐 Store up to 12 password accounts in NVS (persistent across reboots)
- ⌨️ Auto-type via USB HID — the device acts as a physical keyboard
- 👤 Three send modes: Username only / Password only / Username + TAB + Password
- 🔢 TOTP 2FA code generation (1 account, Base32 secret)
- 📟 On-device TFT menu with scroll and button navigation
- ⚙️ Wi-Fi captive portal to add, edit, and delete accounts
- 🔑 Built-in random password generator in the portal
- 🌐 NTP time sync for accurate TOTP codes

### V1 Limitations

- TOTP supports only one account (hardcoded secret)
- No Bluetooth — USB only
- No backup or restore feature
- No PIN protection — anyone with the device can access all passwords

---

## 🔖 V2 — Full-Featured Screen Edition

> **Status:** Stable
> **File:** `MKQ_Vault_V2.ino`

V2 keeps everything from V1 and adds three major upgrades: multi-account TOTP, Bluetooth HID, and a full backup system. This is the recommended version if you have an ESP32-S3 with a screen.

### What changed from V1

**Multi-account TOTP** — V1 only supported one hardcoded TOTP secret. V2 supports up to 12 TOTP accounts, all managed dynamically through the settings portal. Each account has its own name and Base32 secret, stored in NVS.

**Bluetooth HID** — V2 adds a BLE keyboard alongside USB. From the main menu you can switch between USB mode and Bluetooth mode. This lets you use the device with phones, tablets, or any Bluetooth-capable device — not just computers. The device advertises as `MKQ Vault` and pairs like a standard keyboard.

**Backup & Restore** — The settings portal now has a dedicated Backup tab. You can export all your passwords and TOTP secrets as a single JSON file directly from the browser, and restore them the same way. This is critical if you ever need to re-flash the device or move data to a new one.

**Redesigned portal** — The web interface was rebuilt with a tabbed layout: Passwords, TOTP, and Backup — each on its own page with a consistent dark theme matching the MKQ brand.

### V2 Features

Everything in V1, plus:

- 🔵 Bluetooth HID keyboard (BLE) — works with phones and tablets
- 🔢 Multi-account TOTP — up to 12 entries, fully dynamic
- 💾 JSON Backup & Restore via the browser portal
- 📋 Tabbed settings portal (Passwords / TOTP / Backup)
- 🔄 Send mode indicator (USB / BLE) visible on-screen at all times

### V2 Limitations

- Still requires a TFT screen and physical buttons
- No PIN protection — physical access = full access
- Settings portal is open to anyone who connects to the Wi-Fi hotspot

---

## 🔖 V3 — Headless Serial Dongle

> **Status:** Stable
> **File:** `MKQ_Vault_V3.ino`

V3 is a complete architectural shift. The screen, buttons, Wi-Fi, and HID keyboard are all removed. The device becomes a silent USB dongle that communicates exclusively through a Serial API — designed to be driven by a companion app, script, or any tool that can open a serial port.

### Why V3 exists

V1 and V2 require specific hardware (a board with a screen and buttons). V3 runs on any ESP32-S3 board regardless of what peripherals are attached — including bare modules soldered to a PCB or a simple dev kit without a screen. This opens the door for integration with desktop apps, browser extensions, mobile apps over USB-OTG, and automation scripts.

### How the security model works

V3 introduces a **PIN-based lock** that V1 and V2 don't have. When the device boots, it starts in a `LOCKED` state and does nothing except wait for an `UNLOCK` command with the correct PIN. Only after successful authentication does it accept any data commands. Wrong PIN attempts are counted, and after 5 failures the device enforces a 30-second lockout.

The PIN is stored in NVS and can be changed at any time via the `CHANGE_PIN` command (requires the current PIN to change it).

### How time works in V3

Because there's no Wi-Fi, the device has no way to get the current time on its own. Instead, the host app sends the current Unix timestamp via `SET_TIME` before requesting any TOTP codes. The device then maintains a software clock internally using `millis()` to keep time ticking between commands — no RTC module required.

### Communication protocol

All communication is plain text over USB CDC Serial at 115200 baud. Every command is a single line ending with `\n`. Every response is a single JSON line. This makes it trivial to drive from Python, JavaScript, shell scripts, or any language with serial port support.

```
→ UNLOCK:1234
← {"ok":true,"auth":"AUTH_OK"}

→ SET_TIME:1750000000
← {"ok":true,"msg":"TIME_SET:1750000000"}

→ GET_TOTP:0
← {"ok":true,"idx":0,"name":"GitHub","code":"482910","expires_in":17}

→ LIST_PW
← {"ok":true,"passwords":[{"idx":0,"name":"Gmail","user":"me@gmail.com"},{"idx":1,"name":"GitHub","user":"dev@mkq.one"}]}

→ ADD_PW:Notion|user@mkq.one|Str0ngP@ss!
← {"ok":true,"msg":"PW_ADDED:idx=2"}
```

### V3 Features

- 🔒 PIN lock with brute-force protection (lockout after 5 wrong attempts)
- 📡 Full JSON Serial API — no screen, no buttons, no Wi-Fi needed
- 🕐 Software clock synced by the host app via `SET_TIME`
- 📋 Full CRUD for Passwords: `LIST_PW`, `GET_PW`, `ADD_PW`, `EDIT_PW`, `DEL_PW`
- 🔢 Full CRUD for TOTP: `LIST_TOTP`, `GET_TOTP`, `ADD_TOTP`, `EDIT_TOTP`, `DEL_TOTP`
- 💾 Export full backup as JSON / Import and replace all data
- 🔑 PIN management: `CHANGE_PIN`
- ⚡ Works on any ESP32-S3 board — no display or buttons required
- 🧩 Designed for integration — drive it from Python, Node.js, shell, or any app

### V3 Limitations

- No on-device UI — requires a host app or terminal to operate
- Does not auto-type passwords (no HID) — the host app reads the data and decides what to do with it
- No Bluetooth in this version

---

## 🛠️ Hardware

### Recommended Boards

| Board | Works With | Notes |
|-------|-----------|-------|
| LILYGO T-Display S3 | V1, V2 | Built-in TFT — plug and play |
| Any ESP32-S3 dev kit | V1, V2, V3 | Add external TFT for V1/V2 |
| ESP32-S3 bare module | V3 | Smallest possible form factor |

### Optional Accessories (V1 / V2)

- USB-C to USB-A adapter — flash-drive style form factor
- USB-C to USB-C adapter for direct laptop connection

---

## 🔌 Arduino IDE Setup

1. Install [Arduino IDE 2.x](https://www.arduino.cc/en/software)
2. Add ESP32 board support via `File → Preferences → Additional boards manager URLs`:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Install board: `Tools → Board Manager → esp32`
4. Select: `ESP32S3 Dev Module` (or your specific board)
5. Set USB Mode:
   - V1 / V2 → `USB-OTG (TinyUSB)`
   - V3 → `CDC and JTAG`

### Required Libraries

| Library | V1 | V2 | V3 |
|---------|----|----|-----|
| `TFT_eSPI` | ✅ | ✅ | ❌ |
| `TOTP-Arduino` | ✅ | ✅ | ✅ |
| `NimBLE-Arduino` | ❌ | ✅ | ❌ |

Install via `Tools → Manage Libraries` in Arduino IDE.

---

## 📡 V3 Serial API Reference

All commands are plain text lines (`\n` terminated). All responses are single JSON lines.

### Authentication

| Command | Description | Example |
|---------|-------------|---------|
| `UNLOCK:<pin>` | Unlock the device (default PIN: `1234`) | `UNLOCK:1234` |
| `LOCK` | Re-lock the device | `LOCK` |
| `CHANGE_PIN:<old>\|<new>` | Change PIN — min 4 characters | `CHANGE_PIN:1234\|9876` |
| `INFO` | Device info and state — works while locked | `INFO` |

### Time

| Command | Description | Example |
|---------|-------------|---------|
| `SET_TIME:<unix>` | Set Unix timestamp from host app | `SET_TIME:1750000000` |
| `GET_TIME` | Read current device clock | `GET_TIME` |

### Passwords

| Command | Payload | Example |
|---------|---------|---------|
| `LIST_PW` | — | `LIST_PW` |
| `GET_PW:<idx>` | Returns password value | `GET_PW:0` |
| `ADD_PW:<name>\|<user>\|<pass>` | — | `ADD_PW:Gmail\|me@gmail.com\|P@ss!` |
| `EDIT_PW:<idx>\|<name>\|<user>\|<pass>` | Leave field empty to keep current | `EDIT_PW:0\|\|\|NewPass` |
| `DEL_PW:<idx>` | — | `DEL_PW:2` |

### TOTP

| Command | Payload | Example |
|---------|---------|---------|
| `LIST_TOTP` | — | `LIST_TOTP` |
| `GET_TOTP:<idx>` | Returns code + seconds remaining | `GET_TOTP:0` |
| `ADD_TOTP:<name>\|<base32>` | — | `ADD_TOTP:GitHub\|JBSWY3DPEHPK3PXP` |
| `EDIT_TOTP:<idx>\|<name>\|<base32>` | Leave field empty to keep current | `EDIT_TOTP:0\|GitHub\|` |
| `DEL_TOTP:<idx>` | — | `DEL_TOTP:1` |

### Backup & Restore

| Command | Description |
|---------|-------------|
| `EXPORT_JSON` | Export all data as a single JSON line |
| `IMPORT_JSON:<json>` | Replace all data from a JSON string |

---

## 🔒 Security Notes

- Data is stored in ESP32 NVS flash — currently unencrypted (AES encryption is on the roadmap)
- V3 enforces a lockout after 5 failed PIN attempts — 30-second timeout before retrying
- V1/V2 portal Wi-Fi password is randomly generated on every boot — to retrieve it you type it via USB, so it never travels wirelessly in plain text
- Never share `EXPORT_JSON` output in plain text — it contains all passwords and TOTP secrets
- V1 and V2 have no access control — physical possession of the device means full access

---

## 🔮 Roadmap

- [ ] AES-256 storage encryption with PIN-derived key
- [ ] Fingerprint unlock module support
- [ ] Companion desktop / mobile app for V3
- [ ] USB HID output mode for V3 (optional auto-type)
- [ ] Over-the-air (OTA) firmware updates
- [ ] Custom PCB hardware design

---

## 🤝 Contributing

Pull requests are welcome. Areas where help is especially needed:

- Security review and hardening
- Companion app for V3 (any platform — Python, Electron, Flutter, etc.)
- Testing on different ESP32-S3 boards and form factors
- UI/UX improvements for V1/V2 screen editions
- Documentation improvements and translations

---

## 👨‍💻 Author

**Mohammad Khaled Qatanany (MAQTANANY)**

Web & App Developer — [mkq.one](https://mkq.one)

---

## 📄 License

This project uses a custom non-commercial open-source license.

✅ Free to use for personal and educational purposes
✅ Open to contributions
❌ Commercial use is not permitted
❌ Selling this project or derivatives is not permitted

See the [LICENSE](LICENSE) file for full terms.
