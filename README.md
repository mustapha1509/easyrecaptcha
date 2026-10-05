# EasyRecaptcha — Google reCAPTCHA v2 & v3 for PrestaShop 8.x / 9.x

Author: Nasraoui Mustapha

Protects your forms against spam and bots, and lets you refuse specific e-mail addresses and IP addresses.

## Features

- **reCAPTCHA v2** (checkbox) **and v3** (invisible, score based)
- Protects: **customer login**, **registration** (including account creation at checkout), **contact us**, **personal information**, **back-office login**
- **Sandbox mode** for testing: nothing is ever blocked, every result is logged. With v2, Google's public test keys are used, so you can try it without creating keys
- **Blocked e-mails** and **blocked IPs** (IPv4, IPv6, CIDR ranges) for login and registration
- Light / dark theme (v2), compact size, v3 badge position or hidden badge (with Google's required notice added under the forms)
- Optional lazy loading: Google's script is only loaded when a visitor touches a form
- Optional `recaptcha.net` domain, for visitors who cannot reach `google.com`
- Log of the last 100 checks (form, IP, result, v3 score) to tune the threshold
- No theme edits and no core overrides

## Install

1. Back Office > Modules > Module Manager > **Upload a module** > `easyrecaptcha.zip`
2. Create keys at <https://www.google.com/recaptcha/admin> (choose v2 "Checkbox" **or** v3; keys are not interchangeable)
3. Open the module, choose the version, paste the **site key** and **secret key**, tick **Sandbox mode**, save
4. Visit your login, registration and contact pages: the widget (v2) or badge (v3) should appear
5. Submit each form once, check the log at the bottom of the module page, then switch **Sandbox mode off**

**Back-office login protection is off by default.** Turn it on last, after the other forms work, and keep another admin session open while you test.

## How it works

A small script finds each form by the field PrestaShop always posts (`submitLogin`, `submitCreate`, `submitMessage`) and adds the widget or an invisible token field. On submit, the module verifies the token with Google **before PrestaShop processes the form**. If the check fails, the submit flag is removed from the request (so the form is not processed), the fields the visitor typed are kept, and an error message is shown.

A token is bound to its form (v3 "action"): a token obtained on the contact form cannot be replayed on the login form.

## Restrictions syntax

E-mails, one per line:

| Entry | Blocks |
|---|---|
| `bad@example.com` | that exact address |
| `@spam.com` or `spam.com` | every address of that domain (and its sub-domains) |
| `*.ru`, `*viagra*` | wildcard pattern |

IPs, one per line: `203.0.113.7`, `198.51.100.0/24`, `2001:db8::/32`. The page refuses to save a list that contains **your own IP**.

E-mail blocks apply to login, registration and the personal-information form. IP blocks apply to login and registration. Neither applies to the contact form.

Enable **Behind Cloudflare** only if your site really is behind Cloudflare, otherwise visitors could fake their IP.

## Locked out of the back office?

Create an empty file named **`disable.flag`** in `modules/easyrecaptcha/` (FTP or your host's file manager). Every check switches off at once. Delete it to switch protection back on. The module is also inert until both keys are entered.

## Good to know

- If Google's script is blocked (some ad blockers, firewalls), the visitor's form is refused with the "captcha failed" message. If **your server** cannot reach Google, requests are let through by default (setting "If Google cannot be reached"); a missing or invalid token is always refused.
- v3 score: start at 0.5. If real customers get refused, look at the score in the log and lower it; raise it if spam gets through.
- reCAPTCHA sets cookies and shares data with Google: mention it in your privacy / cookie policy and check your consent banner.
- The log stores IP addresses (last 100 checks only).
- Custom or third-party forms are not covered, except contact / login / registration forms embedded on other pages: add the page name (its `php_self`, e.g. `cms`) under **Extra pages**.
- Not supported: reCAPTCHA Enterprise, v2 invisible.
- Translations: shopper-facing messages are translated to French (`translations/fr.php`); the admin screen is in English.

