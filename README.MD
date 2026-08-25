# ALTCHA CAPTCHA for Concrete CMS

Version 1.0.2 provides a self-hosted proof-of-work bot check for Concrete CMS 9.

## Privacy and network behavior

At runtime all CAPTCHA traffic stays on the same Concrete CMS installation:

1. the locally bundled ALTCHA widget runs in the visitor's browser;
2. it requests a fresh challenge from `/altcha-captcha/challenge` on the same origin;
3. the proof-of-work is solved in the browser;
4. the normal form POST is verified locally by PHP.

There are no requests to ALTCHA, Google, hCaptcha, a CDN, or another external CAPTCHA service.

## Replay protection

Only successfully verified challenge signatures are recorded, and only as SHA-256 hashes. The replay table is a short-lived rolling store, not a request log. Expired rows are deleted on every successful claim and entries are retained for 5 minutes.

## Requirements

- Concrete CMS 9.0+
- PHP 8.1+
- Composer for the PHP ALTCHA library
- a browser with Web Crypto support

## Installation

Copy the directory to:

`packages/altcha_captcha`

Then install the PHP dependency inside the package directory:

```bash
cd packages/altcha_captcha
composer install --no-dev --optimize-autoloader
```

Install or upgrade the package in Concrete CMS and select **ALTCHA CAPTCHA** as the site's CAPTCHA library.

The HMAC secret is generated locally with `random_bytes()` during installation/upgrade. There is no external API key to create or paste.

## Upgrading from 0.9.x

Replace the old package files with this version, run Composer in the package directory, then run the Concrete CMS package upgrade. A new local HMAC secret is generated if the package does not already have a valid one. Outstanding old challenges will simply become invalid.

## Local development

The bundled ALTCHA browser code uses the Web Crypto API and therefore needs a secure browser context.

`http://localhost`, `http://127.0.0.1`, and `http://*.localhost` are generally treated as trustworthy local origins by modern browsers. A custom hostname such as `http://development.test` is not automatically trusted.

For `development.test`, use one of these development-only options:

- configure local HTTPS (recommended for a permanent development setup);
- use a `.localhost` alias such as `development.localhost`;
- in Chromium/Chrome, temporarily add `http://development.test` under `chrome://flags/#unsafely-treat-insecure-origin-as-secure` and restart the browser.

Never use the insecure-origin browser exception for production.

## Implementation note

The package uses the current `altcha-org/altcha` 2.x PHP library through its maintained V1 compatibility namespace because the self-hosted browser widget bundled with the original package is ALTCHA Widget v2.0.3 and uses the SHA-based V1 challenge format. The package architecture (same-origin challenge endpoint, automatic secret management and single-use replay protection) is isolated so a future PoW-v2 widget migration does not require redesigning the Concrete CMS integration.


## 1.0.2

- Refined the frictionless floating verification UI without changing CAPTCHA behavior.
- Uses Bootstrap/Concrete CSS variables so the widget follows the active site theme and dark mode where available.
- Adds a compact card layout, softer shadow, clearer typography, success/error states and a brief entrance animation.
- Honors `prefers-reduced-motion`.
- Asset versioning now follows the package version so updated CSS/JS is cache-busted after upgrades.

## 1.0.1

- fixed package upgrade on Concrete CMS 9: `parent::install()` and package lookup return a `Concrete\Core\Entity\Package`, not a package controller;
- HMAC configuration is now created directly through the package controller configuration liaison;
- runtime secret lookup now uses `PackageService::getClass()` explicitly instead of relying on entity method proxying.
