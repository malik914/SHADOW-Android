# SHADOW Android Security Lab

SHADOW is a lightweight native Android app for basic security checks on systems, servers, and APKs that you own or are explicitly authorized to assess.

## Features

- TCP connect scan of a user-specified host and port list (up to 64 ports per run).
- HTTP response security-header inspection.
- HTTPS certificate trust/expiry details, SHA-256 fingerprint, and negotiated cipher-suite information.
- Passive configuration checks for common web security headers, cookie flags, HTTPS redirects, and server banner disclosure.
- Optional NVD CVE keyword lookup when a product/version banner is detected. Results are candidates only and must be manually verified against the exact product, version, and configuration.
- Local scan history (latest 10 reports).
- Export the latest report as a PDF using Android's document picker.
- APK permission inventory using Android's document picker. The selected APK is inspected, not installed or executed.

## Build

GitHub Actions builds a debug APK on pushes to the `main` branch. Open the repository's **Actions** tab, select the newest **Build SHADOW APK** run, and download the `shadow-debug-apk` artifact after a successful build.

The project uses JDK 17, Android Gradle Plugin 8.7.3, Gradle 8.9, and Android SDK 35.

## Limitations

- This is a passive/basic assessment tool, not a full vulnerability scanner or penetration-testing suite.
- NVD keyword matches are not proof that a detected service is vulnerable.
- TCP port results only indicate whether a connection was accepted; they do not identify every service or vulnerability.
- Network checks require internet/network access and may be affected by firewalls, DNS, rate limits, and server behavior.
- Reports are stored locally on the device; scan history is limited to the latest 10 entries.

## Safety

Use only against your own devices, apps, and servers, or with explicit permission. SHADOW does not exploit services, bypass authentication, or collect credentials.
