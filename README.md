# SHADOW Android Security Lab

A lightweight Android app for basic security checks on systems and APKs you own or are authorized to assess.

## Features
- TCP connect scan of a user-specified host and port list (maximum 64 ports per run).
- HTTP response security-header inspection.
- HTTPS certificate details and SHA-256 fingerprint.
- APK permission inventory using Android's document picker.

## Build
GitHub Actions builds a debug APK on every push to the `main` branch. Open the repository's **Actions** tab, select the latest **Build SHADOW APK** run, and download the `shadow-debug-apk` artifact.

## Safety
Use only against your own devices, apps, and servers, or with explicit permission. SHADOW performs basic connection and metadata checks; it does not exploit services, bypass authentication, or collect credentials.
