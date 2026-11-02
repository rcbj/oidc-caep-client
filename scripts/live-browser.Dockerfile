# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# The browser half of scripts/live_iya_sts.py. Playwright's official Python image carries the
# browsers but not the Python package, and Ubuntu's certutil is what puts iya-sts's root into
# Chromium's NSS database. The package version matches the image's browsers.
FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
RUN apt-get update \
 && apt-get install -y --no-install-recommends libnss3-tools \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir playwright==1.55.0
COPY live_browser.py /live/live_browser.py
ENTRYPOINT ["python3", "-I", "/live/live_browser.py"]
