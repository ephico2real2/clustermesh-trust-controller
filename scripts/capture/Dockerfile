# Ubuntu 24.04 with matching Chromium binaries and OS dependencies installed.
# Keep the image version and package-lock.json Playwright version aligned.
FROM mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27
WORKDIR /opt/cmtc-capture
COPY scripts/capture/package.json scripts/capture/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && node -e "const {chromium}=require('playwright');(async()=>{const browser=await chromium.launch({headless:true});await browser.close()})().catch(e=>{console.error(e);process.exit(1)})"
COPY scripts/capture/capture.mjs ./capture.mjs
COPY scripts/capture/walk.cjs ./walk.cjs
COPY scripts/capture/walk-smoke.cjs ./walk-smoke.cjs
COPY scripts/capture/grafana-page.cjs ./grafana-page.cjs
COPY scripts/capture/grafana-page.test.cjs ./grafana-page.test.cjs
RUN node walk-smoke.cjs && node grafana-page.test.cjs
WORKDIR /workspace
ENTRYPOINT ["node", "/opt/cmtc-capture/capture.mjs"]
