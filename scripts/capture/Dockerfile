# Ubuntu 24.04 with matching Chromium binaries and OS dependencies installed.
# Keep the image version and package-lock.json Playwright version aligned.
FROM mcr.microsoft.com/playwright:v1.56.1-noble@sha256:f1e7e01021efd65dd1a2c56064be399f3e4de00fd021ac561325f2bfbb2b837a
WORKDIR /opt/cmtc-capture
COPY scripts/capture/package.json scripts/capture/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && node -e "const {chromium}=require('playwright');(async()=>{const browser=await chromium.launch({headless:true});await browser.close()})().catch(e=>{console.error(e);process.exit(1)})"
COPY scripts/capture/capture.mjs ./capture.mjs
WORKDIR /workspace
ENTRYPOINT ["node", "/opt/cmtc-capture/capture.mjs"]
