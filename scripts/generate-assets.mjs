import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const root = process.cwd();
const iconBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeIcons() {
  for (const size of [16, 32, 48, 128]) {
    const path = resolve(root, "public", "icons", `icon-${size}.png`);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, Buffer.from(iconBase64, "base64"));
  }
}

const trackerRules = (domains) => domains.map((domain, index) => ({
  id: index + 1,
  priority: 1,
  action: { type: "block" },
  condition: { requestDomains: [domain], resourceTypes: ["script", "xmlhttprequest", "sub_frame", "image", "ping"] },
}));

const lists = {
  analytics: ["google-analytics.com", "googletagmanager.com", "mixpanel.com", "amplitude.com", "segment.io"],
  advertising: ["doubleclick.net", "googlesyndication.com", "criteo.com", "taboola.com", "outbrain.com"],
  social: ["connect.facebook.net", "platform.twitter.com", "platform.linkedin.com"],
  session_replay: ["hotjar.com", "fullstory.com", "mouseflow.com"],
  fingerprinting: ["fingerprint.com", "fingerprintjs.com"],
  strict: ["adnxs.com", "adsrvr.org", "scorecardresearch.com", "quantserve.com"],
};

await writeIcons();
for (const [id, domains] of Object.entries(lists)) {
  await writeJson(resolve(root, "public", "rules", `${id}.json`), trackerRules(domains, id));
}
await writeJson(resolve(root, "public", "rules", "default-blocklist.json"), lists);
