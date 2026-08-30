#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const idpRoot = path.resolve(__dirname, "..");
const infraDir = path.resolve(idpRoot, "..", "infra");
const srcDir = path.join(idpRoot, "src");

console.log("\x1b[36m%s\x1b[0m", "=== UniERP IdP Container Auto-Build File Watcher ===");
console.log(`\x1b[90mWatching:\x1b[0m ${srcDir}`);
console.log(`\x1b[90mInfra dir:\x1b[0m ${infraDir}`);
console.log("\x1b[32m%s\x1b[0m", "Waiting for file changes in idp/src/...\n");

let isBuilding = false;
let pendingRebuild = false;
let debounceTimer = null;

function triggerRebuild(changedFile) {
  if (isBuilding) {
    pendingRebuild = true;
    console.log(`\x1b[33m[Watcher]\x1b[0m Change queued (${changedFile || "unknown"}) - build already in progress.`);
    return;
  }

  isBuilding = true;
  console.log(`\x1b[35m[Watcher]\x1b[0m File changed: \x1b[1m${changedFile}\x1b[0m. Triggering container build...`);

  const startTime = Date.now();
  const cmd = "docker";
  const args = [
    "compose",
    "-f", "docker-compose.dev.yml",
    "-f", "docker-compose.platform.yml",
    "up", "-d", "--build", "--no-deps", "idp"
  ];

  const child = spawn(cmd, args, {
    cwd: infraDir,
    stdio: "inherit",
    shell: true
  });

  child.on("close", (code) => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    isBuilding = false;

    if (code === 0) {
      console.log(`\x1b[32m[Watcher] [OK]\x1b[0m idp container rebuilt & restarted in ${elapsed}s!\n`);
    } else {
      console.error(`\x1b[31m[Watcher] [FAILED]\x1b[0m docker compose exited with code ${code} (${elapsed}s)\n`);
    }

    if (pendingRebuild) {
      pendingRebuild = false;
      triggerRebuild("queued-change");
    }
  });

  child.on("error", (err) => {
    console.error(`\x1b[31m[Watcher] [ERROR]\x1b[0m Failed to spawn docker compose:`, err);
    isBuilding = false;
  });
}

// Watch src recursively
fs.watch(srcDir, { recursive: true }, (eventType, filename) => {
  if (!filename) return;
  // Ignore tests, temp files, or hidden files if desired, but capture all ts/js/json changes
  if (filename.includes(".git") || filename.includes("node_modules") || filename.endsWith(".tmp")) {
    return;
  }

  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    triggerRebuild(filename);
  }, 1000);
});
