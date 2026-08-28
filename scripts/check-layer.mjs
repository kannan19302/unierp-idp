#!/usr/bin/env node
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const idpRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const gate = resolve(idpRoot, "..", "unierp-workspace", "scripts", "check-layer.mjs");
if (!existsSync(gate)) {
  console.error(`Active-estate layer gate is unavailable at ${gate}. Check out unierp-workspace beside idp.`);
  process.exit(1);
}
const result = spawnSync(process.execPath, [gate, "--repo-root", idpRoot], { stdio: "inherit" });
process.exit(result.status ?? 1);
