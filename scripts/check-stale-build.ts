#!/usr/bin/env bun
/**
 * Checks if dist/ is stale (older than src/).
 *
 * Prevents testing against outdated compiled code. Run automatically before tests.
 *
 * Run: bun run scripts/check-stale-build.ts
 */

import { statSync, existsSync, readdirSync } from "fs";
import { resolve, dirname, join } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, "..");

const srcDir = join(projectRoot, "src");
const distDir = join(projectRoot, "dist");

// Check if dist/ exists
if (!existsSync(distDir)) {
  console.error("❌ dist/ directory does not exist. Run 'npm run build' first.");
  process.exit(1);
}

// Get the most recent modification time in src/
function getNewestMtime(dir: string): number {
  let newest = 0;

  function walk(d: string) {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const fullPath = join(d, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules" && entry.name !== "__tests__") {
          walk(fullPath);
        }
      } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
        const mtime = statSync(fullPath).mtimeMs;
        if (mtime > newest) newest = mtime;
      }
    }
  }

  walk(dir);
  return newest;
}

// Get the newest modification time in dist/ (excluding tests)
function getDistNewestMtime(dir: string): number {
  let newest = 0;

  function walk(d: string) {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const fullPath = join(d, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "__tests__") {
          walk(fullPath);
        }
      } else if (entry.name.endsWith(".js")) {
        const mtime = statSync(fullPath).mtimeMs;
        if (mtime > newest) newest = mtime;
      }
    }
  }

  walk(dir);
  return newest;
}

const srcNewest = getNewestMtime(srcDir);
const distNewest = getDistNewestMtime(distDir);

// If the newest src file is newer than the newest dist file, build is stale
if (srcNewest > distNewest) {
  const srcDate = new Date(srcNewest).toLocaleString();
  const distDate = new Date(distNewest).toLocaleString();
  console.error("❌ dist/ is stale! Source files are newer than compiled output.");
  console.error(`   Newest src/ file: ${srcDate}`);
  console.error(`   Newest dist/ file: ${distDate}`);
  console.error("\n   Run 'npm run build' to rebuild.");
  process.exit(1);
}

console.log("✅ dist/ is up to date");
