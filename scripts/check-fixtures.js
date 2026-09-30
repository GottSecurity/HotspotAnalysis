"use strict";

const path = require("path");
const { assertCatalog, allSearches, STEPS } = require("../library/catalog");
const { scanRepo } = require("../scanner/scan");

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

async function main() {
  assertCatalog();
  if (STEPS.length !== 16) fail(`Expected 16 steps, found ${STEPS.length}`);
  for (const item of allSearches()) {
    if (item.regex.includes("(?<=") || item.regex.includes("(?<!")) {
      fail(`Lookbehind in ${item.id}`);
    }
    if (!item.whatToCheck || !item.falsePositives || !item.why) {
      fail(`Missing review text for ${item.id}`);
    }
  }

  const result = await scanRepo(path.join(__dirname, "..", "test-fixtures"));
  const joined = result.hotspots
    .map((item) => `${item.file}\n${item.match}\n${item.category}\n${item.title}`)
    .join("\n");

  for (const word of ["SHOULD_NOT_SCAN", "LONG_LINE_SHOULD_SKIP"]) {
    if (joined.includes(word)) fail(`Scanned excluded content: ${word}`);
  }
  for (const hotspot of result.hotspots) {
    const parts = hotspot.file.split(/[/\\]/);
    if (parts.some((part) => ["node_modules", "dist", "generated", "target", "build"].includes(part))) {
      fail(`Scanned excluded path ${hotspot.file}`);
    }
    if (hotspot.file.endsWith(".min.js")) fail(`Scanned minified file ${hotspot.file}`);
  }

  const has = (predicate) => result.hotspots.some(predicate);
  if (!has((item) => item.category === "SQL Injection" && item.file.includes("node-sample") && item.sourceToSink)) {
    fail("Expected a Node SQL source-to-sink candidate");
  }
  if (!has((item) => item.category === "Command Injection" && item.file.includes("node-sample"))) {
    fail("Expected a Node command execution match");
  }
  if (!has((item) => item.category === "Secrets")) fail("Expected a secret match");
  if (!has((item) => item.match.includes("permitAll"))) fail("Expected permitAll");
  if (!has((item) => item.match.includes("GetMapping") || item.match.includes("RestController"))) {
    fail("Expected a Spring mapping");
  }
  if (!has((item) => item.category === "Command Injection" && item.file.includes("java-sample"))) {
    fail("Expected a Java command execution match");
  }
  if (!has((item) => item.match.includes("ObjectInputStream"))) fail("Expected ObjectInputStream");
  if (!has((item) => item.match.includes("DocumentBuilderFactory"))) fail("Expected an XML factory");
  if (!has((item) => item.file.includes("application.properties"))) fail("Expected a configuration match");
  if (result.filesScanned < 4) fail(`Too few files scanned: ${result.filesScanned}`);

  if (process.exitCode) {
    console.error(joined);
    return;
  }
  console.log(`OK ${result.filesScanned} files, ${result.hotspotCount} hotspots`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
