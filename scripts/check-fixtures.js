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
  if (!has((item) => item.title === "Classic Spring Security rules" && item.match.includes("antMatchers"))) {
    fail("Expected a classic Spring Security match");
  }
  if (!has((item) => item.title === "Classic Spring MVC handlers" && item.match.includes("ModelAndView"))) {
    fail("Expected a classic Spring MVC match");
  }
  if (!has((item) => item.title === "Classic form binding" && item.match.includes("ModelAttribute"))) {
    fail("Expected classic form binding");
  }
  if (!has((item) => item.title === "Classic Spring ORM queries")) fail("Expected a classic Spring ORM match");
  if (!has((item) => item.title === "Spring view redirects" && item.match.includes("RedirectView"))) {
    fail("Expected a Spring redirect view");
  }
  if (!has((item) => item.title === "Spring expression evaluation" && item.match.includes("parseExpression"))) {
    fail("Expected a Spring expression match");
  }
  if (!has((item) => item.title === "Spring Security bypasses" && item.match.includes("csrf.disable"))) {
    fail("Expected a Spring Security bypass");
  }
  if (!has((item) => item.title === "Spring Security OAuth and JWT" && item.match.includes("oauth2ResourceServer"))) {
    fail("Expected a Spring Security OAuth match");
  }
  if (!has((item) => item.title === "Spring HTTP APIs" && item.match.includes("GetExchange"))) {
    fail("Expected a Spring HTTP API match");
  }
  if (!has((item) => item.file.includes("python-sample") && item.title === "Python SQL execution")) {
    fail("Expected a Python SQL match");
  }
  if (!has((item) => item.file.includes("python-sample") && item.category === "Command Injection")) {
    fail("Expected a Python command execution match");
  }
  if (!has((item) => item.file.includes("js-sample") && item.title === "Browser location and document sources")) {
    fail("Expected a browser location source");
  }
  if (!has((item) => item.file.includes("js-sample") && item.title === "DOM HTML insertion" && item.match.includes("insertAdjacentHTML"))) {
    fail("Expected a DOM HTML sink");
  }
  if (!has((item) => item.file.includes("js-sample") && item.title === "postMessage handlers")) {
    fail("Expected a postMessage match");
  }
  if (!has((item) => item.file.includes("js-sample") && item.title === "Browser location changes")) {
    fail("Expected a browser redirect");
  }
  if (!has((item) => item.file.includes("js-sample") && item.title === "Prototype pollution")) {
    fail("Expected a prototype pollution match");
  }
  if (!has((item) => item.file.includes("js-sample") && item.title === "eval and Function")) {
    fail("Expected a JavaScript eval match");
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
