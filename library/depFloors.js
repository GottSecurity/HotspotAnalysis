"use strict";

/**
 * Current registry releases read on 2026-10-01.
 * A lower declared version is a review note, not a vulnerability.
 * Packages marked always are reviewed at every version.
 */

const SNAPSHOT = "2026-10-01";

const NODE_FLOORS = [
  { name: "axios", floor: "1.20.0" },
  { name: "bcrypt", floor: "6.0.0" },
  { name: "body-parser", floor: "2.3.0" },
  { name: "cookie-parser", floor: "1.4.7" },
  { name: "cors", floor: "2.8.6" },
  { name: "csurf", floor: "1.11.0", always: true, note: "Archived. Review any version." },
  { name: "dotenv", floor: "18.0.5" },
  { name: "ejs", floor: "6.0.1" },
  { name: "express", floor: "5.2.1" },
  { name: "express-fileupload", floor: "1.5.2" },
  { name: "express-flash", floor: "0.0.2" },
  { name: "express-session", floor: "1.19.0" },
  { name: "flash", floor: "1.1.0" },
  { name: "handlebars", floor: "4.7.9" },
  { name: "helmet", floor: "8.3.0" },
  { name: "jsonwebtoken", floor: "9.0.3" },
  { name: "libxmljs", floor: "1.0.11" },
  { name: "lodash", floor: "4.18.1" },
  { name: "mathjs", floor: "15.2.0" },
  { name: "md5", floor: "2.3.0", always: true, note: "MD5 is a weak hash. Review any version." },
  { name: "minimist", floor: "1.2.8" },
  { name: "mongoose", floor: "9.10.3" },
  { name: "morgan", floor: "1.12.1" },
  { name: "multer", floor: "2.4.0" },
  { name: "mysql2", floor: "3.24.5" },
  { name: "node-fetch", floor: "3.3.2" },
  { name: "node-serialize", floor: "0.0.4", always: true, note: "Turns serialized data into code. Review any version." },
  { name: "nodemailer", floor: "10.0.13" },
  { name: "passport", floor: "0.7.0" },
  { name: "passport-local", floor: "1.0.0" },
  { name: "pg", floor: "8.23.1" },
  { name: "qs", floor: "6.16.0" },
  { name: "request", floor: "2.88.2", always: true, note: "Deprecated. Review any version." },
  { name: "sequelize", floor: "6.37.8" },
  { name: "serialize-javascript", floor: "7.1.2" },
  { name: "socket.io", floor: "4.8.4" },
  { name: "winston", floor: "3.19.0" },
  { name: "ws", floor: "8.22.0" },
  { name: "x-xss-protection", floor: "2.0.0", note: "Sets a retired browser header." },
  { name: "xml2js", floor: "0.6.2" },
];

const JAVA_FLOORS = [
  { name: "bcprov-jdk18on", floor: "1.86" },
  { name: "commons-beanutils", floor: "1.11.0" },
  { name: "commons-codec", floor: "1.22.1" },
  { name: "commons-collections", floor: "3.2.2", note: "Last 3.x release. Prefer commons-collections4." },
  { name: "commons-collections4", floor: "4.6.0" },
  { name: "commons-compress", floor: "1.28.0" },
  { name: "commons-fileupload", floor: "1.6.0" },
  { name: "commons-io", floor: "2.22.0" },
  { name: "commons-text", floor: "1.15.0" },
  { name: "dom4j", floor: "2.2.0" },
  { name: "gson", floor: "2.14.0" },
  { name: "guava", floor: "33.7.2-jre" },
  { name: "h2", floor: "2.5.252" },
  { name: "hibernate-core", floor: "7.4.11.Final", note: "Current line is org.hibernate.orm." },
  { name: "httpclient", floor: "4.5.14", note: "The 5.x client is the artifact httpclient5." },
  { name: "httpclient5", floor: "5.6.4" },
  { name: "jackson-core", floor: "2.22.3" },
  { name: "jackson-databind", floor: "2.22.3" },
  { name: "java-jwt", floor: "4.6.1" },
  { name: "jetty-server", floor: "12.1.13" },
  { name: "jjwt-api", floor: "0.13.0" },
  { name: "jsoup", floor: "1.23.2" },
  { name: "log4j-api", floor: "2.26.1" },
  { name: "log4j-core", floor: "2.26.1" },
  { name: "logback-classic", floor: "1.6.5" },
  { name: "mysql-connector-j", floor: "26.7.0" },
  { name: "netty-codec-http", floor: "4.2.18.Final" },
  { name: "netty-handler", floor: "4.2.18.Final" },
  { name: "nimbus-jose-jwt", floor: "10.10" },
  { name: "okhttp", floor: "5.5.0" },
  { name: "postgresql", floor: "42.7.13" },
  { name: "shiro-core", floor: "3.0.1" },
  { name: "snakeyaml", floor: "2.7" },
  { name: "spring-boot-starter-parent", floor: "4.1.1" },
  { name: "spring-core", floor: "7.0.9" },
  { name: "spring-security-core", floor: "7.1.1" },
  { name: "spring-security-web", floor: "7.1.1" },
  { name: "spring-webmvc", floor: "7.0.9" },
  { name: "tomcat-embed-core", floor: "11.0.26" },
  { name: "xstream", floor: "1.4.21" },
];

const PYTHON_FLOORS = [
  { name: "aiohttp", floor: "3.14.3" },
  { name: "beautifulsoup4", floor: "4.15.0" },
  { name: "celery", floor: "5.6.3" },
  { name: "certifi", floor: "2026.7.22" },
  { name: "click", floor: "8.5.0" },
  { name: "cryptography", floor: "50.0.2" },
  { name: "django", floor: "6.1.1" },
  { name: "django-cors-headers", floor: "4.9.0" },
  { name: "djangorestframework", floor: "3.18.1" },
  { name: "fastapi", floor: "0.142.2" },
  { name: "flask", floor: "3.1.3" },
  { name: "flask-cors", floor: "6.0.5" },
  { name: "gunicorn", floor: "26.2.0" },
  { name: "httplib2", floor: "0.32.0" },
  { name: "itsdangerous", floor: "2.2.0" },
  { name: "jinja2", floor: "3.1.6" },
  { name: "lxml", floor: "6.1.3" },
  { name: "markupsafe", floor: "3.0.3" },
  { name: "paramiko", floor: "5.0.0" },
  { name: "passlib", floor: "1.7.4" },
  { name: "pillow", floor: "12.3.0" },
  { name: "pycrypto", floor: "2.6.1", always: true, note: "Abandoned. Review any version." },
  { name: "pycryptodome", floor: "3.23.0" },
  { name: "pydantic", floor: "2.13.5" },
  { name: "pyjwt", floor: "2.15.1" },
  { name: "python-multipart", floor: "0.0.32" },
  { name: "pyyaml", floor: "6.0.3" },
  { name: "redis", floor: "8.1.0" },
  { name: "requests", floor: "2.34.2" },
  { name: "setuptools", floor: "84.0.0" },
  { name: "sqlalchemy", floor: "2.1.1" },
  { name: "starlette", floor: "1.7.0" },
  { name: "tornado", floor: "6.5.10" },
  { name: "urllib3", floor: "2.8.0" },
  { name: "uvicorn", floor: "0.54.0" },
  { name: "werkzeug", floor: "3.1.9" },
];

function escapeName(name) {
  return name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function alternation(rows) {
  return rows
    .map((row) => row.name)
    .sort((a, b) => b.length - a.length)
    .map(escapeName)
    .join("|");
}

function nodeRegex() {
  return `"((?:${alternation(NODE_FLOORS)}))"\\s*:`;
}

function javaRegex() {
  const names = alternation(JAVA_FLOORS);
  return `<artifactId>((?:${names}))</artifactId>|['"][\\w.$-]+:((?:${names})):[^'"]+['"]`;
}

function pythonRegex() {
  const names = alternation(PYTHON_FLOORS);
  return `^\\s*(?:${names})(?:\\[[^\\]]*\\])?\\s*(?:==|>=|~=|!=|<=|>|<)\\s*[0-9]|^\\s*(?:${names})\\s*=\\s*["'][\\^~>=<!]*[0-9]|["'](?:${names})(?:\\[[^\\]]*\\])?(?:==|>=|~=|!=|<=|>|<)[0-9]`;
}

function pythonManifest(base) {
  const name = String(base || "").toLowerCase();
  return name === "pipfile" || name === "pyproject.toml" || /^requirements.*\.txt$/.test(name);
}

function parts(spec) {
  const match = String(spec || "").match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3] || 0)];
}

function below(declared, floor) {
  const left = parts(declared);
  const right = parts(floor);
  if (!left || !right) return null;
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index];
  }
  return false;
}

function indexFloors(rows) {
  const map = new Map();
  for (const row of rows) map.set(row.name.toLowerCase(), row);
  return map;
}

const NODE_MAP = indexFloors(NODE_FLOORS);
const JAVA_MAP = indexFloors(JAVA_FLOORS);
const PYTHON_MAP = indexFloors(PYTHON_FLOORS);

function versionLine(declared, knownGood, note) {
  const extra = note ? ` ${note}` : "";
  return {
    reportedVersion: declared,
    knownGood,
    versionNote: note || "",
    why: `Reported Version: ${declared}, Last Known Good: ${knownGood}.${extra}`,
  };
}

function clientFloors(rows) {
  return rows.map((row) => ({
    name: row.name,
    floor: row.floor,
    note: row.note || "",
    always: row.always === true,
  }));
}

function decide(map, name, declared) {
  const row = map.get(String(name).toLowerCase());
  if (!row || !declared) return { keep: false };
  const line = versionLine(declared, row.floor, row.note || (row.always ? "Review any version." : ""));
  if (row.always) return { keep: true, priority: "High", ...line };
  const older = below(declared, row.floor);
  if (older === null) {
    return { keep: true, priority: "Low", ...versionLine(declared, row.floor, "The declared version could not be compared.") };
  }
  if (!older) return { keep: false };
  return { keep: true, priority: "Medium", ...line };
}

function pythonSpec(line) {
  const patterns = [
    /^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*(?:==|>=|~=|!=|<=|>|<)\s*([0-9][^\s;\\]*)/i,
    /^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*=\s*["'][\^~>=<!]*([0-9][^"']*)/i,
    /["']([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?(?:==|>=|~=|!=|<=|>|<)([0-9][^"']*)/i,
  ];
  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match) return { name: match[1], declared: match[2] };
  }
  return null;
}

function judgeDependency(kind, line, lines, index) {
  if (kind === "node") {
    const match = line.match(/"([^"]+)"\s*:\s*"([^"]*)"/);
    if (!match) return { keep: false };
    return decide(NODE_MAP, match[1], match[2]);
  }
  if (kind === "python") {
    const spec = pythonSpec(line);
    if (!spec) return { keep: false };
    return decide(PYTHON_MAP, spec.name, spec.declared);
  }
  const gradle = line.match(/['"][\w.$-]+:([\w.-]+):([^'"]+)['"]/);
  if (gradle) return decide(JAVA_MAP, gradle[1], gradle[2]);
  const pom = line.match(/<artifactId>([\w.-]+)<\/artifactId>/);
  if (!pom) return { keep: false };
  const window = lines.slice(index + 1, index + 8);
  let declared = "";
  for (const next of window) {
    const version = next.match(/<version>([^<]+)<\/version>/);
    if (version) {
      declared = version[1].trim();
      break;
    }
    if (next.includes("</dependency>") || next.includes("</parent>") || next.includes("<artifactId>")) break;
  }
  if (!declared) return { keep: false };
  if (declared.includes("${")) {
    const row = JAVA_MAP.get(pom[1].toLowerCase());
    if (!row) return { keep: false };
    return { keep: true, priority: "Low", ...versionLine(declared, row.floor, "Version is a Maven property.") };
  }
  return decide(JAVA_MAP, pom[1], declared);
}

module.exports = {
  SNAPSHOT,
  NODE_FLOORS,
  JAVA_FLOORS,
  PYTHON_FLOORS,
  nodeRegex,
  javaRegex,
  pythonRegex,
  pythonManifest,
  clientFloors,
  judgeDependency,
};
