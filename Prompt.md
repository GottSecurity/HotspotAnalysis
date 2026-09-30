Build a local, read-only Security Hotspot Navigator for reviewing Node.js, Java, and Spring Boot repositories.

GOAL

Create a lightweight local web application that scans a selected source-code repository for security-sensitive code patterns and presents likely hotspots in an easy-to-navigate HTML interface.

This is NOT an autonomous vulnerability scanner and must NOT modify the target repository.

The tool should:

* Find likely security hotspots.
* Show why each hotspot matters.
* Show filename and line number.
* Show a small surrounding code snippet.
* Categorize findings.
* Rank findings by likely security impact.
* Let the human reviewer decide whether something is actually vulnerable.

SUPPORTED TECHNOLOGIES

Support these initially:

1. Node.js / JavaScript / TypeScript
2. Java
3. Spring Boot / Spring MVC / Spring Security

ARCHITECTURE

Use a simple local architecture:

* Local Node.js web server.
* HTML/CSS/JavaScript frontend.
* Runs only on localhost.
* Target repository should be provided when starting the server or through a local path field.
* Recursively scan source files.
* Exclude:

  * node_modules
  * target
  * build
  * dist
  * .git
  * generated files
  * minified JavaScript
* Never modify files in the target repository.

Example startup:

node server.js --repo "C:\code\interview-repo"

Then open:

http://localhost:3000

INTERFACE

Create a dark-mode HTML interface optimized for fast security code review.

At the top provide dropdowns for:

Language:

* All
* Node.js
* Java
* Spring Boot

Security category:

* All
* Authentication
* Authorization / IDOR / BOLA
* SQL Injection
* NoSQL Injection
* Command Injection
* XSS
* Path Traversal
* File Upload
* SSRF
* XXE
* Deserialization
* Secrets
* Cryptography
* Password Handling
* Session / Cookies
* CORS
* CSRF
* Open Redirect
* Mass Assignment
* Logging / Sensitive Data
* Dependency / Configuration

Severity / review priority:

* Critical
* High
* Medium
* Low
* All

Also provide:

* Search box
* Filename filter
* "Show only likely sinks"
* "Show only likely sources"
* "Show source-to-sink candidates"

HOTSPOT DISPLAY

Each result should be a collapsible section.

Collapsed form:

[HIGH] SQL Injection
src/controllers/UserController.java:84
JdbcTemplate.query(...)
Reason: User-controlled value may reach SQL execution.

Expanded form should show:

* Filename
* Line number
* Language/framework
* Category
* Priority
* Source pattern, if present
* Sink pattern
* 5-10 lines of surrounding code
* Why this code is security-sensitive
* What the reviewer should verify
* Typical secure alternative

Do NOT claim that a hotspot is definitely vulnerable unless the code proves it.

Use wording like:

"Potential SQL injection sink"
"Review whether this value is user controlled"
"Verify authorization is enforced before accessing this object"

SOURCE / SINK ANALYSIS

Where practical, identify nearby source-to-sink relationships.

Examples of sources:

Node:

* req.body
* req.query
* req.params
* req.headers
* req.cookies
* request data
* uploaded filenames

Spring:

* @RequestParam
* @PathVariable
* @RequestBody
* @RequestHeader
* MultipartFile
* HttpServletRequest
* Cookie
* request.getParameter()

Java:

* servlet request parameters
* command-line input
* files
* environment variables
* network input

Examples of security-sensitive sinks:

DATABASE

Node:

* query()
* execute()
* raw()
* sequelize.query()
* knex.raw()
* mongoose queries using user-created objects

Java/Spring:

* Statement.execute*
* createStatement()
* nativeQuery
* EntityManager.createNativeQuery()
* JdbcTemplate usage
* string-built SQL/HQL/JPQL

COMMAND EXECUTION

Node:

* child_process.exec
* execSync
* spawn
* spawnSync

Java:

* Runtime.exec
* ProcessBuilder

FILES

Node:

* fs.readFile
* fs.writeFile
* createReadStream
* createWriteStream
* path.join / resolve with user input

Java:

* File
* Paths.get
* Files.read*
* Files.write*
* MultipartFile.transferTo

NETWORK / SSRF

Node:

* fetch
* axios
* http.request
* https.request

Java:

* URL
* URI
* HttpClient
* RestTemplate
* WebClient
* URLConnection

XSS / HTML

Node:

* innerHTML
* dangerouslySetInnerHTML
* res.send with user-controlled HTML
* template rendering without encoding

Java/Spring:

* writing directly to HTTP response
* constructing HTML strings
* unsafe template rendering

DESERIALIZATION

Java:

* ObjectInputStream
* readObject
* XMLDecoder
* unsafe Jackson polymorphic configuration

Node:

* eval
* Function()
* unsafe YAML/deserialization packages
* JSON-derived dynamic execution

XXE

Java:

* DocumentBuilderFactory
* SAXParserFactory
* XMLInputFactory
* TransformerFactory

Flag XML parser creation where external entities / DTD processing are not clearly disabled.

AUTHORIZATION

Search for routes/controllers that:

* retrieve objects by ID
* update objects by ID
* delete objects by ID
* receive accountId, userId, customerId, orderId, documentId, etc.

Then highlight whether nearby authorization checks appear present.

Spring patterns:

* @PreAuthorize
* @PostAuthorize
* @Secured
* hasRole
* hasAuthority
* SecurityContext
* principal checks

Node patterns:

* auth middleware
* role middleware
* owner/user ID comparisons
* permission checks

Do not automatically declare missing authorization solely because an annotation isn't present. Authorization may be enforced elsewhere.

SECRETS

Look for:

* passwords
* API keys
* tokens
* private keys
* connection strings
* AWS credentials
* JWT secrets
* database credentials

Especially detect suspicious literal assignments.

CRYPTO

Look for:

* MD5
* SHA1
* ECB
* DES
* hardcoded IVs
* hardcoded encryption keys
* predictable random numbers
* java.util.Random used for security tokens
* Math.random used for security tokens

SESSION / COOKIES

Review:

* secure
* httpOnly
* SameSite
* session ID generation
* JWT expiration
* JWT signature verification
* algorithm selection

MASS ASSIGNMENT

Spring:

* directly binding request bodies into persistence/domain entities

Node:

* spreading req.body into database update objects
* Object.assign with request data
* Model.update(req.body)
* save(req.body)

OPEN REDIRECT

Look for redirects based on request parameters.

CORS

Look for:

* Access-Control-Allow-Origin: *
* permissive CORS middleware
* @CrossOrigin("*")
* credentials combined with overly broad origins

LOGGING

Flag likely sensitive values being logged:

* passwords
* access tokens
* authorization headers
* SSNs
* credit-card values
* secrets

SPRING-SPECIFIC HOTSPOTS

Explicitly detect:

* @RequestMapping
* @GetMapping
* @PostMapping
* @PutMapping
* @PatchMapping
* @DeleteMapping
* @RequestParam
* @PathVariable
* @RequestBody
* @Controller
* @RestController
* @Repository
* @Service

Highlight controllers first because they define external entry points.

Also identify security configuration:

* SecurityFilterChain
* HttpSecurity
* authorizeHttpRequests
* requestMatchers
* permitAll
* csrf
* cors
* sessionManagement

Highlight any use of permitAll because it deserves human review, but do not automatically label it vulnerable.

PRIORITY MODEL

Prioritize likely high-impact issues roughly in this order:

1. Authentication bypass
2. Authorization / IDOR / BOLA
3. Command execution
4. SQL / NoSQL injection
5. Arbitrary file write / upload
6. Path traversal
7. SSRF
8. Unsafe deserialization
9. XXE
10. Hardcoded secrets
11. XSS
12. Mass assignment
13. Weak cryptography
14. Session / cookie problems
15. CSRF
16. CORS
17. Open redirect
18. Information leakage / logging
19. Security headers
20. General configuration issues

Do not treat this ordering as absolute. Context determines actual risk.

REVIEW MODE

Add a special "Interview Review" view.

It should display the checklist:

1. External entry points
2. Authentication
3. Authorization / object ownership
4. Database queries
5. OS command execution
6. File operations / uploads
7. Outbound network requests
8. Deserialization / XML
9. Secrets / crypto
10. XSS / HTML output
11. Mass assignment
12. Sessions / JWT / cookies
13. CSRF / CORS
14. Logging / sensitive data
15. Dependencies / configuration

Each item should be collapsible and show matching hotspots.

Allow the reviewer to mark each category:

[ ] Not reviewed
[ ] Reviewed
[ ] Issue found
[ ] No obvious issue

Provide a visible progress counter such as:

8 / 15 categories reviewed

TRIAGE VIEW

Provide another view called "Top Hotspots."

Show no more than approximately 20 high-value findings initially.

Prefer:

* externally reachable code
* user-controlled input
* dangerous sinks
* missing or questionable authorization
* high-impact operations

Do not drown the reviewer in hundreds of low-value regex matches.

SCORING

Each hotspot can receive an internal confidence score based on evidence:

High confidence:
Source and dangerous sink appear in the same function or obvious short path.

Medium confidence:
Dangerous sink exists and user-controlled input may plausibly reach it.

Low confidence:
Security-sensitive API exists but exploitability cannot be inferred.

Display this as:

Confidence: High / Medium / Low

Do not present CVSS scores.

IMPLEMENTATION QUALITY

Keep the implementation small and understandable.

Prefer simple static pattern scanning over building a full AST engine initially.

Structure the scanner so AST-based analysis could be added later.

Example:

scanner/
nodeScanner.js
javaScanner.js
springScanner.js
patterns.js
sourceSink.js

ui/
index.html
app.js
styles.css

server.js

README.md

TEST DATA

Create a small separate sample repository under test-fixtures containing deliberately insecure Node and Java/Spring examples.

Do not mix intentionally vulnerable fixtures into the scanner's production code.

README

Document:

* installation
* startup
* supported languages
* hotspot categories
* limitations
* false-positive expectations
* how source/sink heuristics work

Important disclaimer:

"This tool identifies code that deserves security review. A hotspot is not necessarily a vulnerability."

FIRST IMPLEMENTATION

Build the MVP first:

1. Local server
2. Repository traversal
3. Node/Java/Spring classification
4. Pattern detection
5. Hotspot JSON model
6. Dark HTML UI
7. Dropdown filtering
8. Collapsible findings
9. Interview Review checklist
10. Top Hotspots view

After the MVP works, improve source-to-sink correlation.

Do not over-engineer the first version.



Add two operating modes to the Security Hotspot Navigator:

# PASSIVE MODE

Passive Mode does NOT inspect, scan, parse, or analyze the target repository.

Its purpose is to act as an interactive security code-review reference during a manual review.

The user selects:

Language / Framework:

* Node.js / JavaScript / TypeScript
* Java
* Spring Boot / Spring MVC / Spring Security

Then display:

1. Recommended review checklist, in priority order
2. Security categories to investigate
3. Important keywords and APIs
4. Copy/paste search expressions
5. Regex searches
6. Explanation of what each search is attempting to find
7. Common false positives
8. What to inspect after a match is found

Provide search formats suitable for:

* Visual Studio Code global search
* Notepad++ Find in Files
* Node / terminal environments
* ripgrep (`rg`) when installed

Prefer regex patterns that work consistently across VS Code, Notepad++, JavaScript regex, and ripgrep.

Avoid complicated regex features such as variable-length lookbehind.

Each Passive Mode section should be collapsible.

At the top, provide:

Language: [Node.js]
Category: [All]
Search Type: [Keywords | Regex | Checklist]
Tool: [VS Code | Notepad++ | ripgrep]

Also provide:

[Copy Search]

for every regex or keyword expression.

---

# PASSIVE REVIEW ORDER

Display this checklist prominently:

1. External entry points
2. Authentication
3. Authorization / IDOR / BOLA
4. Database access
5. OS command execution
6. File handling / uploads
7. Outbound network requests / SSRF
8. Deserialization / XML
9. Secrets
10. XSS / HTML output
11. Mass assignment
12. Cryptography / randomness
13. Sessions / JWT / cookies
14. CSRF / CORS
15. Sensitive logging
16. Dependencies and configuration

Allow each item to be marked:

[ ] Not reviewed
[ ] Reviewing
[ ] Issue found
[ ] Reviewed

---

# NODE.JS PASSIVE SEARCH LIBRARY

## ENTRY POINTS

Keywords:

req.body
req.query
req.params
req.headers
req.cookies
router.get
router.post
router.put
router.patch
router.delete
app.get
app.post

Regex:

(req.(body|query|params|headers|cookies)|router.(get|post|put|patch|delete)|app.(get|post|put|patch|delete))

Review:

* What input enters here?
* Is validation performed?
* Is authentication required?
* Is authorization checked?
* Where does the value flow?

---

## SQL / DATABASE

Keywords:

query(
execute(
raw(
sequelize.query
knex.raw
findOne
findById
updateOne
deleteOne

Regex:

(query|execute|raw|sequelize.query|knex.raw|findOne|findById|updateOne|deleteOne)\s*(

Also search for SQL strings:

(SELECT|INSERT|UPDATE|DELETE)\s+

Look especially for:

query("SELECT ... " + userInput)

or:

`SELECT ... ${value}`

Review whether user-controlled input reaches database execution without parameterization.

---

## COMMAND EXECUTION

Keywords:

child_process
exec
execSync
spawn
spawnSync

Regex:

(child_process|execSync|exec|spawnSync|spawn)\s*(

High-priority review.

Determine whether request data can influence:

* command
* executable
* arguments

---

## FILE OPERATIONS

Keywords:

readFile
writeFile
unlink
createReadStream
createWriteStream
path.join
path.resolve
multer

Regex:

(readFile|writeFile|unlink|createReadStream|createWriteStream|path.(join|resolve)|multer)\s*(

Then investigate whether:

req.params
req.query
req.body
uploaded filenames

influence the path.

---

## SSRF / OUTBOUND REQUESTS

Keywords:

fetch
axios
http.request
https.request
got
request

Regex:

(fetch|axios.(get|post|put|delete)|https?.request|got)\s*(

Review whether the URL or hostname is influenced by request input.

---

## XSS

Keywords:

innerHTML
outerHTML
document.write
dangerouslySetInnerHTML
res.send

Regex:

(innerHTML|outerHTML|document.write|dangerouslySetInnerHTML|res.send)

Review whether attacker-controlled data reaches HTML output without encoding.

---

## DYNAMIC EXECUTION

Keywords:

eval
Function

Regex:

(eval|Function)\s*(

Treat matches as high-priority review points.

---

## MASS ASSIGNMENT

Keywords:

req.body
Object.assign
...req.body
update(req.body)
save(req.body)

Regex:

(Object.assign|...req.body|update\s*(\s*req.body|save\s*(\s*req.body)

Review whether attacker-controlled properties can modify:

* roles
* permissions
* ownership
* account IDs
* admin flags
* internal state

---

## SECRETS

Regex:

(password|passwd|secret|api[*-]?key|token|jwt[*-]?secret|private[_-]?key)\s*[:=]\s*["'][^"']+["']

Also search keywords:

password
secret
token
apiKey
API_KEY
JWT_SECRET
PRIVATE_KEY

Do not automatically classify every match as a secret.

---

## JWT / SESSION

Keywords:

jwt.sign
jwt.verify
jsonwebtoken
express-session
cookie
httpOnly
secure
sameSite

Regex:

(jwt.(sign|verify)|jsonwebtoken|express-session|httpOnly|sameSite)

Review:

* signature verification
* expiration
* algorithm handling
* cookie flags
* secret handling

---

# JAVA PASSIVE SEARCH LIBRARY

## INPUT SOURCES

Keywords:

getParameter
getHeader
getCookies
getInputStream
Scanner
BufferedReader

Regex:

(getParameter|getHeader|getCookies|getInputStream|Scanner|BufferedReader)

---

## SQL

Keywords:

createStatement
executeQuery
executeUpdate
prepareStatement
createNativeQuery

Regex:

(createStatement|executeQuery|executeUpdate|prepareStatement|createNativeQuery)\s*(

Pay special attention to string concatenation surrounding SQL.

Additional search:

(SELECT|INSERT|UPDATE|DELETE).*(+|String.format)

---

## COMMAND EXECUTION

Keywords:

Runtime.getRuntime
exec
ProcessBuilder

Regex:

(Runtime.getRuntime|ProcessBuilder|.exec\s*()

Review immediately if user-controlled data reaches these APIs.

---

## FILE OPERATIONS

Keywords:

Paths.get
new File
Files.read
Files.write
FileInputStream
FileOutputStream

Regex:

(Paths.get|new\s+File|Files.(read|write)|FileInputStream|FileOutputStream)

Look for request-controlled paths and filenames.

---

## SSRF

Keywords:

new URL
URI.create
HttpClient
URLConnection
RestTemplate
WebClient

Regex:

(new\s+URL|URI.create|HttpClient|URLConnection|RestTemplate|WebClient)

---

## DESERIALIZATION

Keywords:

ObjectInputStream
readObject
XMLDecoder

Regex:

(ObjectInputStream|readObject\s*(|XMLDecoder)

Treat ObjectInputStream/readObject as high-value review targets.

---

## XXE

Keywords:

DocumentBuilderFactory
SAXParserFactory
XMLInputFactory
TransformerFactory

Regex:

(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)

After finding one, inspect whether:

* DTD processing is disabled
* external entities are disabled
* external schema access is disabled

---

## WEAK CRYPTO

Keywords:

MD5
SHA-1
SHA1
DES
ECB
java.util.Random

Regex:

(MD5|SHA-?1|DES|ECB|java.util.Random)

Review context before classifying.

---

# SPRING BOOT PASSIVE SEARCH LIBRARY

## EXTERNAL ENTRY POINTS

Keywords:

@RestController
@Controller
@RequestMapping
@GetMapping
@PostMapping
@PutMapping
@PatchMapping
@DeleteMapping

Regex:

@(RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)

This should generally be the FIRST Spring search.

---

## USER INPUT

Keywords:

@RequestParam
@PathVariable
@RequestBody
@RequestHeader
@CookieValue
MultipartFile

Regex:

@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)|MultipartFile

Use these matches to identify sources.

---

## AUTHORIZATION

Keywords:

@PreAuthorize
@PostAuthorize
@Secured
hasRole
hasAuthority
SecurityContext
Principal

Regex:

(@PreAuthorize|@PostAuthorize|@Secured|hasRole|hasAuthority|SecurityContext|Principal)

Also search for endpoints without assuming annotations are the only authorization mechanism.

---

## SECURITY CONFIGURATION

Keywords:

SecurityFilterChain
HttpSecurity
authorizeHttpRequests
requestMatchers
permitAll
authenticated
csrf
cors

Regex:

(SecurityFilterChain|HttpSecurity|authorizeHttpRequests|requestMatchers|permitAll|authenticated|csrf|cors)

Review every `permitAll` match.

Regex:

permitAll\s*(

Do NOT automatically call `permitAll` vulnerable.

Determine what endpoint or matcher it applies to.

---

## SPRING DATABASE ACCESS

Keywords:

JdbcTemplate
EntityManager
createNativeQuery
@Query

Regex:

(JdbcTemplate|EntityManager|createNativeQuery|@Query)

Search additionally for string-built queries:

(createNativeQuery|queryForObject|queryForList).*(+|${)

---

## MASS ASSIGNMENT / ENTITY BINDING

Search for request bodies directly bound to persistence objects.

Keywords:

@RequestBody
@Entity
save(

Useful workflow:

1. Find `@RequestBody`
2. Determine the receiving class
3. Determine whether it is an Entity or DTO
4. Determine whether sensitive properties can be supplied
5. Inspect calls to repository.save()

---

## FILE UPLOAD

Keywords:

MultipartFile
transferTo
getOriginalFilename

Regex:

(MultipartFile|transferTo|getOriginalFilename)

Review:

* filename handling
* extension validation
* MIME checks
* magic bytes
* storage location
* executable content
* path traversal

---

# AUTHORIZATION / IDOR MANUAL SEARCH

For all languages, provide a special IDOR/BOLA section.

Search keywords:

userId
accountId
customerId
orderId
documentId
profileId
ownerId

Regex:

(user|account|customer|order|document|profile|owner)Id

Workflow:

1. Find IDs entering from request parameters.
2. Find where the object is retrieved.
3. Find where authorization or ownership is checked.
4. Verify that authentication alone is not being mistaken for authorization.

This is inherently difficult to detect with regex and should be explicitly marked as a manual-review category.

---

# RIPGREP SUPPORT

For each regex also show a terminal example:

rg -n "<regex>" .

Examples:

rg -n "Runtime.getRuntime|ProcessBuilder|.exec\s*(" .

rg -n "@(RequestParam|PathVariable|RequestBody)" .

rg -n "req.(body|query|params)" .

Provide a button:

Copy rg Command

---

# PASSIVE UI

Use collapsible sections:

Authentication
Authorization / IDOR
SQL Injection
Command Injection
Files
SSRF
XSS
Deserialization
XXE
Secrets
Crypto
Sessions
Mass Assignment
CSRF / CORS
Logging
Configuration

Collapsed:

SQL Injection
8 searches

Expanded:

SQL Injection

KEYWORDS
query
execute
JdbcTemplate
createNativeQuery

REGEX
[regex expression] [COPY]

RIPGREP
[rg command] [COPY]

WHAT TO CHECK
Short explanation.

FALSE POSITIVES
Short explanation.

The Passive interface should be extremely fast to navigate and optimized for use during a timed interview.

# ACTIVE MODE

Active Mode uses the scanner previously defined.

It may:

* Traverse repository files
* Identify matching hotspot patterns
* Associate filenames and line numbers
* Show snippets
* Categorize matches
* Rank likely hotspots
* identify obvious nearby source/sink relationships

It must remain READ ONLY.

It must NEVER:

* modify source files
* automatically remediate code
* execute fixes
* generate commits
* autonomously rewrite the repository

Keep a highly visible toggle:

PASSIVE | ACTIVE

Default to PASSIVE mode.
