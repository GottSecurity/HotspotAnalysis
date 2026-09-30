"use strict";

/**
 * Review guide and scan patterns.
 * The regex strings are the same text a reviewer pastes into VS Code,
 * Notepad++, or ripgrep, and the same text Active mode runs.
 * They avoid variable-length lookbehind so those tools agree.
 */

const DISCLAIMER =
  "This tool identifies code that deserves security review. A hotspot is not necessarily a vulnerability.";

const LANGUAGES = [
  { id: "all", label: "All" },
  { id: "node", label: "Node.js" },
  { id: "java", label: "Java" },
  { id: "spring", label: "Spring / Spring Boot" },
];

const CATEGORIES = [
  "All",
  "External entry points",
  "Authentication",
  "Authorization / IDOR / BOLA",
  "SQL Injection",
  "NoSQL Injection",
  "Command Injection",
  "XSS",
  "Path Traversal",
  "File Upload",
  "SSRF",
  "XXE",
  "Deserialization",
  "Secrets",
  "Cryptography",
  "Password Handling",
  "Session / Cookies",
  "CORS",
  "CSRF",
  "Open Redirect",
  "Mass Assignment",
  "Logging / Sensitive Data",
  "Dependency / Configuration",
];

const PRIORITIES = ["All", "Critical", "High", "Medium", "Low"];

function search(entry) {
  return {
    role: "review",
    priority: "Medium",
    rank: 20,
    top: false,
    flags: "",
    keywords: [],
    onConfig: false,
    active: true,
    secureAlternative: "",
    ...entry,
  };
}

const STEPS = [
  {
    id: "entry",
    order: 1,
    title: "External entry points",
    summary: "Find where untrusted input enters the program.",
    guidance: [
      "Review available code and map every place a request can enter.",
      "List routes, controllers, servlets, and handlers that face the caller.",
      "Note parameters, headers, cookies, path variables, and uploaded files.",
    ],
    searches: [
      search({
        id: "node-entry",
        languages: ["node"],
        category: "External entry points",
        title: "Routes and request input",
        role: "source",
        priority: "High",
        rank: 20,
        keywords: [
          "req.body",
          "req.query",
          "req.params",
          "req.headers",
          "req.cookies",
          "router.get",
          "router.post",
          "router.put",
          "router.patch",
          "router.delete",
          "app.get",
          "app.post",
        ],
        regex:
          "(req\\.(body|query|params|headers|cookies)|router\\.(get|post|put|patch|delete)|app\\.(get|post|put|patch|delete))\\b",
        why: "These are common places request data enters a Node application.",
        whatToCheck:
          "What input enters here? Is validation performed? Is authentication required? Is authorization checked? Where does the value flow?",
        falsePositives:
          "Health checks, static file routes, and handlers that ignore the request object.",
        verify: "Open the handler and follow each request value to the next function.",
        secureAlternative:
          "Validate and allow-list input at the boundary, then pass only the fields the handler needs.",
      }),
      search({
        id: "spring-entry",
        languages: ["spring"],
        category: "External entry points",
        title: "Spring mappings",
        role: "source",
        priority: "High",
        rank: 20,
        keywords: [
          "@RestController",
          "@Controller",
          "@RequestMapping",
          "@GetMapping",
          "@PostMapping",
          "@PutMapping",
          "@PatchMapping",
          "@DeleteMapping",
        ],
        regex:
          "@(RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\\b",
        why: "Controller mappings are the external entry points of a Spring application.",
        whatToCheck:
          "Which methods are reachable without a session? Which path variables and parameters do they accept?",
        falsePositives:
          "Internal @Controller advice and mappings that only forward to a view with no user data.",
        verify: "Treat this as the first Spring search. List the routes before you chase sinks.",
        secureAlternative:
          "Keep request mappings obvious and put authorization on the operation, not only on the UI.",
      }),
      search({
        id: "spring-input",
        languages: ["spring"],
        category: "External entry points",
        title: "Spring request binding",
        role: "source",
        priority: "High",
        rank: 20,
        keywords: [
          "@RequestParam",
          "@PathVariable",
          "@RequestHeader",
          "@CookieValue",
          "MultipartFile",
          "HttpServletRequest",
        ],
        regex:
          "@(RequestParam|PathVariable|RequestHeader|CookieValue)\\b|\\bHttpServletRequest\\b",
        why: "These annotations and types mark values that come from the caller.",
        whatToCheck:
          "Record the parameter name and the method that receives it. That pair is a source for later sink checks.",
        falsePositives:
          "Headers or cookies that are only logged for diagnostics and never used in a decision or query.",
        verify: "Search the rest of the method for how the bound value is used.",
        secureAlternative:
          "Bind a narrow DTO and reject unexpected fields before any security decision.",
      }),
      search({
        id: "spring-mvc-classic",
        languages: ["spring"],
        category: "External entry points",
        title: "Classic Spring MVC handlers",
        role: "source",
        priority: "High",
        rank: 20,
        keywords: [
          "AbstractController",
          "MultiActionController",
          "SimpleFormController",
          "ModelAndView",
          "DispatcherServlet",
        ],
        regex:
          "\\b(AbstractController|MultiActionController|SimpleFormController|ModelAndView|DispatcherServlet)\\b",
        why: "Older Spring MVC apps expose requests through controller base classes, ModelAndView, and the dispatcher servlet, not only Boot mapping annotations.",
        whatToCheck:
          "List the handler method and the request values it reads. A ModelAndView name can also be a forward or redirect target.",
        falsePositives:
          "A dispatcher servlet declaration that only boots the context and never reads request data.",
        verify: "Open the handleRequest or form method and follow each request value.",
        secureAlternative:
          "Prefer explicit request mappings and bind only the fields the handler needs.",
      }),
      search({
        id: "java-input",
        languages: ["java"],
        category: "External entry points",
        title: "Servlet and stream input",
        role: "source",
        priority: "High",
        rank: 20,
        keywords: [
          "getParameter",
          "getHeader",
          "getCookies",
          "getInputStream",
          "getReader",
          "Scanner",
          "BufferedReader",
        ],
        regex:
          "\\b(getParameter|getHeader|getCookies|getInputStream|getReader)\\s*\\(",
        why: "Servlet parameter and header reads are untrusted input in a Java web application.",
        whatToCheck:
          "Note the parameter name and follow it into queries, file paths, commands, and outbound URLs.",
        falsePositives:
          "Reads of a fixed configuration key rather than a request parameter. Scanner and BufferedReader are keywords only because they also appear in local file code.",
        verify: "Confirm the receiver is the HTTP request, not a local file or test fixture.",
        secureAlternative:
          "Parse request values into a validated type before they reach a sink.",
      }),
    ],
  },
  {
    id: "authn",
    order: 2,
    title: "Authentication",
    summary: "Find how callers prove identity, and where that proof is skipped.",
    guidance: [
      "Find how a caller proves identity.",
      "Check which entry points require that proof, and which are open.",
      "Review password storage, token validation, and any explicit bypass.",
    ],
    searches: [
      search({
        id: "node-auth",
        languages: ["node"],
        category: "Authentication",
        title: "Node authentication checks",
        role: "review",
        priority: "Medium",
        rank: 20,
        keywords: [
          "passport",
          "jwt.verify",
          "isAuthenticated",
          "ensureLoggedIn",
          "requireAuth",
          "bcrypt",
        ],
        regex:
          "\\b(passport|isAuthenticated|ensureLoggedIn|requireAuth|bcrypt)\\b|jwt\\.verify\\s*\\(",
        why: "These calls show where Node code checks identity or stores passwords.",
        whatToCheck:
          "See whether sensitive routes use the check. A helper that exists but is not mounted leaves the route open.",
        falsePositives:
          "Authentication on a login route only, or a middleware file that is never registered with the app.",
        verify: "Confirm the middleware is attached to the routes you care about.",
        secureAlternative:
          "Require authentication by default and explicitly opt out public routes.",
      }),
      search({
        id: "spring-security-config",
        languages: ["spring"],
        category: "Authentication",
        title: "Spring Security configuration",
        role: "review",
        priority: "High",
        rank: 20,
        keywords: [
          "SecurityFilterChain",
          "HttpSecurity",
          "authorizeHttpRequests",
          "requestMatchers",
          "authenticated",
          "formLogin",
          "httpBasic",
        ],
        regex:
          "\\b(SecurityFilterChain|HttpSecurity|authorizeHttpRequests|requestMatchers|formLogin|httpBasic)\\b",
        why: "This is where Spring decides which requests must be authenticated.",
        whatToCheck:
          "Read the matcher chain from top to bottom. The first matching rule wins.",
        falsePositives:
          "A configuration class that is not a @Bean or is overridden in another profile.",
        verify: "List every requestMatchers clause and the rule it applies.",
        secureAlternative:
          "Authenticate by default and permit only the specific public paths you intend.",
      }),
      search({
        id: "spring-security-classic",
        languages: ["spring"],
        category: "Authentication",
        title: "Classic Spring Security rules",
        role: "review",
        priority: "High",
        rank: 20,
        keywords: [
          "WebSecurityConfigurerAdapter",
          "antMatchers",
          "mvcMatchers",
          "regexMatchers",
          "authorizeRequests",
          "AuthenticationManagerBuilder",
        ],
        regex:
          "\\b(WebSecurityConfigurerAdapter|antMatchers|mvcMatchers|regexMatchers|authorizeRequests|AuthenticationManagerBuilder)\\b",
        why: "Spring Security 5 and classic Spring apps decide access with WebSecurityConfigurerAdapter and antMatchers. Boot 3 replaced that style with SecurityFilterChain and requestMatchers. Both need the same review.",
        whatToCheck:
          "Read authorizeRequests from top to bottom. The first matching antMatchers rule wins.",
        falsePositives:
          "An adapter class that is not annotated as a configuration, or a matcher that only names a login page.",
        verify: "Pair each antMatchers or mvcMatchers path with permitAll, authenticated, or hasRole on that chain.",
        secureAlternative:
          "Authenticate by default. Permit only the specific public paths you intend.",
      }),
      search({
        id: "spring-permit-all",
        languages: ["spring"],
        category: "Authentication",
        title: "permitAll",
        role: "review",
        priority: "Critical",
        rank: 1,
        top: true,
        keywords: ["permitAll"],
        regex: "\\bpermitAll\\s*\\(",
        why: "permitAll turns authentication off for whatever matcher it is attached to. That deserves review. It is not automatically a vulnerability.",
        whatToCheck:
          "Identify the path, method, and matcher. Decide whether anonymous callers should reach that operation.",
        falsePositives:
          "Login, health, and static asset matchers that are intentionally public.",
        verify: "Read the requestMatchers (or antMatchers) expression on the same chain.",
        secureAlternative:
          "Replace a broad permitAll with a narrow public matcher and authenticated() for everything else.",
      }),
      search({
        id: "password-storage",
        languages: ["node", "java", "spring"],
        category: "Password Handling",
        title: "Password hashing APIs",
        role: "review",
        priority: "Medium",
        rank: 13,
        keywords: ["bcrypt", "scrypt", "pbkdf2", "BCryptPasswordEncoder", "PasswordEncoder", "password"],
        regex:
          "\\b(bcrypt|scrypt|pbkdf2|BCryptPasswordEncoder|PasswordEncoder|Pbkdf2PasswordEncoder)\\b",
        why: "Password storage should use a slow, salted password hash.",
        whatToCheck:
          "Confirm new passwords go through this API. A fast hash such as MD5 or SHA-1 is a separate finding under cryptography.",
        falsePositives:
          "A dependency import that is never called, or a hash used for a non-password checksum.",
        verify: "Find the registration and password-change path and read the hash call.",
        secureAlternative:
          "Use bcrypt, scrypt, argon2, or PBKDF2 with a unique salt. Do not use a bare message digest for passwords.",
      }),
    ],
  },
  {
    id: "authz",
    order: 3,
    title: "Authorization / IDOR / BOLA",
    summary: "A valid login does not decide which object the caller may touch.",
    guidance: [
      "Find identifiers that come from the request, such as user, account, order, or document ids.",
      "Find the line that loads or changes that object.",
      "Verify the code checks ownership or permission. Authentication alone is not authorization.",
    ],
    searches: [
      search({
        id: "idor-ids",
        languages: ["node", "java", "spring"],
        category: "Authorization / IDOR / BOLA",
        title: "Object identifiers",
        role: "source",
        priority: "Critical",
        rank: 2,
        top: true,
        keywords: [
          "userId",
          "accountId",
          "customerId",
          "orderId",
          "documentId",
          "profileId",
          "ownerId",
        ],
        regex: "\\b(user|account|customer|order|document|profile|owner)Id\\b",
        why: "Object ids from the caller are the usual starting point for insecure direct object reference and broken object level authorization. Regex cannot prove the bug.",
        whatToCheck:
          "1. Find ids that enter from the request. 2. Find where the object is retrieved. 3. Find where ownership or permission is checked. 4. Do not treat a logged-in user as authorized for every id.",
        falsePositives:
          "Ids taken from the server-side session or token rather than from the request. Names in comments and tests.",
        verify:
          "This category is manual. Stay on the method and look for an owner comparison or an authorization check before the object is returned or changed.",
        secureAlternative:
          "Load the object in a query that includes the caller's identity, or check a permission against that object before use.",
      }),
      search({
        id: "spring-authz",
        languages: ["spring"],
        category: "Authorization / IDOR / BOLA",
        title: "Spring authorization annotations",
        role: "review",
        priority: "Medium",
        rank: 2,
        keywords: [
          "@PreAuthorize",
          "@PostAuthorize",
          "@Secured",
          "hasRole",
          "hasAuthority",
          "SecurityContext",
          "Principal",
        ],
        regex:
          "(@PreAuthorize|@PostAuthorize|@Secured|\\bhasRole\\b|\\bhasAuthority\\b|\\bSecurityContext\\b)",
        why: "These are common Spring authorization checks. Their absence on one method does not mean the method is open. The check may live in a filter, a service, or a query.",
        whatToCheck:
          "If you see the annotation, read the expression. If you do not, look for a filter, an ownership comparison, or a repository query that includes the caller.",
        falsePositives:
          "hasRole on an admin screen while object ownership is enforced later in the service.",
        verify: "Do not file a missing-annotation bug from the regex alone.",
        secureAlternative:
          "Authorize the operation and the specific object. Role checks do not replace object checks.",
      }),
      search({
        id: "node-authz",
        languages: ["node"],
        category: "Authorization / IDOR / BOLA",
        title: "Node permission checks",
        role: "review",
        priority: "Medium",
        rank: 2,
        keywords: [
          "req.user",
          "requireRole",
          "hasPermission",
          "isOwner",
          "authorize",
        ],
        regex:
          "\\b(requireRole|hasPermission|isOwner|authorize)\\b|req\\.user\\b",
        why: "These hints show where a Node app might be checking the caller against a role or an owner.",
        whatToCheck:
          "Compare the authenticated user id with the owner of the object being read or changed.",
        falsePositives:
          "req.user read only to display a name, with no access decision.",
        verify: "Find the comparison. Presence of req.user is not an authorization check.",
        secureAlternative:
          "Compare the caller's id to the resource owner, or check a permission on that resource, on every object operation.",
      }),
    ],
  },
  {
    id: "database",
    order: 4,
    title: "Database access",
    summary: "Find queries and see whether untrusted data becomes part of the query text.",
    guidance: [
      "Find every query execution.",
      "Check whether SQL or query objects are built with concatenation, templates, or a user-supplied structure.",
      "Prefer bound parameters. Hand-built escaping is easy to get wrong.",
    ],
    searches: [
      search({
        id: "node-sql",
        languages: ["node"],
        category: "SQL Injection",
        title: "Node SQL execution",
        role: "sink",
        priority: "Critical",
        rank: 4,
        top: true,
        keywords: ["query(", "execute(", "raw(", "sequelize.query", "knex.raw"],
        regex: "\\b(query|execute|raw|sequelize\\.query|knex\\.raw)\\s*\\(",
        why: "Potential SQL injection sink. Review whether a user-controlled value is concatenated into the query text.",
        whatToCheck:
          "Look for string addition or a template literal around SELECT, INSERT, UPDATE, or DELETE. Bound placeholders such as ? or $1 are the safer pattern.",
        falsePositives:
          "query() and execute() calls that pass a constant SQL string and a separate parameter array.",
        verify: "Read the SQL string argument. If it is a single literal, this match is likely safe.",
        secureAlternative:
          "Pass the SQL text and the values separately: db.query('SELECT ... WHERE id = ?', [id]).",
      }),
      search({
        id: "node-sql-concat",
        languages: ["node"],
        category: "SQL Injection",
        title: "SQL built with concatenation or a template",
        role: "sink",
        priority: "Critical",
        rank: 4,
        top: true,
        keywords: ["SELECT", "INSERT", "UPDATE", "DELETE"],
        regex: "(SELECT|INSERT|UPDATE|DELETE)[^\\n]{0,80}(\\+|\\$\\{)",
        flags: "i",
        why: "The SQL text on this line is being assembled. If any piece is caller-controlled, this is a potential SQL injection sink.",
        whatToCheck:
          "Check for query(\"SELECT ... \" + userInput) and for SELECT ... ${value} inside a template literal.",
        falsePositives:
          "Concatenation of constant fragments only, with values still passed as parameters.",
        verify: "Trace each interpolated or concatenated piece back to the request.",
        secureAlternative: "Keep SQL text constant and bind values as parameters.",
      }),
      search({
        id: "node-nosql",
        languages: ["node"],
        category: "NoSQL Injection",
        title: "NoSQL query operators",
        role: "sink",
        priority: "Critical",
        rank: 4,
        top: true,
        keywords: ["findOne", "findById", "updateOne", "deleteOne", "$where"],
        regex: "\\b(findOne|findById|updateOne|deleteOne|\\$where)\\s*\\(",
        why: "Potential NoSQL injection sink. A caller-supplied object can change the query operator, not only the value.",
        whatToCheck:
          "See whether req.body or a parsed JSON object is passed straight into the driver.",
        falsePositives:
          "findById with a server-derived id, or a query object built field by field in code.",
        verify: "Reject operator keys such as $gt, $where, and $ne if they arrived from the client.",
        secureAlternative:
          "Assign explicit fields from the request. Do not pass the request object to the driver.",
      }),
      search({
        id: "java-sql",
        languages: ["java"],
        category: "SQL Injection",
        title: "Dynamic JDBC execution",
        role: "sink",
        priority: "Critical",
        rank: 4,
        top: true,
        keywords: ["createStatement", "executeQuery", "executeUpdate", "createNativeQuery"],
        regex:
          "\\b(createStatement|executeQuery|executeUpdate|createNativeQuery)\\s*\\(",
        why: "Potential SQL injection sink. Statement and native-query execution often run SQL that was built as a string.",
        whatToCheck:
          "Look at the string around the call for concatenation or String.format.",
        falsePositives:
          "executeQuery on a PreparedStatement whose SQL text is constant.",
        verify: "If the SQL is a constant and parameters are bound with setString or similar, the execution call itself is the safe pattern.",
        secureAlternative:
          "Use PreparedStatement or a parameterized JPA query. Do not concatenate untrusted values into SQL.",
      }),
      search({
        id: "java-sql-concat",
        languages: ["java", "spring"],
        category: "SQL Injection",
        title: "SQL string concatenation",
        role: "sink",
        priority: "Critical",
        rank: 4,
        top: true,
        keywords: ["String.format", "SELECT", "INSERT", "UPDATE", "DELETE"],
        regex: "(SELECT|INSERT|UPDATE|DELETE)[^\\n]{0,80}(\\+|String\\.format)",
        flags: "i",
        why: "SQL text and string building appear on the same line. Review whether a request value is part of that string.",
        whatToCheck:
          "Find the variables joined onto the SQL. Follow them to getParameter, @RequestParam, or a request body.",
        falsePositives: "Joining constant SQL fragments with no request data.",
        verify: "A constant-only expression is a weaker finding than one that includes request input.",
        secureAlternative: "Use placeholders and bind the values.",
      }),
      search({
        id: "java-prepare",
        languages: ["java", "spring"],
        category: "SQL Injection",
        title: "prepareStatement",
        role: "review",
        priority: "Low",
        rank: 4,
        keywords: ["prepareStatement"],
        regex: "\\bprepareStatement\\s*\\(",
        why: "prepareStatement is often the safe API. Review it only to see whether the SQL string itself is still built from input.",
        whatToCheck:
          "Read the argument. A single string literal is the expected safe case.",
        falsePositives:
          "This pattern matches the safe API on purpose so you can confirm parameterization.",
        verify: "If the SQL is constant, you can move on.",
        secureAlternative: "Keep using prepareStatement with bound parameters.",
      }),
      search({
        id: "spring-db",
        languages: ["spring"],
        category: "SQL Injection",
        title: "Spring data access",
        role: "sink",
        priority: "Critical",
        rank: 4,
        top: true,
        keywords: ["JdbcTemplate", "EntityManager", "createNativeQuery", "@Query", "queryForObject", "queryForList"],
        regex:
          "\\b(JdbcTemplate|EntityManager|createNativeQuery|queryForObject|queryForList)\\b|@Query\\b|\\.query\\s*\\(",
        why: "Potential SQL injection sink when the query string is assembled from request data. JdbcTemplate and @Query are safe when the SQL is constant and values are bound.",
        whatToCheck:
          "Read the SQL argument. Look for + or a SpEL expression that inserts a request value into the query text.",
        falsePositives:
          "jdbcTemplate.query(CONSTANT_SQL, binder, id) and @Query with ?1 placeholders.",
        verify: "Distinguish the SQL text from the bound arguments.",
        secureAlternative:
          "Use named or positional parameters. Do not append request strings to SQL.",
      }),
      search({
        id: "spring-orm",
        languages: ["spring"],
        category: "SQL Injection",
        title: "Classic Spring ORM queries",
        role: "sink",
        priority: "Critical",
        rank: 4,
        top: true,
        keywords: ["NamedParameterJdbcTemplate", "HibernateTemplate", "createSQLQuery"],
        regex: "\\b(NamedParameterJdbcTemplate|HibernateTemplate|createSQLQuery)\\b",
        why: "Classic Spring data access can still run SQL that was built as a string. Named parameters are safe only when the SQL text itself stays constant.",
        whatToCheck:
          "Read the SQL or HQL argument. Look for concatenation or a request value inside the query text.",
        falsePositives:
          "A named-parameter query whose SQL is a constant and whose values are bound with a map or SqlParameterSource.",
        verify: "The parameter map does not make a concatenated query safe.",
        secureAlternative:
          "Keep the SQL text constant and bind values. Do not append request strings.",
      }),
    ],
  },
  {
    id: "command",
    order: 5,
    title: "OS command execution",
    summary: "Find process execution and see whether the caller can influence it.",
    guidance: [
      "Find process and shell APIs.",
      "Check whether request data can change the command, the executable, or the arguments.",
      "Treat a dynamic command as high priority even when reachability is not fully proven.",
    ],
    searches: [
      search({
        id: "node-command",
        languages: ["node"],
        category: "Command Injection",
        title: "Node process execution",
        role: "sink",
        priority: "Critical",
        rank: 3,
        top: true,
        keywords: ["child_process", "exec", "execSync", "spawn", "spawnSync"],
        regex:
          "\\b(child_process|execSync|execFileSync|execFile|spawnSync)\\b|\\b(spawn|exec)\\s*\\(",
        why: "Potential command injection sink. Review whether request data reaches the command string, the executable, or the arguments.",
        whatToCheck:
          "exec and execSync run through a shell. spawn with shell: true does too. Arguments built from req.query or req.body are the review target.",
        falsePositives:
          "spawn of a constant executable, execFile of a fixed path, and .exec calls on a regular expression rather than a process. The child_process import is included so you can find the real call sites.",
        verify: "If any part of the command comes from the request, stay on this finding.",
        secureAlternative:
          "Avoid a shell. Call execFile or spawn with a fixed executable and an argument array that does not include raw request text.",
      }),
      search({
        id: "java-command",
        languages: ["java"],
        category: "Command Injection",
        title: "Java process execution",
        role: "sink",
        priority: "Critical",
        rank: 3,
        top: true,
        keywords: ["Runtime.getRuntime", "exec", "ProcessBuilder"],
        regex: "(Runtime\\.getRuntime|\\bProcessBuilder\\b|\\.exec\\s*\\()",
        why: "Potential command injection sink. Review immediately if user-controlled data can reach Runtime.exec or ProcessBuilder.",
        whatToCheck:
          "See whether the command string or the argument list includes a request parameter, header, or file name.",
        falsePositives:
          "A fixed command array with no request data, such as starting a known local helper.",
        verify: "A single string passed to exec is parsed by the runtime and is riskier than a fixed argument list.",
        secureAlternative:
          "Use ProcessBuilder with a fixed executable and separate arguments. Do not build one command string from request data.",
      }),
    ],
  },
  {
    id: "files",
    order: 6,
    title: "File handling / uploads",
    summary: "Find filesystem calls and upload handlers that a request can steer.",
    guidance: [
      "Find reads, writes, deletes, and upload handlers.",
      "Check whether a request parameter or the original filename is part of the path.",
      "For uploads, check extension, content, storage location, and path traversal.",
    ],
    searches: [
      search({
        id: "node-file",
        languages: ["node"],
        category: "Path Traversal",
        title: "Node file and path APIs",
        role: "sink",
        priority: "High",
        rank: 5,
        top: true,
        keywords: [
          "readFile",
          "writeFile",
          "unlink",
          "createReadStream",
          "createWriteStream",
          "path.join",
          "path.resolve",
          "multer",
        ],
        regex:
          "\\b(readFile|writeFile|unlink|createReadStream|createWriteStream|multer)(Sync)?\\s*\\(|path\\.(join|resolve)\\s*\\(",
        why: "Potential path traversal or arbitrary file access if a request value is part of the path.",
        whatToCheck:
          "See whether req.params, req.query, req.body, or an uploaded filename reaches path.join, path.resolve, or a file call.",
        falsePositives:
          "Paths built only from configuration and constants.",
        verify:
          "path.join does not remove .. segments by itself. Check for a root prefix and a test that the resolved path stays under that root.",
        secureAlternative:
          "Resolve the path and verify it still starts with the intended directory. Store uploads under a generated name.",
      }),
      search({
        id: "java-file",
        languages: ["java"],
        category: "Path Traversal",
        title: "Java file APIs",
        role: "sink",
        priority: "High",
        rank: 6,
        top: true,
        keywords: [
          "Paths.get",
          "new File",
          "Files.read",
          "Files.write",
          "FileInputStream",
          "FileOutputStream",
        ],
        regex:
          "(Paths\\.get\\s*\\(|\\bnew\\s+File\\s*\\(|Files\\.(read|write)|\\bFileInputStream\\b|\\bFileOutputStream\\b)",
        why: "Potential path traversal if a request parameter or header is part of the path.",
        whatToCheck:
          "Look for getParameter, @PathVariable, or a multipart filename in the path expression.",
        falsePositives: "Files opened from a fixed configuration path.",
        verify: "Normalize the path and confirm it remains inside the intended directory.",
        secureAlternative:
          "Use a fixed base directory, reject separators and .. in the user-supplied portion, and open the normalized path only after that check.",
      }),
      search({
        id: "spring-upload",
        languages: ["spring"],
        category: "File Upload",
        title: "Multipart upload handling",
        role: "sink",
        priority: "High",
        rank: 5,
        top: true,
        keywords: ["MultipartFile", "transferTo", "getOriginalFilename"],
        regex: "\\b(MultipartFile|transferTo|getOriginalFilename)\\b",
        why: "Upload handlers can write caller-controlled content and filenames.",
        whatToCheck:
          "Review filename handling, extension checks, content type, storage location, and whether the file is served back from a web root.",
        falsePositives:
          "transferTo of a generated filename under a non-public directory, with a content check before that call.",
        verify: "getOriginalFilename is attacker-controlled, including path separators.",
        secureAlternative:
          "Ignore the client path. Generate a server filename, store it outside the web root, and validate content before use.",
      }),
    ],
  },
  {
    id: "ssrf",
    order: 7,
    title: "Outbound network requests / SSRF",
    summary: "Find HTTP calls and redirects whose target may come from the request.",
    guidance: [
      "Find HTTP clients and redirects.",
      "Check whether the URL, host, or redirect target comes from the request.",
      "See whether internal addresses are rejected, and whether redirects are limited to known paths.",
    ],
    searches: [
      search({
        id: "node-ssrf",
        languages: ["node"],
        category: "SSRF",
        title: "Node outbound HTTP",
        role: "sink",
        priority: "High",
        rank: 7,
        top: true,
        keywords: ["fetch", "axios", "http.request", "https.request", "got", "request"],
        regex:
          "\\b(fetch|got)\\s*\\(|axios\\.(get|post|put|patch|delete)\\s*\\(|https?\\.request\\s*\\(",
        why: "Potential SSRF sink if the URL or hostname comes from the request.",
        whatToCheck:
          "See whether req.query or req.body supplies the URL. A relative path built by the server is a different case.",
        falsePositives:
          "fetch of a constant URL, or an HTTP client aimed at a configured internal service.",
        verify: "If the caller picks the host, check for an allow-list and a block on link-local and metadata addresses.",
        secureAlternative:
          "Allow-list destinations. Do not pass a request URL straight to fetch, axios, or http.request.",
      }),
      search({
        id: "java-ssrf",
        languages: ["java", "spring"],
        category: "SSRF",
        title: "Java and Spring HTTP clients",
        role: "sink",
        priority: "High",
        rank: 7,
        top: true,
        keywords: [
          "new URL",
          "URI.create",
          "HttpClient",
          "URLConnection",
          "RestTemplate",
          "WebClient",
        ],
        regex:
          "(\\bnew\\s+URL\\s*\\(|\\bURI\\.create\\s*\\(|\\bHttpClient\\b|\\bURLConnection\\b|\\bRestTemplate\\b|\\bWebClient\\b)",
        why: "Potential SSRF sink if a request value becomes the URL.",
        whatToCheck:
          "Find the expression passed to the constructor or the exchange method. Follow it to the controller parameter.",
        falsePositives:
          "A client bean pointed at a fixed base URL from configuration.",
        verify: "RestTemplate and WebClient are safe when the host is fixed and the caller only supplies an id that is encoded as a path segment.",
        secureAlternative:
          "Use a fixed base URL and an allow-list. Reject user-supplied hosts.",
      }),
      search({
        id: "open-redirect",
        languages: ["node", "java", "spring"],
        category: "Open Redirect",
        title: "Redirects",
        role: "sink",
        priority: "Medium",
        rank: 17,
        top: true,
        keywords: ["res.redirect", "sendRedirect", "redirect:"],
        regex: "(\\bres\\.redirect|\\bsendRedirect)\\s*\\(",
        why: "Potential open redirect if the target comes from a request parameter.",
        whatToCheck:
          "See whether the argument is a constant path or a value such as req.query.next or a returnUrl parameter.",
        falsePositives: "res.redirect('/login') and other constant relative paths.",
        verify: "A protocol-relative or absolute URL supplied by the caller can send the browser off site.",
        secureAlternative:
          "Accept only relative paths on an allow-list, or map a short code to a server-side destination.",
      }),
      search({
        id: "spring-redirect",
        languages: ["spring"],
        category: "Open Redirect",
        title: "Spring view redirects",
        role: "sink",
        priority: "Medium",
        rank: 17,
        top: true,
        keywords: ["RedirectView", "redirect:"],
        regex: "\\bRedirectView\\b|[\"']redirect:",
        why: "Spring MVC treats a redirect: view name and a RedirectView as a browser redirect. A request value in that target is an open-redirect review.",
        whatToCheck:
          "See whether the view name or the RedirectView URL comes from a request parameter such as next or returnUrl.",
        falsePositives:
          "redirect:/home and other constant relative paths.",
        verify: "A caller-supplied absolute URL can send the browser off site.",
        secureAlternative:
          "Accept only relative paths on an allow-list, or map a short code to a server-side destination.",
      }),
    ],
  },
  {
    id: "deser",
    order: 8,
    title: "Deserialization / XML",
    summary: "Find object deserialization, dynamic execution, and XML parsers.",
    guidance: [
      "Find deserializers, dynamic execution, and XML parser factories.",
      "For XML, check that DTD processing and external entities are disabled.",
      "Treat ObjectInputStream, readObject, eval, and new Function as high priority.",
    ],
    searches: [
      search({
        id: "node-dynamic",
        languages: ["node"],
        category: "Deserialization",
        title: "eval and Function",
        role: "sink",
        priority: "Critical",
        rank: 8,
        top: true,
        keywords: ["eval", "Function", "yaml.load", "unserialize"],
        regex: "\\b(eval|Function)\\s*\\(",
        why: "Potential code execution sink. eval and the Function constructor compile strings at runtime.",
        whatToCheck:
          "See whether the string includes any request data, stored content a caller created, or a file the caller can change.",
        falsePositives:
          "Neither API is a safe parser for JSON. JSON.parse is the usual intent and will not match this pattern.",
        verify: "Assume the match deserves a close read even when the string looks constant.",
        secureAlternative:
          "Remove eval and Function. Parse JSON with JSON.parse and keep logic in real code.",
      }),
      search({
        id: "java-deser",
        languages: ["java"],
        category: "Deserialization",
        title: "Java deserialization",
        role: "sink",
        priority: "Critical",
        rank: 8,
        top: true,
        keywords: ["ObjectInputStream", "readObject", "XMLDecoder"],
        regex: "(\\bObjectInputStream\\b|\\breadObject\\s*\\(|\\bXMLDecoder\\b)",
        why: "Potential unsafe deserialization. ObjectInputStream and XMLDecoder can instantiate attacker-chosen types when the stream is untrusted.",
        whatToCheck:
          "Find where the bytes come from: a request body, a file upload, a queue, or a cache.",
        falsePositives:
          "readObject of a stream the same process just wrote, with no external input. Still confirm the source.",
        verify: "If the bytes cross a trust boundary, treat this as a high-priority review.",
        secureAlternative:
          "Do not deserialize untrusted Java object streams. Use a JSON or XML mapping format with a fixed type.",
      }),
      search({
        id: "java-xxe",
        languages: ["java"],
        category: "XXE",
        title: "XML parser factories",
        role: "sink",
        priority: "High",
        rank: 9,
        top: true,
        keywords: [
          "DocumentBuilderFactory",
          "SAXParserFactory",
          "XMLInputFactory",
          "TransformerFactory",
        ],
        regex:
          "\\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\\b",
        why: "XML parser creation is a review point when external entities or DTD processing are left on.",
        whatToCheck:
          "After you find a factory, look for settings that disable DTDs, external entities, and external schema or stylesheet access. A factory with none of those settings is unfinished, not automatically proven exploitable.",
        falsePositives:
          "A factory that sets FEATURE_SECURE_PROCESSING and disables external entities just below the match.",
        verify:
          "Read the next lines for setFeature, setAttribute, or XMLConstants.ACCESS_EXTERNAL_DTD.",
        secureAlternative:
          "Disable DTDs and external entities on the factory before parsing any document that a caller can influence.",
      }),
      search({
        id: "spring-spel",
        languages: ["spring"],
        category: "Deserialization",
        title: "Spring expression evaluation",
        role: "sink",
        priority: "Critical",
        rank: 8,
        top: true,
        keywords: ["SpelExpressionParser", "StandardEvaluationContext", "parseExpression"],
        regex: "\\b(SpelExpressionParser|StandardEvaluationContext|parseExpression)\\b",
        why: "Spring Expression Language can call methods and constructors when the expression text comes from a request. That is a code-execution review, not a normal template.",
        whatToCheck:
          "See whether the expression string is constant or includes a request parameter, header, or body field.",
        falsePositives:
          "A constant expression used to read a bean property inside the application.",
        verify: "StandardEvaluationContext is the more powerful context. SimpleEvaluationContext is the narrower one.",
        secureAlternative:
          "Do not parse caller-supplied expressions. If a template is required, use SimpleEvaluationContext and a fixed expression.",
      }),
    ],
  },
  {
    id: "secrets",
    order: 9,
    title: "Secrets",
    summary: "Find literal credentials and keys, then decide whether the literal is real.",
    guidance: [
      "Search for literal passwords, API keys, tokens, and connection strings.",
      "Decide whether the match is a real secret or a name, placeholder, or test value.",
      "Check that production code reads secrets from the environment or a secret store.",
    ],
    searches: [
      search({
        id: "secret-assign",
        languages: ["node", "java", "spring"],
        category: "Secrets",
        title: "Literal secret assignment",
        role: "review",
        priority: "High",
        rank: 10,
        top: true,
        onConfig: true,
        flags: "i",
        keywords: [
          "password",
          "secret",
          "token",
          "apiKey",
          "API_KEY",
          "JWT_SECRET",
          "PRIVATE_KEY",
        ],
        regex:
          "(password|passwd|secret|api[_-]?key|token|jwt[_-]?secret|private[_-]?key)\\s*[:=]\\s*[\"'][^\"'\\r\\n]{4,}[\"']",
        why: "A credential-like name is assigned a quoted literal. It may be a hardcoded secret. Do not treat every match as one.",
        whatToCheck:
          "Look at the value. Placeholders, empty examples, and public test fixtures are weaker than a long random token in production code.",
        falsePositives:
          "password = \"password\" in a demo, input type labels, and example values in sample configuration.",
        verify: "If the value would grant access and is shipped in the repo, it deserves rotation after you confirm it is real.",
        secureAlternative:
          "Read secrets from the environment or a secret manager. Keep them out of source.",
      }),
    ],
  },
  {
    id: "xss",
    order: 10,
    title: "XSS / HTML output",
    summary: "Find places that turn data into HTML or script.",
    guidance: [
      "Find HTML sinks such as innerHTML, document.write, unescaped templates, and raw responses.",
      "Check whether attacker-controlled data is encoded for the context it is written into.",
      "A text response and an HTML or JavaScript sink are different checks.",
    ],
    searches: [
      search({
        id: "node-xss",
        languages: ["node"],
        category: "XSS",
        title: "HTML sinks",
        role: "sink",
        priority: "High",
        rank: 11,
        top: true,
        keywords: [
          "innerHTML",
          "outerHTML",
          "document.write",
          "dangerouslySetInnerHTML",
          "res.send",
        ],
        regex:
          "\\b(innerHTML|outerHTML|document\\.write|dangerouslySetInnerHTML|res\\.send)\\b",
        why: "Potential XSS sink if attacker-controlled data is written as HTML without encoding.",
        whatToCheck:
          "See whether the value written includes a request parameter, stored user content, or a string built with <tags>.",
        falsePositives:
          "res.send of a JSON object, or innerHTML set to a constant empty string.",
        verify: "Encoding for HTML text is not the same as encoding for an attribute or a URL.",
        secureAlternative:
          "Send a content type that is not HTML, or insert text with textContent. In React, avoid dangerouslySetInnerHTML.",
      }),
      search({
        id: "java-xss",
        languages: ["java", "spring"],
        category: "XSS",
        title: "Response writers and HTML strings",
        role: "sink",
        priority: "High",
        rank: 11,
        top: true,
        keywords: ["getWriter", "text/html", "innerHTML"],
        regex:
          "\\bgetWriter\\s*\\(|setContentType\\s*\\(\\s*[\"']text/html|\"\\s*<\\s*(html|script|div|h1)\\b",
        flags: "i",
        why: "Potential XSS sink when a response is written as HTML from request data.",
        whatToCheck:
          "See whether getWriter or a view model receives a request parameter that is later rendered without encoding.",
        falsePositives:
          "A static error page with no request data, or a template engine that encodes by default.",
        verify: "Thymeleaf and similar engines encode by default until the template opts out.",
        secureAlternative:
          "Keep template escaping on. Do not mark request data as safe HTML.",
      }),
    ],
  },
  {
    id: "mass",
    order: 11,
    title: "Mass assignment",
    summary: "Find request bodies copied onto objects that have sensitive fields.",
    guidance: [
      "Find request bodies copied into models, entities, or update calls.",
      "Check whether role, owner, status, or price fields can be supplied by the caller.",
      "Prefer an allow-list of fields, or a DTO that omits sensitive properties.",
    ],
    searches: [
      search({
        id: "node-mass",
        languages: ["node"],
        category: "Mass Assignment",
        title: "Request body copied into an object",
        role: "sink",
        priority: "High",
        rank: 12,
        top: true,
        keywords: ["req.body", "Object.assign", "...req.body", "update(req.body)", "save(req.body)"],
        regex:
          "Object\\.assign\\s*\\(|\\.\\.\\.\\s*req\\.body|\\.update\\s*\\(\\s*req\\.body|\\.save\\s*\\(\\s*req\\.body",
        why: "Potential mass assignment if properties from the request can set role, owner, or other internal fields.",
        whatToCheck:
          "List the fields on the model. See whether the caller can send isAdmin, role, ownerId, or account status.",
        falsePositives:
          "Object.assign onto a fresh object that is then picked field by field before save.",
        verify: "A schema that strips unknown fields is a mitigating control. Read it before you decide.",
        secureAlternative:
          "Copy an allow-list of fields. Do not spread req.body into a persistence call.",
      }),
      search({
        id: "spring-mass",
        languages: ["spring"],
        category: "Mass Assignment",
        title: "Request body binding",
        role: "source",
        priority: "High",
        rank: 12,
        top: true,
        keywords: ["@RequestBody", "@Entity", "save("],
        regex: "@RequestBody\\b",
        why: "A request body is bound to a Java object. If that type is a persistence entity, the caller may set fields the form never showed.",
        whatToCheck:
          "1. Find @RequestBody. 2. Identify the parameter type. 3. See whether it is an entity or a DTO. 4. See whether sensitive properties exist on that type. 5. Inspect repository.save of that object.",
        falsePositives:
          "Binding to a DTO that contains only the fields the operation should accept.",
        verify: "Open the class. Entity annotations or sensitive setters make this a stronger review.",
        secureAlternative:
          "Bind a DTO and copy the allowed fields onto the entity in code.",
      }),
      search({
        id: "spring-form-binding",
        languages: ["spring"],
        category: "Mass Assignment",
        title: "Classic form binding",
        role: "source",
        priority: "High",
        rank: 12,
        top: true,
        keywords: ["@ModelAttribute", "@InitBinder", "WebDataBinder", "setAllowedFields"],
        regex: "@(ModelAttribute|InitBinder)\\b|\\bWebDataBinder\\b",
        why: "Classic Spring MVC binds request parameters onto a Java object with @ModelAttribute. Every setter on that type can be supplied by the caller unless a binder limits the fields.",
        whatToCheck:
          "Open the bound type. Look for role, owner, or status setters. Then look for setAllowedFields or setDisallowedFields on the WebDataBinder.",
        falsePositives:
          "A binder that allow-lists the form fields, or a command object that has no sensitive setters.",
        verify: "A missing @InitBinder on a rich domain object is the case to stay on.",
        secureAlternative:
          "Bind a small form object and copy the allowed fields in code, or call setAllowedFields with an explicit list.",
      }),
    ],
  },
  {
    id: "crypto",
    order: 12,
    title: "Cryptography / randomness",
    summary: "Find weak hashes, weak ciphers, and predictable random numbers.",
    guidance: [
      "Find hashes, ciphers, and random calls used in a security decision.",
      "Check for MD5, SHA-1, DES, ECB, hardcoded keys or IVs, and non-cryptographic random.",
      "Confirm passwords use a slow password hash and tokens use a cryptographic generator.",
    ],
    searches: [
      search({
        id: "weak-crypto",
        languages: ["node", "java", "spring"],
        category: "Cryptography",
        title: "Weak hash, cipher, or random API",
        role: "review",
        priority: "Medium",
        rank: 13,
        top: true,
        flags: "i",
        keywords: ["MD5", "SHA1", "SHA-1", "DES", "ECB", "java.util.Random", "Math.random"],
        regex:
          "\\b(MD5|SHA-?1|DES|ECB|java\\.util\\.Random)\\b|\\bnew\\s+Random\\s*\\(|\\bMath\\.random\\s*\\(|createHash\\s*\\(\\s*[\"'](md5|sha1)[\"']",
        why: "These APIs are often too weak for passwords, tokens, or encryption. Context decides whether this use is security-sensitive.",
        whatToCheck:
          "See what is being hashed or encrypted, and whether the result is a password, a token, a signature, or a cache key.",
        falsePositives:
          "MD5 or SHA-1 used as a non-security checksum of a file. Math.random used for a visual effect. DES matched inside an unrelated identifier is uncommon but possible.",
        verify: "A cache key is a different decision from a session token or a password hash.",
        secureAlternative:
          "Use SHA-256 or stronger for integrity, AES-GCM for encryption, a password hash for passwords, and SecureRandom or crypto.randomBytes for tokens.",
      }),
    ],
  },
  {
    id: "session",
    order: 13,
    title: "Sessions / JWT / cookies",
    summary: "Find token signing, verification, and cookie flags.",
    guidance: [
      "Find where tokens are signed, verified, and stored.",
      "Check the algorithm, the expiration, and how the secret is stored.",
      "Check cookie flags: Secure, HttpOnly, and SameSite.",
    ],
    searches: [
      search({
        id: "node-jwt",
        languages: ["node"],
        category: "Session / Cookies",
        title: "JWT signing and verification",
        role: "review",
        priority: "Medium",
        rank: 14,
        top: true,
        keywords: ["jwt.sign", "jwt.verify", "jsonwebtoken", "algorithms"],
        regex: "jwt\\.(sign|verify)\\s*\\(|\\bjsonwebtoken\\b",
        why: "JWT calls decide how a token is minted and whether its signature is checked.",
        whatToCheck:
          "Look for algorithm restrictions, expiration, and a secret that is not hardcoded. Verification should reject the none algorithm and unexpected algorithms.",
        falsePositives:
          "A verify call that already passes algorithms and maxAge.",
        verify: "Read the options object, not only the function name.",
        secureAlternative:
          "Verify with an explicit algorithm list and expiration. Load the secret from configuration.",
      }),
      search({
        id: "cookie-flags",
        languages: ["node", "java", "spring"],
        category: "Session / Cookies",
        title: "Cookie and session flags",
        role: "review",
        priority: "Medium",
        rank: 14,
        top: true,
        keywords: ["httpOnly", "sameSite", "secure", "express-session", "res.cookie", "setHttpOnly", "JSESSIONID"],
        regex:
          "\\b(httpOnly|sameSite|express-session)\\b|\\bres\\.cookie\\s*\\(|\\bsetSecure\\s*\\(|\\bsetHttpOnly\\s*\\(|\\bsessionManagement\\b",
        why: "Session cookies should be reviewed for Secure, HttpOnly, and SameSite.",
        whatToCheck:
          "If you found res.cookie or a session middleware setup, look for the three flags. A missing flag is a review note, not proof of exploitation.",
        falsePositives:
          "A cookie that holds a non-sensitive preference and is intentionally readable by script.",
        verify: "Session identifiers and tokens should not be readable by script and should not be sent on plain HTTP.",
        secureAlternative:
          "Set Secure, HttpOnly, and SameSite on session cookies. Give JWTs an expiration and verify the signature.",
      }),
    ],
  },
  {
    id: "csrf-cors",
    order: 14,
    title: "CSRF / CORS",
    summary: "Find cross-origin policy and CSRF switches.",
    guidance: [
      "Find CORS middleware and CSRF configuration.",
      "Review every wildcard origin, and any use of credentials together with a broad origin.",
      "Do not call a match vulnerable until you see which routes it applies to.",
    ],
    searches: [
      search({
        id: "cors-permissive",
        languages: ["node", "java", "spring"],
        category: "CORS",
        title: "Broad cross-origin access",
        role: "review",
        priority: "Medium",
        rank: 16,
        top: true,
        keywords: ["Access-Control-Allow-Origin", "*", "@CrossOrigin", "origin"],
        regex:
          "Access-Control-Allow-Origin\\s*[:=]\\s*[\"']?\\*|@CrossOrigin\\s*\\(\\s*[\"']\\*[\"']\\s*\\)|origin\\s*:\\s*[\"']\\*[\"']",
        why: "A wildcard origin is a review point. Combined with credentials, it can expose authenticated responses to other sites. The wildcard alone is not automatically a vulnerability.",
        whatToCheck:
          "See whether cookies or authorization headers are included, and which routes send this header.",
        falsePositives:
          "A public, cookie-free API that intentionally allows any origin.",
        verify: "Read the route and the credentials setting together.",
        secureAlternative:
          "Reflect a specific allow-list of origins. Do not combine a wildcard with credentialed requests.",
      }),
      search({
        id: "csrf-cors-general",
        languages: ["node", "java", "spring"],
        category: "CSRF",
        title: "CSRF and CORS configuration",
        role: "review",
        priority: "Low",
        rank: 15,
        keywords: ["csrf", "csurf", "cors", "@CrossOrigin", "CookieCsrfTokenRepository"],
        regex:
          "\\b(csrf|csurf|CsrfToken|CookieCsrfTokenRepository)\\b|\\bcors\\s*\\(|@CrossOrigin\\b",
        why: "These calls show where cross-site request and cross-origin policy are configured.",
        whatToCheck:
          "See whether state-changing routes are covered by a CSRF token, or are safe because they do not use cookies for authentication.",
        falsePositives:
          "csrf() enabled in the security chain, which is the protective setting. Read it before treating it as a problem. Bearer-token APIs often do not need cookie CSRF protection.",
        verify: "Disabling CSRF is the finding to read carefully. Enabling it is context.",
        secureAlternative:
          "Keep CSRF protection for cookie-authenticated state changes. Restrict CORS to known origins.",
      }),
    ],
  },
  {
    id: "logging",
    order: 15,
    title: "Sensitive logging",
    summary: "Find logs that may record secrets or personal data.",
    guidance: [
      "Find logs that include credentials, tokens, or personal data.",
      "Check request dumps that print headers or bodies.",
      "Prefer omitting the value, or redacting it.",
    ],
    searches: [
      search({
        id: "sensitive-log",
        languages: ["node", "java", "spring"],
        category: "Logging / Sensitive Data",
        title: "Possible sensitive log argument",
        role: "review",
        priority: "Low",
        rank: 18,
        top: true,
        onConfig: false,
        flags: "i",
        keywords: ["console.log", "logger", "password", "authorization", "token", "ssn"],
        regex:
          "\\b(console\\.(log|debug|info|warn|error)|logger\\.(debug|info|warn|error|trace)|log\\.(debug|info|warn|error))\\s*\\([^\\n]{0,80}\\b(password|passwd|secret|token|authorization|ssn|credit)",
        why: "A log call on this line also mentions a sensitive name. Confirm the value is actually written.",
        whatToCheck:
          "See whether the argument is the secret itself, a redacted label, or only the word in a message.",
        falsePositives:
          "A message that says the password was rejected, without the password value.",
        verify: "Request-body dumps and Authorization header logs are the stronger matches.",
        secureAlternative:
          "Log an event and an id. Do not log passwords, tokens, or full authorization headers.",
      }),
    ],
  },
  {
    id: "config",
    order: 16,
    title: "Dependencies and configuration",
    summary: "Review manifests and framework security settings by hand.",
    guidance: [
      "Open the manifest and the framework security configuration.",
      "Review authentication rules, debug settings, and exposed management endpoints.",
      "This step is mostly manual. A regex only highlights a few obvious keys.",
    ],
    searches: [
      search({
        id: "config-flags",
        languages: ["java", "spring"],
        category: "Dependency / Configuration",
        title: "Debug and schema settings",
        role: "review",
        priority: "Low",
        rank: 20,
        onConfig: true,
        flags: "i",
        keywords: [
          "package.json",
          "pom.xml",
          "build.gradle",
          "application.yml",
          "application.properties",
          "show-sql",
          "ddl-auto",
          "devtools",
        ],
        regex: "(show-sql|ddl-auto|devtools|management\\.endpoints)",
        why: "These settings can expose SQL, change schema on startup, or open management endpoints. Confirm the environment before treating them as a defect.",
        whatToCheck:
          "See whether the setting is in a local profile or in the configuration that production will load. Then open package.json or pom.xml and review dependencies yourself.",
        falsePositives:
          "Local development profiles that are not packaged.",
        verify: "Dependency review is manual. The regex does not know which version is vulnerable.",
        secureAlternative:
          "Keep debug SQL and wide-open actuators out of production configuration. Pin and review dependencies.",
      }),
    ],
  },
];

function allSearches() {
  const list = [];
  for (const step of STEPS) {
    for (const item of step.searches) {
      list.push({
        ...item,
        stepId: step.id,
        stepOrder: step.order,
        stepTitle: step.title,
      });
    }
  }
  return list;
}

function assertCatalog() {
  const ids = new Set();
  for (const item of allSearches()) {
    if (ids.has(item.id)) {
      throw new Error(`Duplicate search id ${item.id}`);
    }
    ids.add(item.id);
    if (!item.regex) {
      throw new Error(`Missing regex for ${item.id}`);
    }
    try {
      new RegExp(item.regex, item.flags || "");
    } catch (err) {
      throw new Error(`Bad regex ${item.id}: ${err.message}`);
    }
  }
  if (STEPS.length !== 16) {
    throw new Error(`Expected 16 review steps, found ${STEPS.length}`);
  }
}

function toClientCatalog() {
  return {
    disclaimer: DISCLAIMER,
    languages: LANGUAGES,
    categories: CATEGORIES,
    priorities: PRIORITIES,
    steps: STEPS.map((step) => ({
      id: step.id,
      order: step.order,
      title: step.title,
      summary: step.summary,
      guidance: step.guidance,
      searches: step.searches.map((item) => ({
        id: item.id,
        languages: item.languages,
        category: item.category,
        title: item.title,
        role: item.role,
        priority: item.priority,
        rank: item.rank,
        top: item.top,
        keywords: item.keywords,
        regex: item.regex,
        flags: item.flags,
        why: item.why,
        whatToCheck: item.whatToCheck,
        falsePositives: item.falsePositives,
        verify: item.verify,
        secureAlternative: item.secureAlternative,
      })),
    })),
  };
}

module.exports = {
  DISCLAIMER,
  LANGUAGES,
  CATEGORIES,
  PRIORITIES,
  STEPS,
  allSearches,
  assertCatalog,
  toClientCatalog,
};
