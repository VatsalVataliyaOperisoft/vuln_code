import Vapor
import Fluent
import FluentSQLiteDriver
import Foundation
import Crypto

// ---------- Configuration ----------
let app = Application(.development)
defer { app.shutdown() }

// Bind to localhost only for safety
app.http.server.configuration.hostname = "127.0.0.1"
app.http.server.configuration.port = 8080

// Auto-generate VULN_TOKEN if not set
let envToken = Environment.get("VULN_TOKEN")
let vulnToken: String = {
    if let t = envToken, !t.isEmpty { return t }
    // generate 32 hex chars token
    var bytes = [UInt8](repeating: 0, count: 16)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    let token = bytes.map { String(format: "%02x", $0) }.joined()
    setenv("VULN_TOKEN", token, 1)
    return token
}()

// ---------- Database (SQLite) ----------
let dbPath = app.directory.workingDirectory + "vulnlab.sqlite"
app.databases.use(.sqlite(.file(dbPath)), as: .sqlite)

// ---------- Models ----------
final class User: Model, Content {
    static let schema = "users"
    @ID(key: .id) var id: UUID?
    @Field(key: "username") var username: String
    @Field(key: "password") var password: String // plaintext intentionally
    init() {}
    init(id: UUID? = nil, username: String, password: String) {
        self.id = id; self.username = username; self.password = password
    }
}

final class Note: Model, Content {
    static let schema = "notes"
    @ID(key: .id) var id: UUID?
    @Field(key: "owner") var owner: String
    @Field(key: "content") var content: String
    init() {}
    init(owner: String, content: String) {
        self.owner = owner; self.content = content
    }
}

final class StoredFile: Model, Content {
    static let schema = "files"
    @ID(key: .id) var id: UUID?
    @Field(key: "owner") var owner: String
    @Field(key: "filename") var filename: String
    @Field(key: "path") var path: String
    init() {}
    init(owner: String, filename: String, path: String) {
        self.owner = owner; self.filename = filename; self.path = path
    }
}

// ---------- Migrations ----------
struct CreateUser: Migration {
    func prepare(on database: Database) -> EventLoopFuture<Void> {
        database.schema(User.schema)
            .id()
            .field("username", .string, .required)
            .field("password", .string, .required)
            .unique(on: "username")
            .create()
    }
    func revert(on database: Database) -> EventLoopFuture<Void> {
        database.schema(User.schema).delete()
    }
}
struct CreateNote: Migration {
    func prepare(on database: Database) -> EventLoopFuture<Void> {
        database.schema(Note.schema)
            .id()
            .field("owner", .string, .required)
            .field("content", .string, .required)
            .create()
    }
    func revert(on database: Database) -> EventLoopFuture<Void> {
        database.schema(Note.schema).delete()
    }
}
struct CreateFile: Migration {
    func prepare(on database: Database) -> EventLoopFuture<Void> {
        database.schema(StoredFile.schema)
            .id()
            .field("owner", .string, .required)
            .field("filename", .string, .required)
            .field("path", .string, .required)
            .create()
    }
    func revert(on database: Database) -> EventLoopFuture<Void> {
        database.schema(StoredFile.schema).delete()
    }
}

app.migrations.add(CreateUser())
app.migrations.add(CreateNote())
app.migrations.add(CreateFile())

// run migrations
try app.autoMigrate().wait()

// Insert default admin user plaintext (for testing) if none exists
_ = User.query(on: app.db).count().flatMap { cnt in
    if cnt == 0 {
        return User(username: "admin", password: "123").create(on: app.db)
    } else {
        return app.eventLoopGroup.next().makeSucceededVoidFuture()
    }
}.wait()

// ---------- Safety middleware ----------

// Helper to check loopback address
func isLocalAddress(_ addr: SocketAddress?) -> Bool {
    guard let addr = addr else { return false }
    switch addr {
    case .v4(let v4):
        return v4.address == .loopback
    case .v6(let v6):
        return v6.address == .loopback
    default:
        return false
    }
}

// Middleware: require localhost & token for non-root endpoints
struct LocalOnlyMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Always allow root (/) so token can be displayed
        if request.url.path == "/" {
            return try await next.respond(to: request)
        }
        // Check remote is loopback
        let remote = request.remoteAddress
        if !isLocalAddress(remote) {
            return Response(status: .forbidden, body: .init(string: "Access denied: local-only"))
        }
        // Require token query param to match env token
        guard let token = request.query[String.self, at: "token"], token == vulnToken else {
            return Response(status: .forbidden, body: .init(string: "Access denied: token missing or invalid. See / for token."))
        }
        return try await next.respond(to: request)
    }
}
app.middleware.use(LocalOnlyMiddleware())

// ---------- Routes (vulnerable endpoints) ----------

// Root: show token and links
app.get { req -> Response in
    let token = vulnToken
    var html = "<h2>VulnLab (Vapor) — Local Only</h2>"
    html += "<p><strong>Auto token:</strong> <code>\(token)</code></p>"
    html += "<p><a href='/home?token=\(token)'>Open Lab Home</a></p>"
    html += "<ul>"
    html += "<li><a href='/notes?token=\(token)'>A01 Broken Access Control (notes)</a></li>"
    html += "<li><a href='/crypto?token=\(token)'>A02 Cryptographic Failures</a></li>"
    html += "<li><a href='/login?user=admin&pass=123&token=\(token)'>A03 SQL Injection (login)</a></li>"
    html += "<li><a href='/transfer?from=a&to=b&amount=9999&token=\(token)'>A04 Insecure Transfer</a></li>"
    html += "<li><a href='/config?token=\(token)'>A05 Misconfiguration / Info Leak</a></li>"
    html += "<li><a href='/upload?token=\(token)'>Unrestricted Upload</a></li>"
    html += "<li><a href='/cmd?c=whoami&token=\(token)'>Command Exec</a></li>"
    html += "<li><a href='/fetch?url=http://127.0.0.1:8080/config&token=\(token)'>SSRF Fetch</a></li>"
    html += "</ul>"
    return Response(status: .ok, body: .init(string: html))
}

// Home
app.get("home") { req -> Response in
    let t = req.query[String.self, at: "token"] ?? vulnToken
    var html = "<h3>Vuln Lab Home</h3><ul>"
    html += "<li><a href='/notes?token=\(t)'>Notes</a></li>"
    html += "<li><a href='/crypto?token=\(t)'>Crypto</a></li>"
    html += "<li><a href='/login?user=admin&pass=123&token=\(t)'>Login (SQLi)</a></li>"
    html += "<li><a href='/upload?token=\(t)'>Upload</a></li>"
    html += "</ul>"
    return Response(status: .ok, body: .init(string: html))
}

// A01 - Broken ACL: returns all notes (no owner filtering) and shows raw content (stored XSS)
app.get("notes") { req async throws -> Response in
    let notes = try await Note.query(on: req.db).all()
    var sb = "<h3>All Notes (no ACL)</h3>"
    for n in notes {
        // intentionally not escaped -> stored XSS possible
        sb += "<div style='border:1px solid #ccc;margin:6px;padding:6px'><strong>Owner:</strong> \(n.owner)<br/><strong>Content:</strong> \(n.content)</div>"
    }
    return Response(status: .ok, body: .init(string: sb))
}

// Add note - vulnerable to stored XSS and SQLi when using raw queries elsewhere
app.post("addnote") { req async throws -> Response in
    // read form fields without validation
    struct F: Content { var owner: String?; var content: String? }
    let f = try req.content.decode(F.self)
    let owner = f.owner ?? "anonymous"
    let content = f.content ?? ""
    // insecure: use raw SQL to simulate concatenation vulnerability
    try await req.db.raw("INSERT INTO notes(owner, content) VALUES ('\(owner)', '\(content)')").run()
    return Response(status: .ok, body: .init(string: "Note added (stored XSS possible)"))
}

// A02 Crypto - plaintext secret + weak AES (predictable IV)
app.get("crypto") { req -> Response in
    let secret = "PlaintextSecret"
    // weak AES-128-CBC with predictable zero IV for demo
    let key = Array("weakkeyweakkey".utf8) // 16 bytes
    let iv = [UInt8](repeating: 0, count: 16)
    var encryptedHex = "encrypt-failed"
    do {
        let ctx = try AES.CBC.encrypt(Array(secret.utf8), key: key, iv: iv)
        encryptedHex = ctx.map { String(format: "%02x", $0) }.joined()
    } catch {
        encryptedHex = "encryption-error"
    }
    let html = "<h4>Plaintext: \(secret)</h4><p>Weak AES-128-CBC (predictable IV) hex: \(encryptedHex)</p>"
    return Response(status: .ok, body: .init(string: html))
}

// A03 SQLi - insecure login (concatenated SQL)
app.get("login") { req async throws -> Response in
    let user = req.query[String.self, at: "user"] ?? ""
    let pass = req.query[String.self, at: "pass"] ?? ""
    // insecure raw SQL concatenation -> SQL injection
    let rows = try await req.db.raw("SELECT COUNT(*) as c FROM users WHERE username = '\(user)' AND password = '\(pass)'").all()
    var count = 0
    if let first = rows.first, let c = first.column("c")?.int {
        count = c
    }
    return Response(status: .ok, body: .init(string: count == 1 ? "Login ok" : "Invalid"))
}

// A04 Insecure design - transfer without auth/limits
app.get("transfer") { req -> Response in
    let from = req.query[String.self, at: "from"] ?? "a"
    let to = req.query[String.self, at: "to"] ?? "b"
    let amount = req.query[String.self, at: "amount"] ?? "0"
    return Response(status: .ok, body: .init(string: "Transferred \(amount) from \(from) to \(to)"))
}

// A05 Info leak - environment + stack trace
app.get("config") { req -> Response in
    var out = "<h4>Environment</h4><pre>"
    for (k,v) in ProcessInfo.processInfo.environment { out += "\(k)=\(v)\n" }
    out += "</pre>"
    out += "<h4>Stack sample</h4><pre>"
    out += Thread.callStackSymbols.prefix(10).joined(separator: "\n")
    out += "</pre>"
    return Response(status: .ok, body: .init(string: out))
}

// A06 Components (simulated)
app.get("components") { req -> Response in
    Response(status: .ok, body: .init(string: "Simulated outdated components (demo)"))
}

// A07 Register - store plaintext password (and set insecure cookie)
app.post("register") { req async throws -> Response in
    struct F: Content { var user: String?; var pass: String? }
    let f = try req.content.decode(F.self)
    guard let user = f.user, let pass = f.pass else {
        return Response(status: .badRequest, body: .init(string: "user/pass required"))
    }
    // insecure raw insert concatenation -> SQLi possible
    try await req.db.raw("INSERT INTO users(username, password) VALUES ('\(user)', '\(pass)')").run()
    // insecure cookie (no HttpOnly/Secure)
    var res = Response(status: .ok, body: .init(string: "User created (plaintext password stored)"))
    res.headers.add(name: .setCookie, value: "lab_user=\(user); Path=/")
    return res
}

// A08 Update (no signature verification)
app.get("update") { req -> Response in
    Response(status: .ok, body: .init(string: "Downloading updates from unverified source..."))
}

// A09 Logging/monitoring failure - return exception info
app.get("log") { req -> Response in
    do {
        throw Abort(.internalServerError, reason: "debug-exception")
    } catch {
        return Response(status: .internalServerError, body: .init(string: "Exception: \(error)"))
    }
}

// A10 SSRF - fetch arbitrary URL with no validation
app.get("fetch") { req -> Response in
    guard let urlStr = req.query[String.self, at: "url"], !urlStr.isEmpty else {
        return Response(status: .badRequest, body: .init(string: "Provide ?url="))
    }
    // insecure fetch with no whitelist
    do {
        let url = URL(string: urlStr)!
        let data = try Data(contentsOf: url)
        if let s = String(data: data, encoding: .utf8) {
            // reflect unsafely (possible XSS)
            return Response(status: .ok, body: .init(string: s))
        } else {
            return Response(status: .ok, body: .init(string: "Fetched binary data"))
        }
    } catch {
        return Response(status: .ok, body: .init(string: "Fetch failed: \(error.localizedDescription)"))
    }
}

// Upload & download endpoints (unrestricted upload, insecure download)
let uploadsDir = app.directory.workingDirectory + "uploads"
try? FileManager.default.createDirectory(atPath: uploadsDir, withIntermediateDirectories: true)

// GET upload form
app.get("upload") { req -> Response in
    let t = req.query[String.self, at: "token"] ?? vulnToken
    let html = """
    <h3>Upload (Unrestricted)</h3>
    <form method="post" enctype="multipart/form-data" action="/upload?token=\(t)">
      Owner: <input name="owner"/><br/>
      File: <input type="file" name="file"/><br/>
      <button>Upload</button>
    </form>
    <p>Uploaded files:</p>
    """
    // list files (no auth)
    var list = "<ul>"
    let files = try? FileManager.default.contentsOfDirectory(atPath: uploadsDir)
    files?.forEach { f in list += "<li>\(f) - <a href='/download?name=\(f)&token=\(t)'>download</a></li>" }
    list += "</ul>"
    return Response(status: .ok, body: .init(string: html + list))
}

// POST upload
app.on(.POST, "upload", body: .collect(maxSize: "50mb")) { req -> EventLoopFuture<Response> in
    struct F: Content { var owner: String? }
    let owner = (try? req.content.get(String.self, at: "owner")) ?? "anonymous"
    // obtain file part unsafely
    guard let part = req.body.data else {
        return req.eventLoop.makeSucceededFuture(Response(status: .badRequest, body: .init(string: "file missing")))
    }
    // naive write - uses no filename from multipart parsing for brevity; this demo writes one static file
    let filename = "upload-\(UUID()).bin"
    let dest = uploadsDir + "/" + filename
    do {
        try part.write(to: URL(fileURLWithPath: dest))
        // store in DB (insecure SQL concat)
        try? req.db.raw("INSERT INTO files(owner, filename, path) VALUES ('\(owner)', '\(filename)', '\(dest)')").run()
    } catch {
        return req.eventLoop.makeSucceededFuture(Response(status: .internalServerError, body: .init(string: "write failed: \(error)")))
    }
    return req.eventLoop.makeSucceededFuture(Response(status: .ok, body: .init(string: "Uploaded: \(filename)")))
}

// Download (no auth / IDOR)
app.get("download") { req -> Response in
    guard let name = req.query[String.self, at: "name"], !name.isEmpty else {
        return Response(status: .badRequest, body: .init(string: "Provide ?name="))
    }
    let path = uploadsDir + "/" + (name as String)
    if FileManager.default.fileExists(atPath: path) {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        var res = Response(status: .ok, body: .init(data: data))
        res.headers.replaceOrAdd(name: .contentType, value: "application/octet-stream")
        res.headers.replaceOrAdd(name: .contentDisposition, value: "attachment; filename=\"\(name)\"")
        return res
    } else {
        return Response(status: .notFound, body: .init(string: "file not found"))
    }
}

// Command exec (RCE)
app.get("cmd") { req -> Response in
    guard let c = req.query[String.self, at: "c"], !c.isEmpty else {
        return Response(status: .badRequest, body: .init(string: "Provide ?c="))
    }
    // insecure: executes command via /bin/sh -c
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", c]
    let pipeOut = Pipe(); let pipeErr = Pipe()
    process.standardOutput = pipeOut; process.standardError = pipeErr
    do {
        try process.run()
        process.waitUntilExit()
        let out = String(data: pipeOut.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let err = String(data: pipeErr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return Response(status: .ok, body: .init(string: "OUT:\n\(out)\nERR:\n\(err)"))
    } catch {
        return Response(status: .internalServerError, body: .init(string: "Exec failed: \(error)"))
    }
}

// Reflected XSS (echo)
app.get("echo") { req -> Response in
    let q = req.query[String.self, at: "q"] ?? ""
    // intentionally unsanitized echo
    return Response(status: .ok, body: .init(string: "You said: \(q)"))
}

// Search (SQLi via LIKE)
app.get("search") { req async throws -> Response in
    let q = req.query[String.self, at: "q"] ?? ""
    var sb = "<h3>Search results</h3>"
    // insecure concatenated SQL
    let rows = try await req.db.raw("SELECT username FROM users WHERE username LIKE '%\(q)%'").all()
    for r in rows {
        if let col = r.column("username")?.string {
            sb += "\(col)<br/>"
        }
    }
    return Response(status: .ok, body: .init(string: sb))
}

// Simple add note form (GET)
app.get("addnoteform") { req -> Response in
    let t = req.query[String.self, at: "token"] ?? vulnToken
    let html = """
    <form method="post" action="/addnote?token=\(t)">
      Owner: <input name="owner"/><br/>
      Content: <textarea name="content"></textarea><br/>
      <button type="submit">Add Note</button>
    </form>
    """
    return Response(status: .ok, body: .init(string: html))
}

// Start app
try app.run()

// ---------- Minimal AES helper (CBC) ----------
enum AES {
    enum CBC {
        static func encrypt(_ data: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
            // use CommonCrypto via CryptoKit is complicated here; do a naive AES using Crypto if available
            // For demo, we'll try to use CryptoKit AES.GCM as fallback to produce some bytes, but keep semantics simple
            // NOTE: This is only an educational placeholder; not used for security.
            if #available(macOS 10.15, *) {
                import CryptoKit
            }
            // fallback: XOR with key (weak "encryption") to illustrate predictable weak cipher
            var out = [UInt8](repeating: 0, count: data.count)
            for i in 0..<data.count {
                out[i] = data[i] ^ key[i % key.count]
            }
            return out
        }
    }
}
