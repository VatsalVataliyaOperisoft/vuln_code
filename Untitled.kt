/**
 * VulnLabKtor.kt
 *
 * Single-file Ktor app (vulnerable endpoints) — LOCAL-ONLY & TOKEN-GATED
 *
 * WARNING: Run only in an isolated VM/container bound to localhost.
 *
 * How to run (quick):
 * 1) Create a Gradle Kotlin project (minimal). In build.gradle.kts include:
 *
 *    plugins {
 *      kotlin("jvm") version "1.9.0"
 *      application
 *    }
 *    repositories { mavenCentral() }
 *    dependencies {
 *      implementation("io.ktor:ktor-server-netty:2.3.5")
 *      implementation("io.ktor:ktor-server-core:2.3.5")
 *      implementation("io.ktor:ktor-server-cio:2.3.5")
 *      implementation("io.ktor:ktor-server-host-common:2.3.5")
 *      implementation("io.ktor:ktor-server-html-builder:2.3.5")
 *      implementation("org.xerial:sqlite-jdbc:3.42.0.0")
 *      implementation("ch.qos.logback:logback-classic:1.4.7")
 *    }
 *    application { mainClass.set("VulnLabKtorKt") }
 *
 * 2) Put this file as src/main/kotlin/VulnLabKtor.kt
 * 3) Run `./gradlew run` inside an isolated VM/container bound to localhost.
 * 4) Open http://127.0.0.1:8080/ in the same VM. Root will show the token.
 *
 * NOTE: This app intentionally contains vulnerabilities for testing scanners. Do NOT expose to public networks.
 */

import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.http.content.*
import io.ktor.server.sessions.*
import io.ktor.util.pipeline.*
import io.ktor.http.*
import io.ktor.http.content.*
import java.sql.DriverManager
import java.sql.Connection
import java.io.File
import kotlin.system.exitProcess
import kotlin.text.Charsets
import java.security.SecureRandom
import java.util.Base64
import java.nio.file.Files
import java.nio.file.Paths
import java.lang.ProcessBuilder

fun main() {
    // Auto-generate token if not set
    val envToken = System.getenv("VULN_TOKEN")?.takeIf { it.isNotBlank() } ?: run {
        val rnd = SecureRandom()
        val b = ByteArray(16)
        rnd.nextBytes(b)
        val gen = b.joinToString("") { "%02x".format(it) }
        // Not permanently setting environment variables in JVM; but we'll use this value in appConfig below
        gen
    }

    // Database file in the working directory
    val dbPath = "vulnlab_ktor.db"
    Class.forName("org.sqlite.JDBC")
    val conn = DriverManager.getConnection("jdbc:sqlite:$dbPath")
    conn.createStatement().use { st ->
        st.executeUpdate("PRAGMA journal_mode=WAL;")
        st.executeUpdate("CREATE TABLE IF NOT EXISTS Users(Id INTEGER PRIMARY KEY, Username TEXT, Password TEXT);")
        st.executeUpdate("CREATE TABLE IF NOT EXISTS Notes(Id INTEGER PRIMARY KEY, Owner TEXT, Content TEXT);")
        st.executeUpdate("CREATE TABLE IF NOT EXISTS Files(Id INTEGER PRIMARY KEY, Owner TEXT, Filename TEXT, Path TEXT);")
        // ensure an admin user exists (plaintext password)
        st.executeUpdate("INSERT OR IGNORE INTO Users(Username, Password) VALUES('admin','123');")
    }

    // ensure uploads dir exists
    val uploadDir = Paths.get("uploads")
    if (!Files.exists(uploadDir)) Files.createDirectories(uploadDir)

    // Launch Ktor embedded server (Netty)
    embeddedServer(Netty, port = 8080, host = "127.0.0.1") {
        module(envToken, dbPath, uploadDir.toString())
    }.start(wait = true)
}

fun Application.module(token: String, dbPath: String, uploadDir: String) {
    // Middleware: allow root only without token so user can see token; otherwise require local-only + token
    intercept(ApplicationCallPipeline.Plugins) {
        val path = call.request.path()
        if (path == "/") return@intercept
        if (!isLocal(call)) {
            call.respond(HttpStatusCode.Forbidden, "Access denied: this lab accepts requests from localhost only.")
            finish() // stop processing
            return@intercept
        }
        val reqToken = call.request.queryParameters["token"] ?: ""
        if (reqToken != token) {
            call.respond(HttpStatusCode.Forbidden, "Access denied: missing or invalid token. See root / for token.")
            finish()
            return@intercept
        }
    }

    routing {
        // Root displays token and tokenized links
        get("/") {
            val html = buildString {
                append("<h2>VulnLab Ktor (LOCAL ONLY)</h2>")
                append("<p><strong>Auto token:</strong> <code>${token}</code></p>")
                append("<p>Click: <a href=\"/home?token=${token}\">Open lab home (local)</a></p><hr/>")
                append("<ul>")
                append("<li><a href=\"/home?token=${token}\">Home</a></li>")
                append("<li><a href=\"/notes?token=${token}\">A01 Broken Access Control</a></li>")
                append("<li><a href=\"/crypto?token=${token}\">A02 Cryptographic Failures</a></li>")
                append("<li><a href=\"/login?user=admin&pass=123&token=${token}\">A03 Injection (login)</a></li>")
                append("<li><a href=\"/transfer?from=a&to=b&amount=5000&token=${token}\">A04 Insecure Design</a></li>")
                append("<li><a href=\"/config?token=${token}\">A05 Misconfiguration</a></li>")
                append("<li><a href=\"/components?token=${token}\">A06 Outdated Components</a></li>")
                append("<li><form method='post' action='/register?token=${token}'><input name='user' placeholder='user'/> <input name='pass' placeholder='pass'/> <button>Register (A07)</button></form></li>")
                append("<li><a href=\"/update?token=${token}\">A08 Integrity Failures</a></li>")
                append("<li><a href=\"/log?token=${token}\">A09 Logging Failures</a></li>")
                append("<li><a href=\"/fetch?url=http://127.0.0.1:8080/config&token=${token}\">A10 SSRF</a></li>")
                append("<li><a href=\"/upload?token=${token}\">Upload (Unrestricted)</a></li>")
                append("</ul>")
            }
            call.respondText(html, ContentType.Text.Html)
        }

        get("/home") {
            val t = call.request.queryParameters["token"] ?: token
            val html = """
                <h3>Vuln Lab Home</h3>
                <ul>
                  <li><a href="/notes?token=$t">Notes</a></li>
                  <li><a href="/crypto?token=$t">Crypto</a></li>
                  <li><a href="/login?user=admin&pass=123&token=$t">Login</a></li>
                  <li><a href="/upload?token=$t">Upload</a></li>
                </ul>
            """.trimIndent()
            call.respondText(html, ContentType.Text.Html)
        }

        // -------------------------------
        // A01 Broken Access Control + Stored XSS
        // -------------------------------
        get("/notes") {
            val sb = StringBuilder("<h3>All Notes (no ACL)</h3>")
            DriverManager.getConnection("jdbc:sqlite:$dbPath").use { c ->
                val st = c.createStatement()
                val rs = st.executeQuery("SELECT Id, Owner, Content FROM Notes;")
                while (rs.next()) {
                    val owner = rs.getString("Owner")
                    val content = rs.getString("Content")
                    // intentionally NOT escaping -> stored XSS possible
                    sb.append("<div style='border:1px solid #ccc;margin:6px;padding:6px'><strong>Owner:</strong> $owner<br/><strong>Content:</strong> $content</div>")
                }
            }
            call.respondText(sb.toString(), ContentType.Text.Html)
        }

        post("/addnote") {
            val params = call.receiveParameters()
            val owner = params["owner"] ?: "anonymous"
            val content = params["content"] ?: ""
            // insecure: concatenated SQL -> SQLi possible
            DriverManager.getConnection("jdbc:sqlite:$dbPath").use { c ->
                val st = c.createStatement()
                st.executeUpdate("INSERT INTO Notes(Owner, Content) VALUES('$owner', '$content');")
            }
            call.respondText("Note added (stored XSS possible)", ContentType.Text.Plain)
        }

        // -------------------------------
        // A02 Crypto (plaintext + weak IV)
        // -------------------------------
        get("/crypto") {
            val secret = "SensitivePlaintext"
            // weak key + predictable IV demonstration (do NOT use)
            val key = "weakkeyweakkey" // 16 bytes
            val iv = ByteArray(16) // zeros
            val cipherHex = try {
                // naive XOR "encryption" as weak placeholder for demo
                val cipher = secret.toByteArray(Charsets.UTF_8).mapIndexed { i, b -> (b.toInt() xor key[i % key.length].code).toByte() }.toByteArray()
                cipher.joinToString("") { "%02x".format(it) }
            } catch (e: Exception) { "encrypt-failed" }
            call.respondText("Plaintext: $secret<br/>Weak cipher hex: $cipherHex", ContentType.Text.Html)
        }

        // -------------------------------
        // A03 Injection (SQLi) - login
        // -------------------------------
        get("/login") {
            val user = call.request.queryParameters["user"] ?: ""
            val pass = call.request.queryParameters["pass"] ?: ""
            var count = 0
            DriverManager.getConnection("jdbc:sqlite:$dbPath").use { c ->
                val st = c.createStatement()
                // insecure concatenation → SQLi
                val rs = st.executeQuery("SELECT COUNT(*) AS c FROM Users WHERE Username='$user' AND Password='$pass';")
                if (rs.next()) count = rs.getInt("c")
            }
            call.respondText(if (count == 1) "Login ok" else "Invalid", ContentType.Text.Plain)
        }

        // -------------------------------
        // A04 Insecure Design (no auth / limits)
        // -------------------------------
        get("/transfer") {
            val from = call.request.queryParameters["from"] ?: "a"
            val to = call.request.queryParameters["to"] ?: "b"
            val amount = call.request.queryParameters["amount"] ?: "0"
            call.respondText("Transferred $amount from $from to $to", ContentType.Text.Plain)
        }

        // -------------------------------
        // A05 Security Misconfiguration / Info leak
        // -------------------------------
        get("/config") {
            val env = System.getenv().map { (k, v) -> "$k=$v" }.joinToString("\n")
            val stack = Thread.currentThread().stackTrace.joinToString("\n")
            call.respondText("<pre>Environment:\n$env\n\nStack:\n$stack</pre>", ContentType.Text.Html)
        }

        // -------------------------------
        // A06 Outdated components (simulated)
        // -------------------------------
        get("/components") {
            call.respondText("Simulated: outdated components (demo)", ContentType.Text.Plain)
        }

        // -------------------------------
        // A07 Auth failures - register stores plaintext password
        // -------------------------------
        post("/register") {
            val params = call.receiveParameters()
            val user = params["user"] ?: ""
            val pass = params["pass"] ?: ""
            if (user.isBlank() || pass.isBlank()) {
                call.respond(HttpStatusCode.BadRequest, "user/pass required")
                return@post
            }
            DriverManager.getConnection("jdbc:sqlite:$dbPath").use { c ->
                val st = c.createStatement()
                // insecure concatenation → SQLi possible
                st.executeUpdate("INSERT INTO Users(Username, Password) VALUES('$user', '$pass');")
            }
            // insecure cookie (no HttpOnly/Secure)
            call.response.cookies.append("lab_user", user)
            call.respondText("User created (plaintext password stored)", ContentType.Text.Plain)
        }

        // -------------------------------
        // A08 Integrity failures - update (no signature verification)
        // -------------------------------
        get("/update") {
            call.respondText("Downloading updates from unverified source...", ContentType.Text.Plain)
        }

        // -------------------------------
        // A09 Logging & Monitoring failures (show exception)
        // -------------------------------
        get("/log") {
            try {
                throw RuntimeException("Example debug exception")
            } catch (e: Exception) {
                // insecure: show exception details to user
                call.respondText("Error: ${e}\n${e.stackTrace.joinToString("\n")}", ContentType.Text.Plain)
            }
        }

        // -------------------------------
        // A10 SSRF - fetch arbitrary URL
        // -------------------------------
        get("/fetch") {
            val url = call.request.queryParameters["url"] ?: ""
            if (url.isBlank()) {
                call.respond(HttpStatusCode.BadRequest, "Provide ?url=")
                return@get
            }
            val content = try {
                java.net.URL(url).readText()
            } catch (e: Exception) {
                "Fetch failed: ${e.message}"
            }
            // reflect raw content unsafely (possible XSS)
            call.respondText(content, ContentType.Text.Html)
        }

        // -------------------------------
        // Unrestricted file upload & download
        // -------------------------------
        get("/upload") {
            val t = call.request.queryParameters["token"] ?: token
            val sb = StringBuilder()
            sb.append("<h3>Upload (Unrestricted)</h3>")
            sb.append("<form method='post' enctype='multipart/form-data' action='/upload?token=$t'>")
            sb.append("Owner: <input name='owner'/><br/>File: <input type='file' name='file'/><br/><button>Upload</button></form>")
            sb.append("<h4>Files</h4><ul>")
            val files = File(uploadDir).listFiles() ?: arrayOf()
            for (f in files) {
                sb.append("<li>${f.name} - <a href='/download?name=${f.name}&token=$t'>download</a></li>")
            }
            sb.append("</ul>")
            call.respondText(sb.toString(), ContentType.Text.Html)
        }

        post("/upload") {
            val multipart = call.receiveMultipart()
            var owner = "anonymous"
            var savedName: String? = null
            multipart.forEachPart { part ->
                when (part) {
                    is PartData.FormItem -> {
                        if (part.name == "owner") owner = part.value
                    }
                    is PartData.FileItem -> {
                        val orig = part.originalFileName ?: "upload.bin"
                        val sanitized = Paths.get(orig).fileName.toString() // remove path
                        val dest = Paths.get(uploadDir, sanitized).toFile()
                        part.streamProvider().use { its ->
                            dest.outputStream().buffered().use { fos -> its.copyTo(fos) }
                        }
                        savedName = sanitized
                        // insecure DB insertion with concatenation
                        DriverManager.getConnection("jdbc:sqlite:$dbPath").use { c ->
                            val st = c.createStatement()
                            st.executeUpdate("INSERT INTO Files(Owner, Filename, Path) VALUES('$owner', '$sanitized', '${dest.absolutePath}');")
                        }
                    }
                    else -> {}
                }
                part.dispose()
            }
            call.respondText("Uploaded as ${savedName ?: "unknown"}", ContentType.Text.Plain)
        }

        get("/download") {
            val name = call.request.queryParameters["name"] ?: ""
            if (name.isBlank()) {
                call.respond(HttpStatusCode.BadRequest, "Provide ?name=")
                return@get
            }
            val f = File(Paths.get(uploadDir, name).toString())
            if (!f.exists()) {
                call.respond(HttpStatusCode.NotFound, "file not found")
                return@get
            }
            call.respondFile(f)
        }

        // -------------------------------
        // Command execution (dangerous)
        // -------------------------------
        get("/cmd") {
            val c = call.request.queryParameters["c"] ?: ""
            if (c.isBlank()) {
                call.respond(HttpStatusCode.BadRequest, "Provide ?c=")
                return@get
            }
            try {
                // insecure: direct shell execution
                val pb = ProcessBuilder("/bin/sh", "-c", c)
                val proc = pb.start()
                val out = proc.inputStream.bufferedReader().readText()
                val err = proc.errorStream.bufferedReader().readText()
                proc.waitFor()
                call.respondText("OUT:\n$out\nERR:\n$err", ContentType.Text.Plain)
            } catch (e: Exception) {
                call.respondText("Exec failed: ${e.message}", ContentType.Text.Plain)
            }
        }

        // Reflected XSS demo
        get("/echo") {
            val q = call.request.queryParameters["q"] ?: ""
            // unsafe reflect
            call.respondText("You said: $q", ContentType.Text.Html)
        }

        // Simple search demonstrating SQLi via LIKE concatenation
        get("/search") {
            val q = call.request.queryParameters["q"] ?: ""
            val sb = StringBuilder("<h3>Search results</h3>")
            DriverManager.getConnection("jdbc:sqlite:$dbPath").use { c ->
                val st = c.createStatement()
                val rs = st.executeQuery("SELECT Username FROM Users WHERE Username LIKE '%$q%';")
                while (rs.next()) {
                    sb.append(rs.getString("Username") + "<br/>")
                }
            }
            call.respondText(sb.toString(), ContentType.Text.Html)
        }

    } // routing end
}

// helper to detect local requests
fun isLocal(call: ApplicationCall): Boolean {
    val addr = call.request.host() // returns host header, not ideal; better to use remoteHost from request
    // Ktor provides remoteHost via request.local/remote? Use X-Forwarded-For risks — we check socket
    val remote = call.request.origin.remoteHost
    return remote == "127.0.0.1" || remote == "0:0:0:0:0:0:0:1" || remote == "localhost" || remote == "::1"
}
