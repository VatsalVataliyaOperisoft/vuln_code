import spark.Spark._
import java.sql._
import java.io._
import java.net.{HttpURLConnection, URL, InetAddress}
import java.nio.file.{Files, Paths, StandardCopyOption}
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import java.util.Base64
import scala.jdk.CollectionConverters._
import scala.util.Try

/**
 * Vulnerable Scala Lab (SAFETY-GATED)
 *
 * WARNING: Run this only on an isolated VM/container bound to localhost.
 * Usage:
 *   sbt run
 * Open on the same machine: http://127.0.0.1:4567/
 *
 * The app auto-generates VULN_TOKEN and displays it on root (/). All vulnerable endpoints
 * require token=<token> query param and refuse non-local requests.
 *
 * This intentionally contains many vulnerabilities for testing scanners:
 *  - Plaintext password storage
 *  - SQL Injection (concatenated queries)
 *  - Broken access control (returns all notes)
 *  - Stored & reflected XSS (no escaping)
 *  - SSRF (fetch arbitrary URL)
 *  - Command injection (Runtime.exec)
 *  - Unrestricted file upload / insecure download
 *  - Weak crypto (predictable IV & weak key)
 *  - Information disclosure (stack traces)
 *  - No CSRF protection
 *  - Insecure cookies (no HttpOnly/Secure)
 */

object Main {
  // DB file in app directory
  val dbFile = "vulnlab_scala.db"
  val jdbc = s"jdbc:sqlite:$dbFile"

  def main(args: Array[String]): Unit = {
    // Auto-generate token if not present
    val envToken = Option(System.getenv("VULN_TOKEN")).filter(_.nonEmpty).getOrElse {
      val r = new SecureRandom()
      val bytes = new Array
      r.nextBytes(bytes)
      val tok = bytes.map(b => f"$b%02x").mkString
      System.setProperty("VULN_TOKEN", tok) // also set as system property
      tok
    }

    // create DB and tables
    initDb()

    // configure Spark (embedded Jetty) to listen only on localhost
    ipAddress("127.0.0.1")
    port(4567)

    // Before filter: local-only and token gating for non-root paths
    before((req, res) => {
      val remote = req.ip()
      // allow root to display token
      if (req.pathInfo() == "/") return
      if (!isLocal(remote)) {
        halt(403, "Access denied: this lab is local-only.")
      }
      val token = Option(req.queryParams("token")).getOrElse("")
      val actualToken = Option(System.getenv("VULN_TOKEN")).orElse(Option(System.getProperty("VULN_TOKEN"))).getOrElse(envToken)
      if (token != actualToken) {
        halt(403, "Access denied: missing or invalid token. See / for the token.")
      }
    })

    // Root — shows token and links (token included)
    get("/", (req, res) => {
      val token = Option(System.getenv("VULN_TOKEN")).orElse(Option(System.getProperty("VULN_TOKEN"))).getOrElse(envToken)
      res.`type`("text/html")
      s"""
      |<h2>Vulnerable Scala Lab (LOCAL ONLY)</h2>
      |<p><strong>Auto token:</strong> <code>$token</code></p>
      |<p>Click to continue (local): <a href="/home?token=$token">Open Lab Home</a></p>
      |<hr/>
      |<ul>
      | <li><a href="/home?token=$token">Home</a></li>
      | <li><a href="/notes?token=$token">Broken Access Control / Stored XSS</a></li>
      | <li><a href="/crypto?token=$token">Weak Crypto / Plaintext Secret</a></li>
      | <li><a href="/login?user=admin&pass=123&token=$token">SQLi Login</a></li>
      | <li><a href="/transfer?from=a&to=b&amount=9999&token=$token">Insecure Transfer</a></li>
      | <li><a href="/config?token=$token">Info Leak / Misconfiguration</a></li>
      | <li><a href="/upload?token=$token">Unrestricted Upload</a></li>
      | <li><a href="/cmd?c=whoami&token=$token">Command Exec (insecure)</a></li>
      | <li><a href="/fetch?url=http://127.0.0.1:4567/config&token=$token">SSRF Fetch</a></li>
      |</ul>
      """.stripMargin
    })

    get("/home", (req, res) => {
      val token = req.queryParams("token")
      res.`type`("text/html")
      s"""
      |<h3>Vuln Lab Home</h3>
      |<ul>
      | <li><a href="/notes?token=$token">Notes</a></li>
      | <li><a href="/crypto?token=$token">Crypto</a></li>
      | <li><a href="/login?user=admin&pass=123&token=$token">Login (SQLi)</a></li>
      | <li><a href="/register?token=$token">Register (POST)</a></li>
      | <li><a href="/upload?token=$token">Upload</a></li>
      |</ul>
      """.stripMargin
    })

    // A01 Broken Access Control + Stored XSS (no owner filtering; shows all notes)
    get("/notes", (req, res) => {
      val sb = new StringBuilder("<h3>All Notes (no ACL)</h3>")
      usingConn { conn =>
        val st = conn.createStatement()
        val rs = st.executeQuery("SELECT id, owner, content FROM Notes;")
        while (rs.next()) {
          val owner = rs.getString("owner")
          val content = rs.getString("content")
          // intentionally not escaped -> stored XSS possible
          sb.append(s"<div style='border:1px solid #ccc;margin:6px;padding:6px'><b>Owner:</b> $owner<br/><b>Content:</b> $content</div>")
        }
      }
      sb.toString()
    })

    // Add note (vulnerable to stored XSS and SQLi via concatenation)
    post("/addnote", (req, res) => {
      val owner = Option(req.queryParams("owner")).getOrElse("anon")
      val content = Option(req.queryParams("content")).getOrElse("")
      usingConn { conn =>
        val st = conn.createStatement()
        // insecure concatenation -> SQL injection
        val sql = s"INSERT INTO Notes(owner, content) VALUES('$owner', '$content');"
        st.executeUpdate(sql)
      }
      "Note added (stored XSS possible)"
    })

    // A02 Cryptographic failures — plaintext secret + weak AES (predictable IV)
    get("/crypto", (req, res) => {
      val secret = "SuperSecretPlaintext"
      val key = "weakkeyweakkey" // 16 bytes weak key
      val (enc, ok) = tryEncryptAes(secret, key)
      s"<h3>Plaintext: $secret</h3><p>Weak AES-CBC (predictable IV) hex: $enc</p>"
    })

    // A03 SQL injection - login concatenation
    get("/login", (req, res) => {
      val user = Option(req.queryParams("user")).getOrElse("")
      val pass = Option(req.queryParams("pass")).getOrElse("")
      var cnt = 0
      usingConn { conn =>
        val st = conn.createStatement()
        // insecure: direct concatenation -> SQLi
        val q = s"SELECT COUNT(*) AS c FROM Users WHERE Username='$user' AND Password='$pass';"
        val rs = st.executeQuery(q)
        if (rs.next()) cnt = rs.getInt("c")
      }
      if (cnt == 1) "Login ok" else "Invalid"
    })

    // A04 Insecure design - no auth or limit on transfer
    get("/transfer", (req, res) => {
      val from = Option(req.queryParams("from")).getOrElse("a")
      val to = Option(req.queryParams("to")).getOrElse("b")
      val amount = Option(req.queryParams("amount")).getOrElse("0")
      s"Transferred $amount from $from to $to"
    })

    // A05 Info disclosure
    get("/config", (req, res) => {
      val env = System.getProperties().asScala.map{ case (k,v) => s"$k=$v"}.mkString("\n")
      s"<h4>Environment (insecure)</h4><pre>$env</pre><h4>Sample Stack</h4><pre>${Thread.currentThread().getStackTrace.take(10).mkString("\n")}</pre>"
    })

    // A06 components
    get("/components", (req, res) => {
      "Running with simulated outdated components (demo)."
    })

    // A07 register (plaintext password storage; SQLi via concat)
    post("/register", (req, res) => {
      val user = Option(req.queryParams("user")).getOrElse("")
      val pass = Option(req.queryParams("pass")).getOrElse("")
      usingConn { conn =>
        val st = conn.createStatement()
        val q = s"INSERT INTO Users(Username, Password) VALUES('$user', '$pass');"
        st.executeUpdate(q)
      }
      // insecure cookie (no HttpOnly/Secure)
      res.raw().addHeader("Set-Cookie", s"lab_user=$user; Path=/")
      "User created (plaintext password stored)"
    })

    // A08 update (no signature verification)
    get("/update", (req, res) => "Downloading updates from unverified source...")

    // A09 logging/monitoring failures - leaks exception to user
    get("/log", (req, res) => {
      try {
        throw new RuntimeException("Debug Exception Example")
      } catch {
        case e: Throwable =>
          // insecure: return full stack trace
          s"Exception: ${e.toString}\n${e.getStackTrace.mkString("\n")}"
      }
    })

    // A10 SSRF
    get("/fetch", (req, res) => {
      val url = Option(req.queryParams("url")).getOrElse("")
      if (url.isEmpty) halt(400, "Provide ?url=")
      val content = tryFetch(url)
      // reflect unsafely (possible XSS if HTML)
      content
    })

    // File upload (unrestricted)
    get("/upload", (req, res) => {
      val token = req.queryParams("token")
      s"""
      |<h3>Upload (Unrestricted)</h3>
      |<form method="post" enctype="multipart/form-data" action="/upload?token=$token">
      |  Owner: <input name="owner"/><br/>
      |  File: <input type="file" name="file"/><br/>
      |  <button type="submit">Upload</button>
      |</form>
      |<p>Uploaded files:</p>
      |${listFilesHtml()}
      |""".stripMargin
    })

    post("/upload", (req, res) => {
      // Jetty multipart support via Spark: use request.raw() to access parts
      val raw = req.raw()
      raw.setAttribute("org.eclipse.jetty.multipartConfig", new javax.servlet.MultipartConfigElement("/tmp"))
      val part = raw.getPart("file")
      val owner = Option(req.queryParams("owner")).getOrElse("anonymous")
      if (part == null) {
        halt(400, "file missing")
      }
      val filename = Paths.get(part.getSubmittedFileName).getFileName.toString
      val uploadDir = Paths.get("uploads")
      if (!Files.exists(uploadDir)) Files.createDirectories(uploadDir)
      val dest = uploadDir.resolve(filename)
      val is = part.getInputStream
      Files.copy(is, dest, StandardCopyOption.REPLACE_EXISTING)
      part.delete()
      usingConn { conn =>
        val st = conn.createStatement()
        // insecure: concatenated SQL
        val q = s"INSERT INTO Files(Owner, Filename, Path) VALUES('$owner', '$filename', '${dest.toAbsolutePath.toString}');"
        st.executeUpdate(q)
      }
      s"Uploaded as $filename"
    })

    // Download (IDOR / no auth)
    get("/download", (req, res) => {
      val id = Try(req.queryParams("id").toInt).getOrElse(0)
      var path = ""
      var filename = ""
      usingConn { conn =>
        val st = conn.createStatement()
        val rs = st.executeQuery(s"SELECT Path, Filename FROM Files WHERE rowid=$id;")
        if (rs.next()) {
          path = rs.getString("Path")
          filename = rs.getString("Filename")
        }
      }
      if (path.isEmpty || !Files.exists(Paths.get(path))) halt(404, "file missing")
      // insecure: serve file directly
      res.raw().setContentType("application/octet-stream")
      res.header("Content-Disposition", s"""attachment; filename="$filename"""")
      Files.copy(Paths.get(path), res.raw().getOutputStream)
      res.raw().getOutputStream.flush()
      ""
    })

    // Command execution (very dangerous)
    get("/cmd", (req, res) => {
      val c = Option(req.queryParams("c")).getOrElse("")
      if (c.isEmpty) halt(400, "Provide ?c=")
      try {
        // insecure: pass user input directly to shell
        val p = Runtime.getRuntime.exec(Array("/bin/sh", "-c", c))
        val out = scala.io.Source.fromInputStream(p.getInputStream).mkString
        val err = scala.io.Source.fromInputStream(p.getErrorStream).mkString
        p.waitFor()
        s"OUT:\n$out\nERR:\n$err"
      } catch {
        case e: Exception => s"Exec failed: ${e.getMessage}"
      }
    })

    // Reflected XSS demo
    get("/echo", (req, res) => {
      val q = Option(req.queryParams("q")).getOrElse("")
      // insecure reflect
      s"You said: $q"
    })

    // Search with LIKE (SQLi)
    get("/search", (req, res) => {
      val q = Option(req.queryParams("q")).getOrElse("")
      val sb = new StringBuilder("<h3>Search results</h3>")
      usingConn { conn =>
        val st = conn.createStatement()
        val rs = st.executeQuery(s"SELECT Username FROM Users WHERE Username LIKE '%$q%';")
        while (rs.next()) sb.append(rs.getString(1) + "<br/>")
      }
      sb.toString()
    })

    // add sample note insertion endpoint for stored XSS (form)
    get("/addnoteform", (req, res) => {
      val token = req.queryParams("token")
      s"""
      |<form method="post" action="/addnote?token=$token">
      | Owner: <input name="owner"/><br/>
      | Content: <textarea name="content"></textarea><br/>
      | <button type="submit">Add Note</button>
      |</form>
      |""".stripMargin
    })

    // simple search page
    get("/searchform", (req,res) => {
      val token = req.queryParams("token")
      s"""
      |<form method="get" action="/search?token=$token">
      | Query: <input name="q"/><button>Search</button>
      |</form>
      |""".stripMargin
    )

    // graceful shutdown on Ctrl+C handled by sbt/run; nothing special to add
    println(s"Vulnerable Scala Lab started on http://127.0.0.1:4567/ (local only). Token: ${envToken}")
  }

  // Helper: create DB and tables
  def initDb(): Unit = {
    Class.forName("org.sqlite.JDBC")
    usingConn { conn =>
      val stmt = conn.createStatement()
      stmt.executeUpdate(
        """CREATE TABLE IF NOT EXISTS Users(Id INTEGER PRIMARY KEY, Username TEXT, Password TEXT)"""
      )
      stmt.executeUpdate(
        """CREATE TABLE IF NOT EXISTS Notes(Id INTEGER PRIMARY KEY, Owner TEXT, Content TEXT)"""
      )
      stmt.executeUpdate(
        """CREATE TABLE IF NOT EXISTS Files(Id INTEGER PRIMARY KEY, Owner TEXT, Filename TEXT, Path TEXT)"""
      )
      // insert a default user (plaintext password)
      val ps = conn.prepareStatement("INSERT INTO Users(Username, Password) VALUES(?, ?)")
      ps.setString(1, "admin")
      ps.setString(2, "123")
      Try(ps.executeUpdate())
    }
  }

  // DB helper
  def usingConn[T](f: Connection => T): T = {
    val conn = DriverManager.getConnection(jdbc)
    try f(conn) finally conn.close()
  }

  // check local ip
  def isLocal(ip: String): Boolean = {
    if (ip == null) return false
    ip == "127.0.0.1" || ip == "::1" || ip == InetAddress.getLoopbackAddress.getHostAddress
  }

  // weak AES encrypt demo (predictable IV)
  def tryEncryptAes(plain: String, keyStr: String): (String, Boolean) = {
    try {
      val key = keyStr.getBytes("UTF-8")
      val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
      val secretKey = new SecretKeySpec(key, "AES")
      val iv = new Array // predictable zero IV
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv))
      val cipherBytes = cipher.doFinal(plain.getBytes("UTF-8"))
      val hex = cipherBytes.map(b => f"$b%02x").mkString
      (hex, true)
    } catch {
      case e: Throwable => ("encrypt-failed", false)
    }
  }

  // fetch arbitrary URL (SSRF)
  def tryFetch(urlStr: String): String = {
    try {
      val url = new URL(urlStr)
      val conn = url.openConnection().asInstanceOf[HttpURLConnection]
      conn.setConnectTimeout(3000)
      conn.setReadTimeout(3000)
      conn.setRequestMethod("GET")
      val is = conn.getInputStream
      val s = scala.io.Source.fromInputStream(is).mkString
      is.close()
      s
    } catch {
      case e: Throwable => s"Fetch failed: ${e.getMessage}"
    }
  }

  def listFilesHtml(): String = {
    val sb = new StringBuilder("<ul>")
    usingConn { conn =>
      val st = conn.createStatement()
      val rs = st.executeQuery("SELECT Id, Owner, Filename FROM Files;")
      while (rs.next()) {
        val id = rs.getInt(1)
        val owner = rs.getString(2)
        val fn = rs.getString(3)
        sb.append(s"""<li>$fn (owner:$owner) - <a href="/download?id=$id">download</a></li>""")
      }
    }
    sb.append("</ul>")
    sb.toString()
  }
}
