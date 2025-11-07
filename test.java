import java.io.*;
import java.net.*;
import java.sql.*;
import java.security.*;
import java.util.*;
import java.util.regex.Pattern;

// 🔴 VULNERABLE CODE - FOR EDUCATIONAL PURPOSES ONLY
public class VulnerableBankApp {
    
    // 🔴 Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/bank";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "admin123";
    
    // 🔴 Weak encryption key
    private static final String ENCRYPTION_KEY = "weakkey";
    private static Connection connection;
    
    // 🔴 In-memory "database" - vulnerable to memory attacks
    private static Map<String, User> users = new HashMap<>();
    private static Map<String, String> sessions = new HashMap<>();
    
    public static void main(String[] args) throws Exception {
        initializeDatabase();
        startServer();
    }
    
    // 🔴 A1: INJECTION VULNERABILITIES
    
    // 🔴 SQL Injection
    public static boolean loginSQLInjection(String username, String password) throws SQLException {
        // 🔴 Direct string concatenation - SQL Injection
        String query = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
        
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }
    
    // 🔴 Command Injection
    public static void pingHost(String host) throws IOException {
        // 🔴 Command Injection vulnerability
        Runtime.getRuntime().exec("ping -c 4 " + host);
    }
    
    // 🔴 LDAP Injection (simulated)
    public static boolean authenticateLDAP(String username, String password) {
        // 🔴 LDAP Injection pattern
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        // Simulated vulnerable LDAP query
        return executeLDAPQuery(filter);
    }
    
    // 🔴 A2: BROKEN AUTHENTICATION
    
    // 🔴 Weak password hashing (MD5)
    public static String hashPasswordWeak(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return bytesToHex(md.digest(password.getBytes()));
        } catch (Exception e) {
            return password; // 🔴 Fallback to plaintext!
        }
    }
    
    // 🔴 Password in URL
    public static boolean loginWithURLParams(String url) {
        // 🔴 Password in URL parameters
        if (url.contains("password=")) {
            String password = url.split("password=")[1].split("&")[0];
            return checkPassword(password);
        }
        return false;
    }
    
    // 🔴 Session fixation vulnerability
    public static String createSession(String username) {
        // 🔴 Predictable session ID
        String sessionId = username + System.currentTimeMillis();
        sessions.put(sessionId, username);
        return sessionId;
    }
    
    // 🔴 A3: SENSITIVE DATA EXPOSURE
    
    // 🔴 Plaintext password storage
    public static void registerUser(String username, String password) {
        users.put(username, new User(username, password)); // 🔴 Storing plaintext password
    }
    
    // 🔴 Credit card in memory without protection
    public static String processPayment(String cardNumber, String expiry, String cvv) {
        // 🔴 Storing sensitive data in memory
        String paymentData = "Card: " + cardNumber + " Expiry: " + expiry + " CVV: " + cvv;
        System.out.println("Processing: " + paymentData); // 🔴 Logging sensitive data
        return "Payment processed";
    }
    
    // 🔴 A4: XXE - XML External Entities
    public static String parseXML(String xmlData) {
        try {
            // 🔴 Vulnerable XML parsing (simplified)
            if (xmlData.contains("<!ENTITY")) {
                // 🔴 Processing external entities
                return "XXE processed: " + xmlData;
            }
            return "XML parsed";
        } catch (Exception e) {
            return "Error: " + e.getMessage(); // 🔴 Information disclosure
        }
    }
    
    // 🔴 A5: BROKEN ACCESS CONTROL
    
    // 🔴 No authorization check
    public static String deleteUser(String currentUser, String targetUser) {
        // 🔴 Any user can delete any other user
        users.remove(targetUser);
        return targetUser + " deleted by " + currentUser;
    }
    
    // 🔴 Direct object reference
    public static String getUserFile(String username, String requestedFile) {
        // 🔴 No access control - users can access any file
        return readFile("/home/" + username + "/" + requestedFile);
    }
    
    // 🔴 A6: SECURITY MISCONFIGURATION
    
    // 🔴 Debug endpoints enabled in production
    public static String debugInfo(String endpoint) {
        if ("memory".equals(endpoint)) {
            return "Memory usage: " + Runtime.getRuntime().totalMemory();
        } else if ("users".equals(endpoint)) {
            return "Users: " + users.keySet(); // 🔴 Exposing user list
        }
        return "Debug info";
    }
    
    // 🔴 Default credentials
    public static boolean checkDefaultCredentials(String user, String pass) {
        return "admin".equals(user) && "admin".equals(pass); // 🔴 Default credentials
    }
    
    // 🔴 A7: CROSS-SITE SCRIPTING (XSS)
    
    // 🔴 Reflected XSS
    public static String searchProducts(String query) {
        // 🔴 No output encoding
        return "<div>Search results for: " + query + "</div>";
    }
    
    // 🔴 Stored XSS simulation
    public static void addComment(String user, String comment) {
        // 🔴 Storing unsanitized user input
        users.get(user).comments.add(comment);
    }
    
    // 🔴 A8: INSECURE DESERIALIZATION
    
    // 🔴 Insecure deserialization
    public static Object deserializeData(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject(); // 🔴 RCE vulnerability
    }
    
    // 🔴 A9: USING KNOWN VULNERABLE COMPONENTS
    
    // 🔴 Using weak random number generator
    public static String generatePassword() {
        Random rand = new Random(); // 🔴 Not cryptographically secure
        return "pass" + rand.nextInt(10000);
    }
    
    // 🔴 Weak SSL/TLS simulation (conceptual)
    public static void connectWithWeakSSL(String url) {
        // 🔴 Would use weak protocols in real implementation
        System.out.println("Connecting with weak SSL to: " + url);
    }
    
    // 🔴 A10: INSUFFICIENT LOGGING & MONITORING
    
    // 🔴 No security logging
    public static boolean transferMoney(String from, String to, double amount) {
        // 🔴 No audit trail
        boolean success = performTransfer(from, to, amount);
        System.out.println("Transfer completed"); // 🔴 Insufficient logging
        return success;
    }
    
    // 🔴 ADDITIONAL VULNERABILITIES
    
    // 🔴 Path Traversal
    public static String readFile(String path) {
        try {
            // 🔴 No path validation
            BufferedReader reader = new BufferedReader(new FileReader(path));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            return content.toString();
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }
    
    // 🔴 Buffer overflow simulation (Java has bounds checking, but showing pattern)
    public static void processLargeInput(String input) {
        // 🔴 Potential resource exhaustion
        byte[] buffer = new byte[1024]; // 🔴 Fixed small buffer
        System.arraycopy(input.getBytes(), 0, buffer, 0, input.length());
    }
    
    // 🔴 Race condition
    private static double balance = 1000.0;
    
    public static void withdraw(String user, double amount) {
        if (balance >= amount) {
            // 🔴 Race condition window
            try { Thread.sleep(100); } catch (InterruptedException e) {}
            balance -= amount;
            System.out.println(user + " withdrew: " + amount);
        }
    }
    
    // 🔴 Weak cryptography
    public static String encryptWeak(String data) {
        // 🔴 Simple XOR "encryption" - very weak
        byte[] bytes = data.getBytes();
        byte[] key = ENCRYPTION_KEY.getBytes();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] ^ key[i % key.length]);
        }
        return Base64.getEncoder().encodeToString(bytes);
    }
    
    // 🔴 Integer overflow
    public static int calculateTotal(int[] values) {
        int total = 0;
        for (int value : values) {
            total += value; // 🔴 Potential integer overflow
        }
        return total;
    }
    
    // 🔴 Format string vulnerability simulation
    public static String formatMessage(String format, String input) {
        // 🔴 User-controlled format string
        return String.format(format, input);
    }
    
    // 🔴 Unsafe reflection
    public static Object createInstance(String className) throws Exception {
        // 🔴 User-controlled class loading
        return Class.forName(className).newInstance();
    }
    
    // Helper methods
    private static void initializeDatabase() throws SQLException {
        // Simulate database connection
        connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
    }
    
    private static void startServer() {
        System.out.println("Vulnerable server started...");
    }
    
    private static boolean executeLDAPQuery(String filter) {
        // Simulated LDAP query execution
        return true;
    }
    
    private static boolean checkPassword(String password) {
        return password != null;
    }
    
    private static boolean performTransfer(String from, String to, double amount) {
        return true;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

// 🔴 Vulnerable data class
class User implements Serializable {
    public String username;
    public String password; // 🔴 Plaintext password
    public List<String> comments = new ArrayList<>();
    
    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }
    
    // 🔴 Dangerous deserialization method
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 🔴 Could execute arbitrary code
    }
}

// 🔴 Malicious class that could be deserialized
class MaliciousPayload implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            // 🔴 This would execute during deserialization
            Runtime.getRuntime().exec("calc.exe");
        } catch (Exception e) {
            // Silent catch
        }
    }
}