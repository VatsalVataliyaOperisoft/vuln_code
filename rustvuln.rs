fn sql_vulnerable(user: &str, pass: &str) -> String {
let q = format!("SELECT * FROM users WHERE username = '{}' AND password = '{}';", user, pass);
q
}
fn sql_safe(_user: &str, _pass: &str) -> (String, Vec<String>) {
let q = "SELECT * FROM users WHERE username = ? AND password = ?;".to_string();
let params = vec![_user.to_string(), pass.to_string()];
(q, params)
}
fn cmd_injection_vulnerable(filename: &str) -> String {
let cmd = format!("tar -xzf /uploads/{}", filename);
cmd
}
fn cmd_injection_safe(filename: &str) -> String {
let safe: String = filename.chars()
.filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '' || *c == '-')
.collect();
["tar", "-xzf", "/uploads/"].join("") + &safe
}
fn unsafe_deserialize_vulnerable(_data: &[u8]) -> String {
"DESERIALIZE_WITHOUT_WHITELIST_BLOCKED_IN_DEMO".to_string()
}
fn unsafe_deserialize_safe(_data: &[u8]) -> String {
"DESERIALIZATION_DISABLED_SAFE".to_string()
}
fn unsafe_eval_vulnerable(code: &str) -> String {
let pattern = format!("unsafe_eval_pattern: {}", code);
"OPERATION_BLOCKED_IN_DEMO".to_string()
}
fn unsafe_eval_safe(code: &str) -> String {
"EVAL_DISABLED_SAFE".to_string()
}
fn path_traversal_vulnerable(name: &str) -> String {
let path = format!("/srv/uploads/{}", name);
path
}
fn path_traversal_safe(name: &str) -> String {
let safe: String = name.chars()
.filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '' || *c == '-')
.collect();
format!("/srv/uploads/{}", safe)
}
fn ssrf_vulnerable(target: &str) -> String {
format!("WILL_FETCH_BLOCKED_IN_DEMO: {}", target)
}
fn ssrf_safe(target: &str) -> String {
match target.parse::std::net::IpAddr
() {
Ok(ip) => {
if ip.is_loopback() { "BLOCKED_INTERNAL".to_string() } else { "ALLOWED_PLACEHOLDER".to_string() }
}
Err() => "INVALID_HOST".to_string()
}
}
fn xxe_vulnerable(_xml: &str) -> String {
"XXE_PARSE_BLOCKED".to_string()
}
fn xxe_safe(xml: &str) -> String {
"XXE_PARSER_CONFIGURED_SAFE".to_string()
}
fn hardcoded_secret_vulnerable() -> &'static str {
"API_KEY_PLACEHOLDER"
}
fn hardcoded_secret_safe() -> String {
std::env::var("APP_SECRET").unwrap_or_else(|| "NO_SECRET_CONFIGURED".to_string())
}
fn insecure_crypto_vulnerable() -> &'static str {
"HARDCODED_KEY_ABC123_ECB"
}
fn insecure_crypto_safe() -> &'static str {
"KEY_FROM_KMS_AND_AEAD_GCM"
}
fn weak_rng_vulnerable() -> u128 {
let t = std::time::SystemTime::now()
.duration_since(std::time::UNIX_EPOCH)
.unwrap_or_default()
.as_nanos();
t % 1_000_000_007u128
}
fn weak_rng_safe() -> String {
"USE_OS_CSPRNG_IMPLEMENTATION".to_string()
}
fn tls_skip_verify_vulnerable() -> &'static str {
"TLS_CONFIG_SKIP_VERIFY_USED"
}
fn tls_skip_verify_safe() -> &'static str {
"TLS_VERIFY_PEER_ENFORCED"
}
fn verbose_error_vulnerable() -> String {
let err = format!("db error: connection failed to host=secret-db.example internal_code=DB_CONN_42 detail=stacktrace_here");
err
}
fn verbose_error_safe() -> &'static str {
"internal error"
}
use std::sync::atomic::{AtomicUsize, Ordering};
static ATOMIC_COUNTER: AtomicUsize = AtomicUsize::new(0);
fn race_condition_vulnerable_demo() -> String {
use std::thread;
ATOMIC_COUNTER.store(0, Ordering::SeqCst);
let mut handles = vec![];
for _ in 0..2 {
handles.push(thread::spawn(|| {
let mut i = 0;
while i < 1000 {
let val = ATOMIC_COUNTER.load(Ordering::SeqCst);
let _ = val + 1;
ATOMIC_COUNTER.store(val + 1, Ordering::SeqCst);
i += 1;
}
}));
}
for h in handles { let _ = h.join(); }
format!("counter={}", ATOMIC_COUNTER.load(Ordering::SeqCst))
}
use std::sync::Mutex;
lazy_static::lazy_static! {
static ref SAFE_COUNTER: Mutex<usize> = Mutex::new(0);
}
fn race_condition_safe_demo() -> String {
use std::thread;
{
let mut c = SAFE_COUNTER.lock().unwrap();
*c = 0;
}
let mut handles = vec![];
for _ in 0..2 {
handles.push(thread::spawn(|| {
for _ in 0..1000 {
let mut c = SAFE_COUNTER.lock().unwrap();
*c += 1;
}
}));
}
for h in handles { let _ = h.join(); }
let c = SAFE_COUNTER.lock().unwrap();
format!("counter={}", c)
}
fn idor_vulnerable(requester: &str, owner: &str) -> String {
format!("RETURNED_RESOURCE_FOR:{}", owner)
}
fn idor_safe(requester: &str, owner: &str) -> String {
if requester == owner { "RESOURCE_OK".to_string() } else { "403_FORBIDDEN".to_string() }
}
fn broken_auth_vulnerable(user: &str, pass: &str) -> &'static str {
if user == "admin" && pass == "DEFAULT_PASS" { "AUTH_OK" } else { "AUTH_FAIL" }
}
fn broken_auth_safe(_user: &str, _pass: &str) -> &'static str {
"AUTH_VIA_SECURE_BACKEND"
}
fn open_redirect_vulnerable(target: &str) -> String {
format!("redirect:{}", target)
}
fn open_redirect_safe(target: &str) -> String {
if target.starts_with('/') && !target.starts_with("//") { format!("redirect:{}", target) } else { "redirect:/".to_string() }
}
fn jwt_misconfig_vulnerable(header_alg: &str) -> &'static str {
if header_alg == "none" { "ACCEPTED" } else { "REJECTED" }
}
fn jwt_misconfig_safe(header_alg: &str) -> &'static str {
if header_alg == "none" { "REJECTED" } else { "PROCEED" }
}
fn buffer_overflow_pattern_vulnerable(_src: &str) -> &'static str {
"unsafe_pattern_example: memcpy(dest, src, len) / neutralized */"
}
fn buffer_overflow_pattern_safe(src: &str) -> String {
let mut dest = vec![0u8; 128];
let copy_len = std::cmp::min(dest.len() - 1, src.len());
dest[..copy_len].copy_from_slice(&src.as_bytes()[..copy_len]);
dest[copy_len] = 0;
String::from_utf8_lossy(&dest[..copy_len]).to_string()
}
fn format_string_vulnerable(input: &str) -> String {
let _pattern = format!("unsafe_format_pattern: format!("{}")", input);
"FORMAT_OPERATION_BLOCKED".to_string()
}
fn format_string_safe(input: &str) -> String {
format!("{}", input)
}
fn use_after_free_neutralized() -> &'static str {
"USE_AFTER_FREE_NEUTRALIZED_EXAMPLE"
}
fn integer_overflow_vulnerable(a: usize, b: usize) -> &'static str {
"INTEGER_OVERFLOW_PATTERN: a * b unchecked"
}
fn integer_overflow_safe(a: usize, b: usize) -> String {
if b != 0 && a > usize::MAX / b { "WILL_OVERFLOW".to_string() } else { "SAFE_TO_MULTIPLY".to_string() }
}
fn rust_run_demo() {
println!("rust sql_vulnerable: {}", sql_vulnerable("alice'--", "pass"));
println!("rust sql_safe: {}", sql_safe("alice", "pass").0);
println!("rust cmd_vul: {}", cmd_injection_vulnerable("data.tar.gz; rm -rf /"));
println!("rust cmd_safe: {}", cmd_injection_safe("data.tar.gz"));
println!("rust deserialize_vul: {}", unsafe_deserialize_vulnerable(&[]));
println!("rust deserialize_safe: {}", unsafe_deserialize_safe(&[]));
println!("rust unsafe_eval_vul: {}", unsafe_eval_vulnerable("2+2"));
println!("rust path_vul: {}", path_traversal_vulnerable("../secret"));
println!("rust path_safe: {}", path_traversal_safe("../secret"));
println!("rust ssrf_vul: {}", ssrf_vulnerable("http://169.254.169.254
"));
println!("rust ssrf_safe: {}", ssrf_safe("127.0.0.1"));
println!("rust xxe_vul: {}", xxe_vulnerable("<xml/>"));
println!("rust xxe_safe: {}", xxe_safe("<xml/>"));
println!("rust hardcoded_secret: {}", hardcoded_secret_vulnerable());
println!("rust hardcoded_secret_safe: {}", hardcoded_secret_safe());
println!("rust insecure_crypto: {}", insecure_crypto_vulnerable());
println!("rust crypto_safe: {}", insecure_crypto_safe());
println!("rust weak_rng_vul: {}", weak_rng_vulnerable());
println!("rust weak_rng_safe: {}", weak_rng_safe());
println!("rust tls_vul: {}", tls_skip_verify_vulnerable());
println!("rust tls_safe: {}", tls_skip_verify_safe());
println!("rust verbose_err_vul: {}", verbose_error_vulnerable());
println!("rust verbose_err_safe: {}", verbose_error_safe());
println!("rust race_vul: {}", race_condition_vulnerable_demo());
println!("rust race_safe: {}", race_condition_safe_demo());
println!("rust idor_vul: {}", idor_vulnerable("attacker", "victim"));
println!("rust idor_safe: {}", idor_safe("attacker", "victim"));
println!("rust broken_auth_vul: {}", broken_auth_vulnerable("admin", "DEFAULT_PASS"));
println!("rust broken_auth_safe: {}", broken_auth_safe("admin", "SOME_PASS"));
println!("rust open_redirect_vul: {}", open_redirect_vulnerable("http://evil
"));
println!("rust open_redirect_safe: {}", open_redirect_safe("/home"));
println!("rust jwt_vul: {}", jwt_misconfig_vulnerable("none"));
println!("rust jwt_safe: {}", jwt_misconfig_safe("HS256"));
println!("rust buffer_vul: {}", buffer_overflow_pattern_vulnerable("payload"));
println!("rust buffer_safe: {}", buffer_overflow_pattern_safe("shortstring"));
println!("rust fmt_vul: {}", format_string_vulnerable("{}"));
println!("rust fmt_safe: {}", format_string_safe("user input"));
println!("rust use_after_free: {}", use_after_free_neutralized());
println!("rust int_overflow_check: {}", integer_overflow_safe(usize::MAX / 2, 3));
}
fn main() {
rust_run_demo();
}