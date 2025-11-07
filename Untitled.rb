puts "RUBY SECTION START"
require 'securerandom'
require 'openssl'
def sql_vulnerable(user, pass)
q = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "';"
return q
end
def sql_safe(user, pass)
q = "SELECT * FROM users WHERE username = ? AND password = ?;"
return { sql: q, params: [user, pass] }
end
def cmd_injection_vulnerable(filename)
return "unsafe_constructed_command: tar -xzf /uploads/" + filename
end
def cmd_injection_safe(filename)
safe = filename.gsub(/[^A-Za-z0-9.-]/, '')
return ["tar", "-xzf", "/uploads/" + safe].join(" ")
end
def unsafe_eval_vulnerable(code)
return "OPERATION_BLOCKED_IN_DEMO"
end
def unsafe_eval_safe(code)
return "EVAL_DISABLED_SAFE"
end
def deserialize_vulnerable(serialized)
return "DESERIALIZE_BLOCKED_IN_DEMO"
end
def deserialize_safe(serialized)
return "DESERIALIZATION_DISABLED"
end
def xss_reflected_vulnerable(input)
return "<div>User: " + input + "</div>"
end
def xss_reflected_safe(input)
esc = input.gsub(/[&<>"']/, '&' => '&', '<' => '<', '>' => '>', '"' => '"', "'" => ''')
return "<div>User: " + esc + "</div>"
end
def csrf_vulnerable()
return "NO_CSRF_TOKEN_CHECK"
end
def csrf_safe(token, stored)
return token == stored ? "CSRF_OK" : "CSRF_BLOCKED"
end
def idor_vulnerable(requester, owner)
return "RESOURCE_FOR:" + owner
end
def idor_safe(requester, owner)
return requester == owner ? "RESOURCE_OK" : "403_FORBIDDEN"
end
def auth_broken_vulnerable(user, pass)
return user == "admin" && pass == "DEFAULT_PASS" ? "AUTH_OK" : "AUTH_FAIL"
end
def auth_broken_safe(user, pass)
return "AUTH_VIA_SECURE_BACKEND"
end
def hardcoded_secret_vulnerable()
return "API_KEY_PLACEHOLDER"
end
def hardcoded_secret_safe()
return ENV['APP_SECRET'] || "NO_SECRET_CONFIGURED"
end
def path_traversal_vulnerable(name)
return "/srv/uploads/" + name
end
def path_traversal_safe(name)
safe = name.gsub(/[^A-Za-z0-9.-]/, '')
return "/srv/uploads/" + safe
end
def cors_vulnerable()
return { "Access-Control-Allow-Origin" => "*" }
end
def cors_safe(origin)
allowed = ["https://example.com
"]
return { "Access-Control-Allow-Origin" => allowed.include?(origin) ? origin : "null" }
end
def open_redirect_vulnerable(target)
return "redirect:" + target
end
def open_redirect_safe(target)
return target.start_with?("/") && !target.start_with?("//") ? "redirect:" + target : "redirect:/"
end
def ssrf_vulnerable(target)
return "SSRF_WOULD_FETCH_BLOCKED:" + target
end
def ssrf_safe(target)
uri = URI.parse(target) rescue nil
host = uri ? uri.host : ""
return (host == "127.0.0.1" || host == "localhost") ? "BLOCKED_INTERNAL" : "ALLOWED"
end
def xxe_vulnerable(xml)
return "XXE_PARSE_BLOCKED"
end
def xxe_safe(xml)
return "XXE_PARSER_CONFIGURED_SAFE"
end
def supply_chain_vulnerable(name)
return "dynamic_require:" + name
end
def supply_chain_safe(name)
return "use_pinned_dependency:" + name + "@1.2.3"
end
def insecure_crypto_vulnerable()
return { key: "HARDCODED_KEY_ABC123", mode: "ECB" }
end
def insecure_crypto_safe()
return { key_source: "KMS_OR_ENV_VAR", mode: "AEAD_GCM" }
end
def weak_rng_vulnerable()
return rand()
end
def weak_rng_safe()
return SecureRandom.random_number
end
def tls_skip_vulnerable()
return OpenSSL::SSL::VERIFY_NONE
end
def tls_skip_safe()
return OpenSSL::SSL::VERIFY_PEER
end
def verbose_error_vulnerable()
begin
raise "detailed internal error: DB_CONN_FAIL"
rescue => e
return e.to_s
end
end
def verbose_error_safe()
begin
raise "internal"
rescue => e
return "internal error"
end
end
def race_condition_vulnerable()
counter = 0
threads = []
2.times do
threads << Thread.new { 1000.times { counter = counter + 1 } }
end
threads.each(&:join)
return "counter=" + counter.to_s
end
def race_condition_safe()
counter = 0
mutex = Mutex.new
threads = []
2.times do
threads << Thread.new { 1000.times { mutex.synchronize { counter = counter + 1 } } }
end
threads.each(&:join)
return "counter=" + counter.to_s
end
def jwt_misconfig_vulnerable(header_alg)
return header_alg == "none" ? "ACCEPTED" : "REJECTED"
end
def jwt_misconfig_safe(header_alg)
return header_alg == "none" ? "REJECTED" : "PROCEED"
end
def ruby_run_demo()
puts "ruby sql_vulnerable: " + sql_vulnerable("alice'--", "p")
puts "ruby sql_safe: " + sql_safe("alice", "p")[:sql]
puts "ruby cmd_vulnerable: " + cmd_injection_vulnerable("data.tar.gz; rm -rf /")
puts "ruby cmd_safe: " + cmd_injection_safe("data.tar.gz")
puts "ruby xss_vulnerable: " + xss_reflected_vulnerable("<script>")
puts "ruby xss_safe: " + xss_reflected_safe("<script>")
puts "ruby csrf_vulnerable: " + csrf_vulnerable()
puts "ruby csrf_safe: " + csrf_safe("tk","tk")
puts "ruby idor_vulnerable: " + idor_vulnerable("attacker","victim")
puts "ruby idor_safe: " + idor_safe("attacker","victim")
puts "ruby jwt_vul: " + jwt_misconfig_vulnerable("none")
puts "ruby jwt_safe: " + jwt_misconfig_safe("HS256")
end
ruby_run_demo()
puts "RUBY SECTION END"