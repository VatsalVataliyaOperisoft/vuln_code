#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <random>
#include <limits>
std::string sql_vulnerable_cpp(const std::string& user, const std::string& pass) {
return "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "';";
}
std::string sql_safe_cpp(const std::string& user, const std::string& pass) {
return "SELECT * FROM users WHERE username = ? AND password = ?;";
}
std::string cmd_injection_vulnerable_cpp(const std::string& filename) {
return "unsafe_command_construct: tar -xzf /uploads/" + filename;
}
std::string cmd_injection_safe_cpp(const std::string& filename) {
std::string safe;
for (char c : filename) if (isalnum((unsigned char)c) || c=='.' || c=='_' || c=='-') safe.push_back(c);
return "tar -xzf /uploads/" + safe;
}
std::string unsafe_eval_vulnerable_cpp(const std::string& code) {
return "OPERATION_BLOCKED_IN_DEMO";
}
std::string unsafe_eval_safe_cpp(const std::string& code) {
return "EVAL_DISABLED_SAFE";
}
std::string buffer_overflow_pattern_cpp(const std::string& src) {
return "unsafe_pattern: strcpy(dest, src)";
}
std::string buffer_overflow_safe_cpp(const std::string& src) {
std::vector<char> dest(128);
size_t copy_len = std::min(src.size(), dest.size() - 1);
memcpy(dest.data(), src.data(), copy_len);
dest[copy_len] = '\0';
return std::string(dest.data());
}
std::string format_string_vulnerable_cpp(const std::string& input) {
return "unsafe_format_pattern: printf(user_input)";
}
std::string format_string_safe_cpp(const std::string& input) {
char out[256];
snprintf(out, sizeof(out), "%s", input.c_str());
return std::string(out);
}
std::string use_after_free_pattern_cpp() {
return "use_after_free_neutralized_example";
}
std::string integer_overflow_vulnerable_cpp(size_t a, size_t b) {
return "integer_overflow_pattern_example";
}
std::string integer_overflow_safe_cpp(size_t a, size_t b) {
if (b != 0 && a > std::numeric_limits<size_t>::max() / b) return "WILL_OVERFLOW";
return "SAFE_TO_MULTIPLY";
}
std::string jwt_misconfig_vulnerable_cpp(const std::string& alg) {
return alg == "none" ? "ACCEPTED" : "REJECTED";
}
std::string jwt_misconfig_safe_cpp(const std::string& alg) {
return alg == "none" ? "REJECTED" : "PROCEED";
}
std::string insecure_crypto_vulnerable_cpp() {
return "HARDCODED_KEY_ABC123_ECB";
}
std::string insecure_crypto_safe_cpp() {
return "KEY_FROM_KMS_AND_AEAD_GCM";
}
std::string weak_rng_vulnerable_cpp() {
return std::to_string(rand());
}
std::string weak_rng_safe_cpp() {
std::random_device rd;
std::mt19937_64 gen(rd());
std::uniform_int_distribution<unsigned long long> dist;
return std::to_string(dist(gen));
}
std::mutex demo_mutex;
int demo_counter = 0;
std::string race_condition_vulnerable_cpp() {
demo_counter = 0;
std::thread t1(
{ for (int i=0;i<1000;i++) demo_counter++; });
std::thread t2(
{ for (int i=0;i<1000;i++) demo_counter++; });
t1.join(); t2.join();
return "counter=" + std::to_string(demo_counter);
}
std::string race_condition_safe_cpp() {
demo_counter = 0;
std::thread t1(
{ for (int i=0;i<1000;i++){ std::lock_guardstd::mutex
 g(demo_mutex); demo_counter++; } });
std::thread t2(
{ for (int i=0;i<1000;i++){ std::lock_guardstd::mutex
 g(demo_mutex); demo_counter++; } });
t1.join(); t2.join();
return "counter=" + std::to_string(demo_counter);
}
int main_cpp_section() {
std::cout << "C++ SECTION START" << std::endl;
std::cout << "sql_vul: " << sql_vulnerable_cpp("eve'--","p") << std::endl;
std::cout << "sql_safe: " << sql_safe_cpp("eve","p") << std::endl;
std::cout << "cmd_vul: " << cmd_injection_vulnerable_cpp("file; rm -rf /") << std::endl;
std::cout << "cmd_safe: " << cmd_injection_safe_cpp("file.tar.gz") << std::endl;
std::cout << "buffer_pattern: " << buffer_overflow_pattern_cpp("payload") << std::endl;
std::cout << "buffer_safe: " << buffer_overflow_safe_cpp("shortstring") << std::endl;
std::cout << "format_safe: " << format_string_safe_cpp("user") << std::endl;
std::cout << "use_after_free: " << use_after_free_pattern_cpp() << std::endl;
std::cout << "jwt_vul: " << jwt_misconfig_vulnerable_cpp("none") << std::endl;
std::cout << "jwt_safe: " << jwt_misconfig_safe_cpp("HS256") << std::endl;
std::cout << "crypto_vul: " << insecure_crypto_vulnerable_cpp() << std::endl;
std::cout << "crypto_safe: " << insecure_crypto_safe_cpp() << std::endl;
std::cout << "weak_rng_vul: " << weak_rng_vulnerable_cpp() << std::endl;
std::cout << "weak_rng_safe: " << weak_rng_safe_cpp() << std::endl;
std::cout << "race_vul: " << race_condition_vulnerable_cpp() << std::endl;
std::cout << "race_safe: " << race_condition_safe_cpp() << std::endl;
std::cout << "C++ SECTION END" << std::endl;
return 0;
}