#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>
const char* sql_vulnerable(const char* user, const char* pass) {
static char buf[512];
snprintf(buf, sizeof(buf), "SELECT * FROM users WHERE username = '%s' AND password = '%s';", user, pass);
return buf;
}
const char* sql_safe(const char* user, const char* pass) {
return "SELECT * FROM users WHERE username = ? AND password = ?;";
}
const char* cmd_injection_vulnerable(const char* filename) {
static char cmd[256];
snprintf(cmd, sizeof(cmd), "tar -xzf /uploads/%s", filename);
return cmd;
}
const char* cmd_injection_safe(const char* filename) {
static char safecmd[256];
char safe[128] = {0};
size_t j = 0;
for (size_t i = 0; i < strlen(filename) && j + 1 < sizeof(safe); ++i) {
char c = filename[i];
if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
safe[j++] = c;
}
safe[j] = '\0';
snprintf(safecmd, sizeof(safecmd), "tar -xzf /uploads/%s", safe);
return safecmd;
}
const char* unsafe_eval_vulnerable(const char* code) {
return "OPERATION_BLOCKED_IN_DEMO";
}
const char* unsafe_eval_safe(const char* code) {
return "EVAL_DISABLED_SAFE";
}
const char* buffer_overflow_pattern_vulnerable(const char* src) {
return "unsafe_call_example: strcpy(dest, src)";
}
const char* buffer_overflow_pattern_safe(const char* src) {
static char dest[128];
strncpy(dest, src, sizeof(dest) - 1);
dest[127] = '\0';
return dest;
}
const char* format_string_vulnerable(const char* user_input) {
return "unsafe_format_example: printf(user_input)";
}
const char* format_string_safe(const char* user_input) {
static char out[256];
snprintf(out, sizeof(out), "%s", user_input);
return out;
}
const char* use_after_free_vulnerable() {
return "use_after_free_pattern_example (neutralized)";
}
const char* integer_overflow_vulnerable(size_t a, size_t b) {
return "integer_multiply_unsafe: size_t a * b unchecked";
}
const char* integer_overflow_safe(size_t a, size_t b) {
if (b != 0 && a > SIZE_MAX / b) return "MULTIPLY_WOULD_OVERFLOW";
return "SAFE_MULTIPLY_ALLOWED";
}
const char* ssrf_vulnerable(const char* target) {
return "SSRF_WOULD_FETCH_BLOCKED";
}
const char* ssrf_safe(const char* target) {
return "SSRF_CHECKED_AND_BLOCKED_IF_INTERNAL";
}
const char* tls_skip_vulnerable() {
return "TLS_INSECURE_SKIP_VERIFY_USED";
}
const char* tls_skip_safe() {
return "TLS_VERIFY_PEER_USED";
}
const char* hardcoded_secret_vulnerable() {
return "API_KEY_PLACEHOLDER";
}
const char* hardcoded_secret_safe() {
return "SECRET_FROM_ENV_OR_VAULT";
}
volatile int race_counter;
void* race_worker_vulnerable(void* arg) {
for (int i = 0; i < 1000; ++i) race_counter++;
return NULL;
}
const char* race_condition_vulnerable_demo() {
race_counter = 0;
pthread_t t1, t2;
pthread_create(&t1, NULL, race_worker_vulnerable, NULL);
pthread_create(&t2, NULL, race_worker_vulnerable, NULL);
pthread_join(t1, NULL);
pthread_join(t2, NULL);
static char out[64];
snprintf(out, sizeof(out), "race_counter=%d", race_counter);
return out;
}
pthread_mutex_t race_mutex = PTHREAD_MUTEX_INITIALIZER;
void* race_worker_safe(void* arg) {
for (int i = 0; i < 1000; ++i) { pthread_mutex_lock(&race_mutex); race_counter++; pthread_mutex_unlock(&race_mutex); }
return NULL;
}
const char* race_condition_safe_demo() {
race_counter = 0;
pthread_t t1, t2;
pthread_create(&t1, NULL, race_worker_safe, NULL);
pthread_create(&t2, NULL, race_worker_safe, NULL);
pthread_join(t1, NULL);
pthread_join(t2, NULL);
static char out[64];
snprintf(out, sizeof(out), "race_counter=%d", race_counter);
return out;
}
int main_c_section() {
printf("C SECTION START\n");
printf("sql_vulnerable: %s\n", sql_vulnerable("bob'--", "p"));
printf("sql_safe: %s\n", sql_safe("bob", "p"));
printf("cmd_vul: %s\n", cmd_injection_vulnerable("data.tar.gz; rm -rf /"));
printf("cmd_safe: %s\n", cmd_injection_safe("data.tar.gz"));
printf("buffer_pattern: %s\n", buffer_overflow_pattern_vulnerable("payload"));
printf("buffer_safe_copy: %s\n", buffer_overflow_pattern_safe("shortstring"));
printf("format_safe: %s\n", format_string_safe("user input %s"));
printf("use_after_free_example: %s\n", use_after_free_vulnerable());
printf("integer_check: %s\n", integer_overflow_safe(1024, 2048));
printf("ssrf: %s\n", ssrf_vulnerable("http://169.254.169.254
"));
printf("tls_vul: %s\n", tls_skip_vulnerable());
printf("hardcoded_secret: %s\n", hardcoded_secret_vulnerable());
printf("race_vul: %s\n", race_condition_vulnerable_demo());
printf("race_safe: %s\n", race_condition_safe_demo());
printf("C SECTION END\n");
return 0;
}