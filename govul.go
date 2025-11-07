// vulnerable_go.go
package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"
)

func main() {
	fmt.Println("FOR DEFENSIVE/EDUCATIONAL PURPOSES ONLY — RUN IN LAB/VM")
	fmt.Println(sqlVulnerable("u','--","p"))
	fmt.Println(sqlSafe("u","p"))
	fmt.Println(cmdVulnerable("file; rm -rf /"))
	fmt.Println(cmdSafe("file"))
	fmt.Println(ssrfVulnerable("http://127.0.0.1"))
	fmt.Println(ssrfSafe("http://127.0.0.1"))
	fmt.Println(tlsVulnerable())
	fmt.Println(tlsSafe())
	fmt.Println(randVulnerable())
	fmt.Println(randSafe())
	fmt.Println(raceConditionDemo())
	fmt.Println(dirTraversalVulnerable("../etc/passwd"))
	fmt.Println(dirTraversalSafe("safe.txt"))
	fmt.Println(defaultCredsVulnerable())
	fmt.Println(defaultCredsSafe("admin","S3CR3T"))
}

func sqlVulnerable(u, p string) string {
	return "SELECT * FROM users WHERE u='" + u + "' AND p='" + p + "';"
}

func sqlSafe(u, p string) string {
	return "SELECT * FROM users WHERE u=? AND p=?; params=[" + u + "," + p + "]"
}

func cmdVulnerable(arg string) string {
	return "tar -xzf /uploads/" + arg
}

func cmdSafe(arg string) string {
	allowed := ""
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			allowed += string(c)
		}
	}
	return "tar -xzf /uploads/" + allowed
}

func ssrfVulnerable(target string) string {
	return "WILL_FETCH:" + target
}

func ssrfSafe(target string) string {
	u, err := url.Parse(target)
	if err != nil { return "invalid" }
	host := u.Hostname()
	if host == "127.0.0.1" || host == "localhost" { return "blocked-internal" }
	return "ok:" + u.String()
}

func tlsVulnerable() string {
	_ = &tls.Config{InsecureSkipVerify: true}
	return "TLS_SKIP_VERIFY_ON"
}

func tlsSafe() string {
	_ = &tls.Config{InsecureSkipVerify: false}
	return "TLS_VERIFY_ON"
}

func randVulnerable() int {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return int(b[0])
}

func randSafe() int {
	var b [4]byte
	_, _ = rand.Read(b[:])
	val := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if val < 0 { val = -val }
	return val
}

var raceCounter int
func raceConditionDemo() string {
	raceCounter = 0
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < 1000; j++ { raceCounter = raceCounter + 1 }
			wg.Done()
		}()
	}
	wg.Wait()
	safe := raceCounter
	raceCounter = 0
	var mu sync.Mutex
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			for j := 0; j < 1000; j++ { mu.Lock(); raceCounter = raceCounter + 1; mu.Unlock() }
			wg.Done()
		}()
	}
	wg.Wait()
	return fmt.Sprintf("vulnerable_count=%d safe_count=%d", safe, raceCounter)
}

func dirTraversalVulnerable(p string) string {
	return "READ_FILE:" + p
}

func dirTraversalSafe(p string) string {
	if p == "" || p == ".." || p == "../" { return "invalid" }
	return "READ_FILE_SAFE:" + p
}

func defaultCredsVulnerable() string {
	return "admin:DEFAULT_PASS"
}

func defaultCredsSafe(u, provided string) string {
	if u == "admin" && provided == "S3CR3T" { return "auth_ok" }
	return "auth_fail"
}
