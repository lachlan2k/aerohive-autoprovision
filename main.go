package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type ConfigValues struct {
	Ssid          string
	Psk           string
	HivePsk       string
	HostName      string
	AdminPassword string
	TargetIP      string
	ConfigID      string
}

var possiblePasswords []string

func promptPassword(prompt string) (password string) {
	fmt.Print(prompt)
	bytePassword, _ := term.ReadPassword(int(syscall.Stdin))
	password = string(bytePassword)
	possiblePasswords = append(possiblePasswords, password)
	println("")
	return
}

func createConnection(host string, password string) (client *ssh.Client, err error) {
	sshConfig := &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshConfig.SetDefaults()

	client, err = ssh.Dial("tcp", host+":22", sshConfig)
	return
}

func createConnectionInteractive(host string) (client *ssh.Client, err error) {
	for _, password := range possiblePasswords {
		client, err = createConnection(host, password)

		if client != nil && err == nil {
			return
		}
	}

	for client == nil || err != nil {
		password := promptPassword("[-] Password for admin@" + host + ": ")
		client, err = createConnection(host, password)
	}

	return
}

func openShell(client *ssh.Client) (r io.Reader, w io.Writer, err error) {
	sess, err := client.NewSession()

	if err != nil {
		return
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	err = sess.RequestPty("xterm", 40, 40, modes)

	if err != nil {
		return
	}

	w, err = sess.StdinPipe()
	r, err = sess.StdoutPipe()

	if err != nil {
		return
	}

	err = sess.Shell()

	return
}

var baseURL string

func chooseWebserverURL() (err error) {
	// Get local IP address of system
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		return
	}

	reader := bufio.NewReader(os.Stdin)

	localIP := ""

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip := ipnet.IP.String()
				fmt.Printf("[+] Would you like to use %s to host the server? (y/N) ", ip)
				response, _ := reader.ReadString('\n')
				response = strings.TrimSpace(response)

				if response == "y" || response == "Y" {
					localIP = ip
					break
				}
			}
		}
	}

	if localIP == "" {
		return fmt.Errorf("No local IP address found/chosen")
	}

	fmt.Printf("[+] Enter port to host server from (default 8080): ")

	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)

	if port == "" {
		port = "8080"
	}

	baseURL = "http://" + localIP + ":" + port

	fmt.Println("[*] Using base url", baseURL, "to host config")

	return nil
}

func provisionAp(config ConfigValues) (err error) {
	fmt.Println("[*] Connecting to...", config.TargetIP)

	client, err := createConnectionInteractive(config.TargetIP)
	fmt.Printf("[+] Connection to %s established!\n", config.TargetIP)

	_, w, err := openShell(client)

	if err != nil {
		return
	}

	fmt.Println("[*] Setting admin password...")
	fmt.Fprintln(w, "admin root-admin admin password \""+config.AdminPassword+"\"")
	time.Sleep(1 * time.Second)

	fmt.Println("[*] Clearing existing bootstrap config...")
	fmt.Fprintln(w, "reset config bootstrap")
	time.Sleep(1 * time.Second)
	fmt.Fprintln(w, "Y")
	time.Sleep(1 * time.Second)

	serveURL := baseURL + "/config/" + config.ConfigID

	fmt.Println("[*] Sending config to AP...", serveURL)
	fmt.Fprintln(w, "save config "+serveURL+" bootstrap")
	time.Sleep(1 * time.Second)
	fmt.Fprintln(w, "Y")
	time.Sleep(10 * time.Second)

	fmt.Println("[*] Resetting AP config (will reboot)")
	fmt.Fprintln(w, "reset config")
	time.Sleep(1 * time.Second)
	fmt.Fprintln(w, "Y")
	time.Sleep(1 * time.Second)

	return
}

// Defined by aerohive
func checkPasswordRequirements(password string) string {
	if len(password) < 8 || len(password) > 32 {
		return "Password must be between 8 and 32 characters"
	}

	hasNumber, _ := regexp.MatchString("[0-9]", password)

	if !hasNumber {
		return "Password must contain a number"
	}

	hasUppercase, _ := regexp.MatchString("[A-Z]", password)

	if !hasUppercase {
		return "Password must have an uppercase character"
	}

	return ""
}

func generateConfigInteractive() (config ConfigValues) {
	reader := bufio.NewReader(os.Stdin)

	for {
		password := promptPassword("[*] New admin password: ")
		feedback := checkPasswordRequirements(password)

		if feedback == "" {
			config.AdminPassword = password
			break
		} else {
			fmt.Println("[!]", feedback)
		}
	}

	fmt.Print("[*] WiFi SSID: ")

	config.HostName = "AP"

	config.Ssid, _ = reader.ReadString('\n')
	config.Ssid = strings.TrimRight(config.Ssid, "\n")

	config.Psk = promptPassword("[*] Pre-shared key for " + config.Ssid + ": ")
	config.HivePsk = promptPassword("[*] Pre-shared key for Hive (leave blank to randomly generate): ")

	if config.HivePsk == "" {
		bytes := make([]byte, 32)
		rand.Read(bytes)
		config.HivePsk = hex.EncodeToString(bytes)
	}

	return
}

var ConfigMap map[string]ConfigValues = make(map[string]ConfigValues)

func startHttpServer(template *template.Template) {
	listen := strings.Split(baseURL, "http://")[1]

	http.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/config/")

		fmt.Printf("[*] Incoming config request from %s for %s\n", r.RemoteAddr, id)

		// Get the config from the map, if it exists. Then, render the template, remove all blank lines, and return it
		config, ok := ConfigMap[id]

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		tpl, _ := template.Clone()

		var configBytes bytes.Buffer

		if err := tpl.Execute(&configBytes, config); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		re := regexp.MustCompile("\n\n+")
		cleanedConfig := re.ReplaceAllString(configBytes.String(), "\n")

		w.Write([]byte(cleanedConfig))
	})

	http.ListenAndServe(listen, nil)
}

func main() {
	possiblePasswords = []string{"aerohive", "Aerohive1", "admin"}

	fmt.Println("====================")
	fmt.Println("Aerohive Provisioner")
	fmt.Println("")

	fmt.Println("[*] Loading config from ./config.template")

	template, err := template.ParseFiles("./config.template")

	if err != nil {
		log.Fatal(err)
	}

	// Load all AP targets from targets.csv
	fmt.Println("[*] Loading targets from ./targets.csv")

	file, err := os.Open("./targets.csv")

	if err != nil {
		log.Fatal("Couldn't open targets.csv:", err)
	}

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = 2
	targets, err := reader.ReadAll()

	if err != nil {
		log.Fatal("Couldn't read targets.csv as a csv:", err)
	}

	fmt.Println("\n[*] Configuring config webserver")
	err = chooseWebserverURL()

	if err != nil {
		log.Fatal(err)
	}

	go startHttpServer(template)

	fmt.Println("\nEntering configuration...")

	baseConfig := generateConfigInteractive()

	fmt.Println("[*] Starting provisioning")

	for _, target := range targets {
		config := baseConfig

		config.TargetIP = target[0]
		config.HostName = target[1]

		bytes := make([]byte, 16)
		rand.Read(bytes)
		id := hex.EncodeToString(bytes)

		config.ConfigID = id
		ConfigMap[id] = config

		fmt.Println("[*] Provisioning", config.HostName)

		err = provisionAp(ConfigMap[id])

		if err != nil {
			fmt.Println("[!] Error while provisioning:", err)
			continue
		}

		fmt.Printf("[+] Successfully provisioned %s (%s)\n", config.HostName, config.TargetIP)
		fmt.Println("-")
	}

	fmt.Println("[-] Leaving the webserver open just in case...")

	time.Sleep(time.Second * 10)

	fmt.Println("[*] Done!")
}
