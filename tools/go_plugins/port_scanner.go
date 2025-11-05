// @name port_scanner
// @description Fast TCP port scanner in Go
// @category recon
// @version 1.0.0

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Args representa os argumentos do plugin
type Args struct {
	Target  string `json:"target"`
	Ports   string `json:"ports"`
	Timeout int    `json:"timeout"`
	Threads int    `json:"threads"`
	Verbose bool   `json:"verbose"`
}

// Result representa o resultado do scan
type Result struct {
	Success bool        `json:"success"`
	Target  string      `json:"target"`
	Ports   []PortInfo  `json:"ports"`
	Total   int         `json:"total"`
	Open    int         `json:"open"`
	Closed  int         `json:"closed"`
	Elapsed float64     `json:"elapsed"`
}

// PortInfo informações de uma porta
type PortInfo struct {
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service"`
}

// PluginInfo informações do plugin
type PluginInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Version     string `json:"version"`
}

// Common services mapping
var commonServices = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	143:  "imap",
	443:  "https",
	445:  "smb",
	3306: "mysql",
	3389: "rdp",
	5432: "postgresql",
	6379: "redis",
	8080: "http-proxy",
	8443: "https-alt",
	27017: "mongodb",
}

func main() {
	// Se --info, retorna metadados
	if len(os.Args) > 1 && os.Args[1] == "--info" {
		info := PluginInfo{
			Name:        "port_scanner",
			Description: "Fast TCP port scanner in Go",
			Category:    "recon",
			Version:     "1.0.0",
		}
		json.NewEncoder(os.Stdout).Encode(info)
		return
	}

	// Parse argumentos
	var args Args
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: No arguments provided")
		os.Exit(1)
	}

	err := json.Unmarshal([]byte(os.Args[1]), &args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments: %v\n", err)
		os.Exit(1)
	}

	// Defaults
	if args.Timeout == 0 {
		args.Timeout = 2
	}
	if args.Threads == 0 {
		args.Threads = 100
	}
	if args.Ports == "" {
		args.Ports = "common" // Portas comuns
	}

	// Executa scan
	result := scanPorts(args)

	// Output JSON
	json.NewEncoder(os.Stdout).Encode(result)
}

func scanPorts(args Args) Result {
	startTime := time.Now()

	// Determina portas a scanear
	var ports []int
	if args.Ports == "common" {
		// Top 100 portas comuns
		ports = []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
			143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
		}
	} else if args.Ports == "all" {
		// Todas as portas 1-65535
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
	} else {
		// Parse custom range
		// Simplificado: assume single port por agora
		var port int
		fmt.Sscanf(args.Ports, "%d", &port)
		if port > 0 && port <= 65535 {
			ports = []int{port}
		} else {
			ports = []int{80, 443}
		}
	}

	result := Result{
		Success: true,
		Target:  args.Target,
		Ports:   []PortInfo{},
		Total:   len(ports),
	}

	// Scan paralelo
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, args.Threads)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := scanPort(args.Target, p, args.Timeout)

			if args.Verbose {
				fmt.Fprintf(os.Stderr, "Scanning port %d: %s\n", p, info.State)
			}

			mu.Lock()
			if info.State == "open" {
				result.Ports = append(result.Ports, info)
				result.Open++
			} else {
				result.Closed++
			}
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	result.Elapsed = time.Since(startTime).Seconds()

	return result
}

func scanPort(host string, port int, timeout int) PortInfo {
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Second)

	info := PortInfo{
		Port:    port,
		State:   "closed",
		Service: getServiceName(port),
	}

	if err == nil {
		info.State = "open"
		conn.Close()
	}

	return info
}

func getServiceName(port int) string {
	if service, ok := commonServices[port]; ok {
		return service
	}
	return "unknown"
}
