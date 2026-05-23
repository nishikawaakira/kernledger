// Command ir-lab-target is a tiny long-lived process used to validate
// host-side collection with kernledger.
//
// It is intentionally boring and observable:
//   - parent process stays resident
//   - optional child processes are spawned so `pstree` has something to show
//   - TCP and UDP listeners stay open for `ss -antp` / `ss -uanp`
//   - a status file and heartbeat log are written under --state-dir
//
// This is for sandbox / self-test use only. It is NOT part of the
// production IR tool path.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type config struct {
	ChildMode  bool
	ChildIndex int
	Name       string
	StateDir   string
	TCPAddr    string
	UDPAddr    string
	Children   int
	Heartbeat  time.Duration
	Runtime    time.Duration
	Quiet      bool
}

type status struct {
	Name       string      `json:"name"`
	Role       string      `json:"role"`
	PID        int         `json:"pid"`
	PPID       int         `json:"ppid"`
	StartedAt  time.Time   `json:"started_at"`
	TCPAddr    string      `json:"tcp_addr,omitempty"`
	UDPAddr    string      `json:"udp_addr,omitempty"`
	Children   []childInfo `json:"children,omitempty"`
	Tag        string      `json:"tag"`
	Heartbeat  string      `json:"heartbeat_interval"`
	Hostname   string      `json:"hostname"`
	Executable string      `json:"executable"`
}

type childInfo struct {
	Index int `json:"index"`
	PID   int `json:"pid"`
}

func main() {
	cfg := parseFlags()
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	if cfg.Quiet {
		logger.SetOutput(os.Stderr)
	}

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		log.Fatalf("mkdir %s: %v", cfg.StateDir, err)
	}

	if cfg.ChildMode {
		if err := runChild(cfg, logger); err != nil {
			log.Fatalf("child: %v", err)
		}
		return
	}
	if err := runParent(cfg, logger); err != nil {
		log.Fatalf("parent: %v", err)
	}
}

func parseFlags() config {
	var cfg config
	flag.BoolVar(&cfg.ChildMode, "child", false, "run in child mode (internal)")
	flag.IntVar(&cfg.ChildIndex, "child-index", 0, "child index (internal)")
	flag.StringVar(&cfg.Name, "name", "ir-lab-target", "label written to logs and status files")
	flag.StringVar(&cfg.StateDir, "state-dir", "/tmp/ir-lab-target", "directory for status and heartbeat files")
	flag.StringVar(&cfg.TCPAddr, "tcp", "0.0.0.0:18080", "TCP listen address for the parent")
	flag.StringVar(&cfg.UDPAddr, "udp", "0.0.0.0:18081", "UDP listen address for the parent")
	flag.IntVar(&cfg.Children, "children", 2, "number of child processes to spawn")
	flag.DurationVar(&cfg.Heartbeat, "heartbeat", 15*time.Second, "heartbeat interval")
	flag.DurationVar(&cfg.Runtime, "runtime", 0, "optional max runtime; 0 means run until signal")
	flag.BoolVar(&cfg.Quiet, "quiet", false, "reduce stdout noise")
	flag.Parse()
	return cfg
}

func runParent(cfg config, logger *log.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if cfg.Runtime > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, cfg.Runtime)
		defer timeoutCancel()
	}

	hostname, _ := os.Hostname()
	exe, _ := os.Executable()
	st := status{
		Name:       cfg.Name,
		Role:       "parent",
		PID:        os.Getpid(),
		PPID:       os.Getppid(),
		StartedAt:  time.Now().UTC(),
		TCPAddr:    cfg.TCPAddr,
		UDPAddr:    cfg.UDPAddr,
		Tag:        os.Getenv("IR_LAB_TAG"),
		Heartbeat:  cfg.Heartbeat.String(),
		Hostname:   hostname,
		Executable: exe,
	}

	children, waitChildren, err := spawnChildren(cfg, logger)
	if err != nil {
		return err
	}
	defer waitChildren()
	st.Children = children
	if err := writeJSON(filepath.Join(cfg.StateDir, "parent-status.json"), st); err != nil {
		return err
	}

	tcpLn, err := net.Listen("tcp", cfg.TCPAddr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", cfg.TCPAddr, err)
	}
	defer tcpLn.Close()

	udpConn, err := net.ListenPacket("udp", cfg.UDPAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", cfg.UDPAddr, err)
	}
	defer udpConn.Close()

	logger.Printf("parent started pid=%d tcp=%s udp=%s children=%d state_dir=%s",
		st.PID, cfg.TCPAddr, cfg.UDPAddr, len(children), cfg.StateDir)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		serveTCP(ctx, tcpLn, cfg, logger)
	}()
	go func() {
		defer wg.Done()
		serveUDP(ctx, udpConn, cfg, logger)
	}()
	go func() {
		defer wg.Done()
		heartbeatLoop(ctx, cfg.StateDir, "parent-heartbeat.log", cfg.Name, "parent", cfg.Heartbeat, logger)
	}()

	<-ctx.Done()
	logger.Printf("parent stopping: %v", ctx.Err())
	_ = tcpLn.Close()
	_ = udpConn.Close()
	wg.Wait()
	return nil
}

func runChild(cfg config, logger *log.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if cfg.Runtime > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, cfg.Runtime)
		defer timeoutCancel()
	}

	hostname, _ := os.Hostname()
	exe, _ := os.Executable()
	st := status{
		Name:       cfg.Name,
		Role:       "child-" + strconv.Itoa(cfg.ChildIndex),
		PID:        os.Getpid(),
		PPID:       os.Getppid(),
		StartedAt:  time.Now().UTC(),
		Tag:        os.Getenv("IR_LAB_TAG"),
		Heartbeat:  cfg.Heartbeat.String(),
		Hostname:   hostname,
		Executable: exe,
	}
	if err := writeJSON(filepath.Join(cfg.StateDir, fmt.Sprintf("child-%d-status.json", cfg.ChildIndex)), st); err != nil {
		return err
	}
	logger.Printf("child started index=%d pid=%d ppid=%d", cfg.ChildIndex, st.PID, st.PPID)
	heartbeatLoop(ctx, cfg.StateDir, fmt.Sprintf("child-%d-heartbeat.log", cfg.ChildIndex), cfg.Name, st.Role, cfg.Heartbeat, logger)
	logger.Printf("child stopped index=%d pid=%d reason=%v", cfg.ChildIndex, st.PID, ctx.Err())
	return nil
}

func spawnChildren(cfg config, logger *log.Logger) ([]childInfo, func(), error) {
	if cfg.Children <= 0 {
		return nil, func() {}, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("os.Executable: %w", err)
	}

	children := make([]*exec.Cmd, 0, cfg.Children)
	infos := make([]childInfo, 0, cfg.Children)
	for i := 0; i < cfg.Children; i++ {
		cmd := exec.Command(
			exe,
			"--child",
			"--child-index", strconv.Itoa(i),
			"--name", cfg.Name,
			"--state-dir", cfg.StateDir,
			"--heartbeat", cfg.Heartbeat.String(),
			"--runtime", "0",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(),
			"IR_LAB_CHILD=1",
			"IR_LAB_CHILD_INDEX="+strconv.Itoa(i),
		)
		if err := cmd.Start(); err != nil {
			for _, started := range children {
				_ = started.Process.Signal(syscall.SIGTERM)
			}
			return nil, nil, fmt.Errorf("start child %d: %w", i, err)
		}
		logger.Printf("spawned child index=%d pid=%d", i, cmd.Process.Pid)
		children = append(children, cmd)
		infos = append(infos, childInfo{Index: i, PID: cmd.Process.Pid})
	}

	cleanup := func() {
		for _, child := range children {
			if child.Process != nil {
				_ = child.Process.Signal(syscall.SIGTERM)
			}
		}
		for _, child := range children {
			_ = child.Wait()
		}
	}
	return infos, cleanup, nil
}

func serveTCP(ctx context.Context, ln net.Listener, cfg config, logger *log.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			logger.Printf("tcp accept error: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			payload := map[string]string{
				"name":      cfg.Name,
				"role":      "parent",
				"pid":       strconv.Itoa(os.Getpid()),
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"message":   "ir-lab-target tcp listener is alive",
			}
			_ = json.NewEncoder(c).Encode(payload)
			logger.Printf("tcp connection from=%s", c.RemoteAddr())
		}(conn)
	}
}

func serveUDP(ctx context.Context, conn net.PacketConn, cfg config, logger *log.Logger) {
	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			logger.Printf("udp read error: %v", err)
			continue
		}
		reply := fmt.Sprintf("ir-lab-target udp listener alive pid=%d bytes=%d\n", os.Getpid(), n)
		_, _ = conn.WriteTo([]byte(reply), addr)
		logger.Printf("udp datagram from=%s bytes=%d", addr, n)
	}
}

func heartbeatLoop(ctx context.Context, dir, fileName, name, role string, every time.Duration, logger *log.Logger) {
	if every <= 0 {
		every = 15 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	writeHeartbeat(dir, fileName, name, role)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			writeHeartbeat(dir, fileName, name, role)
			logger.Printf("heartbeat role=%s pid=%d", role, os.Getpid())
		}
	}
}

func writeHeartbeat(dir, fileName, name, role string) {
	line := fmt.Sprintf("%s name=%s role=%s pid=%d ppid=%d tag=%s\n",
		time.Now().UTC().Format(time.RFC3339),
		name,
		role,
		os.Getpid(),
		os.Getppid(),
		os.Getenv("IR_LAB_TAG"),
	)
	_ = appendFile(filepath.Join(dir, fileName), line)
}

func appendFile(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
