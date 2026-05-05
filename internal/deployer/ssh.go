package deployer

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const sshTimeout = 60 * time.Second

// DeploySSH copies certificate files to a remote server via SSH/SCP
// and runs the given commands over SSH.
func DeploySSH(
	privateSrc, fullchainSrc string,
	host, username, keyPath string,
	privateDst, fullchainDst string,
	commands []string,
	log *slog.Logger,
) error {
	log.Info("deployer: обновление удалённых сертификатов", "host", host)

	signer, err := loadSigner(keyPath)
	if err != nil {
		return fmt.Errorf("deployer ssh: load key %s: %w", keyPath, err)
	}

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         sshTimeout,
	}

	netConn, err := net.DialTimeout("tcp", host+":22", sshTimeout)
	if err != nil {
		return fmt.Errorf("deployer ssh: dial %s: %w", host, err)
	}
	netConn.SetDeadline(time.Now().Add(5 * time.Minute)) //nolint:errcheck

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, host+":22", cfg)
	if err != nil {
		netConn.Close()
		return fmt.Errorf("deployer ssh: handshake %s: %w", host, err)
	}
	conn := ssh.NewClient(sshConn, chans, reqs)
	defer conn.Close()

	// Upload both files.
	for _, pair := range [][2]string{
		{privateSrc, privateDst},
		{fullchainSrc, fullchainDst},
	} {
		if err := scpUpload(conn, pair[0], pair[1], log); err != nil {
			return fmt.Errorf("deployer ssh: upload %s: %w", pair[0], err)
		}
	}

	// Run post-deploy commands.
	for _, cmd := range commands {
		log.Info("deployer ssh: выполнение команды", "host", host, "cmd", cmd)
		out, err := sshRun(conn, cmd)
		if out != "" {
			log.Info("deployer ssh: вывод команды", "host", host, "cmd", cmd, "output", out)
		}
		if err != nil {
			return fmt.Errorf("deployer ssh: command %q on %s: %w", cmd, host, err)
		}
	}
	return nil
}

// scpUpload sends a local file to remotePath using the SCP sink protocol.
func scpUpload(conn *ssh.Client, localPath, remotePath string, log *slog.Logger) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	w, err := session.StdinPipe()
	if err != nil {
		return err
	}

	r, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	if err := session.Start("scp -t " + remotePath); err != nil {
		return err
	}

	// SCP sink protocol requires reading a \x00 ack after each step.
	if err := scpReadAck(r, "ready"); err != nil {
		return err
	}

	header := fmt.Sprintf("C0644 %d %s\n", info.Size(), filepath.Base(remotePath))
	if _, err := fmt.Fprint(w, header); err != nil {
		return err
	}
	if err := scpReadAck(r, "header"); err != nil {
		return err
	}

	if _, err := io.Copy(w, f); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, "\x00"); err != nil {
		return err
	}
	if err := scpReadAck(r, "data"); err != nil {
		return err
	}
	w.Close()

	if err := session.Wait(); err != nil {
		return err
	}
	log.Info("deployer ssh: файл загружен", "local", localPath, "remote", remotePath)
	return nil
}

// scpReadAck reads one SCP ack byte; on error reads the message line that follows.
func scpReadAck(r io.Reader, step string) error {
	b := make([]byte, 1)
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("scp %s ack: %w", step, err)
	}
	if b[0] == 0 {
		return nil
	}
	// bytes 1 (warning) and 2 (fatal) are followed by a message ending in \n
	var msg []byte
	buf := make([]byte, 1)
	for len(msg) < 512 {
		if _, err := r.Read(buf); err != nil {
			break
		}
		if buf[0] == '\n' {
			break
		}
		msg = append(msg, buf[0])
	}
	return fmt.Errorf("scp %s ack: remote error: %s", step, strings.TrimSpace(string(msg)))
}

// sshRun executes a single command and returns combined stdout+stderr.
func sshRun(conn *ssh.Client, cmd string) (string, error) {
	session, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	return strings.TrimSpace(string(out)), err
}

func loadSigner(keyPath string) (ssh.Signer, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(key)
}
