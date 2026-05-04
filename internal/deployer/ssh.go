package deployer

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// DeploySSH copies certificate files to a remote server via SSH/SCP
// and runs the given commands over SSH.
func DeploySSH(
	privateSrc, fullchainSrc string,
	host, username, keyPath string,
	privateDst, fullchainDst string,
	commands []string,
	log *slog.Logger,
) error {
	log.Info("deployer: updating remote certificates", "host", host)

	signer, err := loadSigner(keyPath)
	if err != nil {
		return fmt.Errorf("deployer ssh: load key %s: %w", keyPath, err)
	}

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	conn, err := ssh.Dial("tcp", host+":22", cfg)
	if err != nil {
		return fmt.Errorf("deployer ssh: dial %s: %w", host, err)
	}
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
		log.Info("deployer ssh: running command", "host", host, "cmd", cmd)
		out, err := sshRun(conn, cmd)
		if out != "" {
			log.Info("deployer ssh: command output", "host", host, "cmd", cmd, "output", out)
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

	// Pipe to scp stdin.
	w, err := session.StdinPipe()
	if err != nil {
		return err
	}

	if err := session.Start("scp -t " + remotePath); err != nil {
		return err
	}

	// SCP protocol: header then data then NUL.
	header := fmt.Sprintf("C0644 %d %s\n", info.Size(), filepath.Base(remotePath))
	if _, err := fmt.Fprint(w, header); err != nil {
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, "\x00"); err != nil {
		return err
	}
	w.Close()

	if err := session.Wait(); err != nil {
		return err
	}
	log.Info("deployer ssh: file uploaded", "local", localPath, "remote", remotePath)
	return nil
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
