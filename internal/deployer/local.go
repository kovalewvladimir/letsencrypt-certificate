package deployer

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// DeployLocal copies certificate files to local paths and runs commands.
func DeployLocal(
	privateSrc, fullchainSrc string,
	privateDst, fullchainDst string,
	commands []string,
	log *slog.Logger,
) error {
	hostname, _ := os.Hostname()
	log.Info("deployer: updating local certificates", "host", hostname)

	if err := copyFile(privateSrc, privateDst); err != nil {
		return fmt.Errorf("deployer local: copy private key: %w", err)
	}
	if err := copyFile(fullchainSrc, fullchainDst); err != nil {
		return fmt.Errorf("deployer local: copy fullchain: %w", err)
	}

	for _, cmd := range commands {
		log.Info("deployer local: running command", "cmd", cmd)
		parts := strings.Fields(cmd)
		if len(parts) == 0 {
			continue
		}
		out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
		if len(out) > 0 {
			log.Info("deployer local: command output", "cmd", cmd, "output", string(out))
		}
		if err != nil {
			return fmt.Errorf("deployer local: command %q: %w", cmd, err)
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
