package distro

import (
	"bufio"
	"os"
	"strings"
)

// ParseOSRelease reads /etc/os-release into an OSInfo.
// Returns a zero value (no error) if the file is missing — callers may
// still want to dispatch via --distro override.
func ParseOSRelease(path string) (OSInfo, error) {
	if path == "" {
		path = "/etc/os-release"
	}
	var info OSInfo
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return info, nil
		}
		return info, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			info.ID = v
		case "VERSION_ID":
			info.VersionID = v
		case "PRETTY_NAME":
			info.PrettyName = v
		case "NAME":
			info.Name = v
		}
	}
	return info, s.Err()
}
