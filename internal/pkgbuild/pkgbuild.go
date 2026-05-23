// Package pkgbuild builds a tar.gz evidence bundle out of an --out
// directory previously populated by `acquire` and `collect`.
//
// The bundle layout:
//
//   bundle.tar.gz
//   └── <case_id-or-hostname>-<timestamp>/
//       ├── manifest.json          (consolidated)
//       ├── acquire-manifest.json  (if present)
//       ├── collect-manifest.json  (if present)
//       ├── audit.log
//       ├── collect/...
//       └── memory.lime            (if present)
//
// Self-reference rule:
//
// `manifest.json` itself is NOT listed in `manifest.Artifacts`. A file
// cannot meaningfully record its own SHA-256 because writing the hash
// changes the file. Instead:
//   - Every OTHER regular file in the bundle is listed in
//     `manifest.Artifacts` with its size and SHA-256.
//   - The manifest is then saved exactly once and the same bytes are
//     placed into the tarball. The in-memory Manifest returned to the
//     caller is byte-identical to the on-disk `manifest.json` inside
//     the tarball.
//   - Integrity of `manifest.json` itself is established by:
//       (a) the parallel `acquire-manifest.json`/`collect-manifest.json`
//           files saved at acquisition time (also inside the bundle),
//       (b) the tarball-level SHA-256 returned by Build().
package pkgbuild

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/example/kernledger/internal/audit"
	"github.com/example/kernledger/internal/distro"
	"github.com/example/kernledger/internal/hashutil"
	"github.com/example/kernledger/internal/manifest"
)

// Options for Build.
type Options struct {
	InDir              string
	OutPath            string // .tar.gz file to create
	IncludeEC2Metadata bool
	ToolVersion        string
	ToolCommit         string
	Adapter            distro.Adapter
	OSInfo             distro.OSInfo
}

// BuildResult is what Build returns to its caller.
type BuildResult struct {
	Manifest      *manifest.Manifest
	ManifestPath  string // path to the manifest.json inside InDir (also embedded in tarball)
	TarballPath   string
	TarballSHA256 string // SHA-256 of the produced tar.gz
}

// consolidatedManifestName is the filename used inside InDir AND the
// tarball. Hard-coded so the self-reference exclusion rule has a single
// well-known target.
const consolidatedManifestName = "manifest.json"

// Build consolidates the input directory into a tarball and writes a
// fresh manifest.json alongside it. The returned BuildResult.Manifest
// is byte-identical to the manifest.json embedded in the tarball.
func Build(ctx context.Context, log *audit.Logger, opts Options) (*BuildResult, error) {
	if opts.InDir == "" {
		return nil, fmt.Errorf("--in is required")
	}
	if opts.OutPath == "" {
		return nil, fmt.Errorf("--out is required")
	}

	m := manifest.New(opts.ToolVersion, opts.ToolCommit, adapterID(opts.Adapter))
	hostname, _ := os.Hostname()
	m.Host = manifest.HostInfo{
		Hostname:      hostname,
		KernelRelease: readTrim("/proc/sys/kernel/osrelease"),
		KernelVersion: readTrim("/proc/sys/kernel/version"),
		OSPrettyName:  opts.OSInfo.PrettyName,
		OSID:          opts.OSInfo.ID,
		OSVersionID:   opts.OSInfo.VersionID,
	}

	// Populate cloud info. IMDS is consulted only when --include-ec2-metadata
	// is set. We route the lookup through the distro adapter's
	// CloudProviders() so that non-AWS distros can substitute (or omit)
	// without touching pkgbuild.
	m.Cloud = buildCloudInfo(ctx, log, opts)

	// Bring forward acquire/collect manifests if present.
	if sub, err := manifest.Load(filepath.Join(opts.InDir, "acquire-manifest.json")); err == nil {
		m.Acquisition = sub.Acquisition
	}
	if sub, err := manifest.Load(filepath.Join(opts.InDir, "collect-manifest.json")); err == nil {
		m.Collection = sub.Collection
	}

	// Hash every regular file under InDir except:
	//   - the tarball itself (if nested in InDir)
	//   - the consolidated manifest.json (self-reference is impossible)
	rootClean := filepath.Clean(opts.InDir)
	tbClean := filepath.Clean(opts.OutPath)
	manifestPath := filepath.Join(rootClean, consolidatedManifestName)

	var artifacts []manifest.Artifact
	err := filepath.Walk(rootClean, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warn("package.walk.error", err.Error(), map[string]interface{}{"path": path})
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		clean := filepath.Clean(path)
		if clean == tbClean {
			return nil
		}
		if clean == manifestPath {
			// Self-reference exclusion. See package doc.
			return nil
		}
		rel, _ := filepath.Rel(rootClean, path)
		h, n, err := hashutil.FileSHA256(path)
		if err != nil {
			log.Warn("package.hash.error", err.Error(), map[string]interface{}{"path": path})
			return nil
		}
		artifacts = append(artifacts, manifest.Artifact{
			Path:   rel,
			SHA256: h,
			Size:   n,
			Kind:   classify(rel),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	m.Artifacts = artifacts

	// Persist the consolidated manifest exactly once. From this point
	// on the in-memory Manifest must NOT be mutated, otherwise the
	// on-disk and in-memory copies would diverge.
	if err := m.Save(manifestPath); err != nil {
		return nil, err
	}

	if err := writeTarGz(opts.InDir, opts.OutPath); err != nil {
		return nil, err
	}

	// Hash the tarball after it is closed.
	tbHash, _, err := hashutil.FileSHA256(opts.OutPath)
	if err != nil {
		log.Warn("package.tarball.hash", err.Error(), nil)
	}

	log.Info("package.done", "tarball written", map[string]interface{}{
		"out":            opts.OutPath,
		"artifacts":      len(m.Artifacts),
		"tarball_sha256": tbHash,
	})
	return &BuildResult{
		Manifest:      m,
		ManifestPath:  manifestPath,
		TarballPath:   opts.OutPath,
		TarballSHA256: tbHash,
	}, nil
}

// buildCloudInfo returns the manifest's cloud section.
//
// There is only one source: IMDSv2 (or whatever the active distro
// adapter exposes via CloudProviders()), gated by IncludeEC2Metadata.
// We do NOT accept operator-supplied overrides here — that was the
// behavior in schema ≤ 3.0.0, removed because operator-typed strings
// were forgeable and just duplicated what IMDS provides authentically.
//
// If the flag is off, or IMDS is unreachable, or the provider returns
// no data, this returns nil — manifest.cloud is then absent from the
// JSON output. The analyst recovers the AWS context from the bundle's
// filename / S3 prefix / ticket instead.
func buildCloudInfo(ctx context.Context, log *audit.Logger, opts Options) *manifest.CloudInfo {
	if !opts.IncludeEC2Metadata {
		return nil
	}
	md := fetchCloudMetadata(ctx, log, opts.Adapter)
	if md == nil {
		return nil
	}
	c := &manifest.CloudInfo{
		Provider:     md["_provider"],
		InstanceID:   md["instance_id"],
		InstanceType: md["instance_type"],
		Region:       md["region"],
		AvailZone:    md["availability_zone"],
		AMIID:        md["ami_id"],
	}
	if doc := md["account_id"]; doc != "" {
		if acc := extractField(doc, "accountId"); acc != "" {
			c.AccountID = acc
		}
	}
	if *c == (manifest.CloudInfo{}) {
		return nil
	}
	return c
}

// fetchCloudMetadata asks the distro adapter for its preferred cloud
// providers and uses the first one that succeeds. The provider's name
// is stored under the synthetic key "_provider".
func fetchCloudMetadata(ctx context.Context, log *audit.Logger, adapter distro.Adapter) map[string]string {
	if adapter == nil {
		return nil
	}
	providers := adapter.CloudProviders()
	for _, p := range providers {
		log.Info("package.metadata.fetch", "fetching cloud metadata via "+p.Name(), nil)
		md, err := p.Fetch(ctx)
		if err != nil {
			log.Warn("package.metadata.failed", err.Error(), map[string]interface{}{"provider": p.Name()})
			continue
		}
		if md == nil {
			md = map[string]string{}
		}
		md["_provider"] = p.Name()
		return md
	}
	return nil
}

func adapterID(a distro.Adapter) string {
	if a == nil {
		return "unknown"
	}
	return a.ID()
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func classify(rel string) string {
	switch {
	case strings.HasSuffix(rel, ".lime"), strings.HasSuffix(rel, ".raw"):
		return "memory_image"
	case strings.HasSuffix(rel, "manifest.json"):
		return "manifest"
	case strings.Contains(rel, "collect/files/"):
		return "filesystem_artifact"
	case strings.HasPrefix(rel, "collect/"):
		return "command_output"
	case strings.HasSuffix(rel, "audit.log"):
		return "audit_log"
	default:
		return "other"
	}
}

// extractField does a tiny JSON-ish extraction without pulling in extra
// deps. The IMDS document is small and well-formed; this is sufficient.
func extractField(doc, field string) string {
	needle := `"` + field + `"`
	i := strings.Index(doc, needle)
	if i < 0 {
		return ""
	}
	rest := doc[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	rest = rest[j+1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return ""
	}
	return rest[:k]
}

func writeTarGz(srcDir, dst string) error {
	// In-tarball directory prefix: hostname + UTC timestamp. The
	// operator's case linkage is expressed via the filename of `dst`
	// itself (and the name of `srcDir`), not here.
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "host"
	}
	prefix := hostname + "-" + time.Now().UTC().Format("20060102T150405Z")

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	cleanRoot := filepath.Clean(srcDir)
	return filepath.Walk(cleanRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable, do not abort
		}
		// Skip the tarball itself if nested inside the source dir.
		if filepath.Clean(path) == filepath.Clean(dst) {
			return nil
		}
		rel, _ := filepath.Rel(cleanRoot, path)
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(filepath.Join(prefix, rel))
		// Tar mtime carries forensic value — leave it as-is rather than
		// normalizing. Modes default from FileInfoHeader.

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			if err != nil {
				return err
			}
		}
		return nil
	})
}
