// Package ec2 implements a minimal IMDSv2 client.
//
// IMDSv2 is strongly preferred because it requires a session token and
// thus mitigates SSRF-style accidents from a compromised host. We never
// fall back to IMDSv1.
package ec2

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	imdsBase    = "http://169.254.169.254"
	tokenPath   = "/latest/api/token"
	tokenTTLHdr = "X-aws-ec2-metadata-token-ttl-seconds"
	tokenHdr    = "X-aws-ec2-metadata-token"
	tokenTTL    = "60"
)

// Client talks to IMDSv2. It is safe to construct and discard per-call.
type Client struct {
	HTTP    *http.Client
	BaseURL string
}

// New returns a Client with a short connect timeout. We do NOT want to
// hang on a host without IMDS (containers, on-prem testing).
func New() *Client {
	return &Client{
		BaseURL: imdsBase,
		HTTP: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 1 * time.Second,
				}).DialContext,
			},
		},
	}
}

func (c *Client) token(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.BaseURL+tokenPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(tokenTTLHdr, tokenTTL)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("imds token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("imds token: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *Client) get(ctx context.Context, token, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(tokenHdr, token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("imds %s: status %d", path, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Metadata returns a small set of fields useful for chain-of-custody.
// Failures on individual lookups are non-fatal — missing fields are
// returned as empty strings and the caller decides how to handle them.
func (c *Client) Metadata(ctx context.Context) (map[string]string, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	keys := map[string]string{
		"instance_id":       "/latest/meta-data/instance-id",
		"instance_type":     "/latest/meta-data/instance-type",
		"availability_zone": "/latest/meta-data/placement/availability-zone",
		"region":            "/latest/meta-data/placement/region",
		"ami_id":            "/latest/meta-data/ami-id",
		"account_id":        "/latest/dynamic/instance-identity/document",
	}
	out := map[string]string{}
	for name, path := range keys {
		v, err := c.get(ctx, token, path)
		if err != nil {
			continue
		}
		out[name] = v
	}
	return out, nil
}
