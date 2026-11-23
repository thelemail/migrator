//go:build e2e

package session

import "context"

func UseBrowser(open func(context.Context, string) error) { opener = open }
