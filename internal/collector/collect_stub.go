//go:build !windows

package collector

import (
	"context"
	"errors"
)

func collect(context.Context, Options) (Report, error) {
	return Report{}, errors.New("get-machinekey collection is supported only on Windows")
}
