package collector

import "github.com/nbareil/get-machinekey/internal/iis"

func effectiveMachineKeyArgs(app iis.Application) []string {
	return []string{
		"list",
		"config",
		iis.ConfigURL(app),
		"/section:system.web/machineKey",
	}
}
