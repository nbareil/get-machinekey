package collector

import (
	"reflect"
	"testing"

	"github.com/nbareil/get-machinekey/internal/iis"
)

func TestEffectiveMachineKeyArgsDoNotRequestIISSchemaDefaults(t *testing.T) {
	t.Parallel()

	app := iis.Application{Site: "Default Web Site", Path: "/orders"}
	want := []string{
		"list",
		"config",
		"Default Web Site/orders",
		"/section:system.web/machineKey",
	}

	if got := effectiveMachineKeyArgs(app); !reflect.DeepEqual(got, want) {
		t.Fatalf("effectiveMachineKeyArgs() = %#v, want %#v", got, want)
	}
}
