package iis

import (
	"strings"
	"testing"
)

func TestParseApplicationHost(t *testing.T) {
	t.Parallel()
	xml := `<?xml version="1.0"?>
<configuration><system.applicationHost>
  <applicationPools>
    <applicationPoolDefaults><processModel identityType="ApplicationPoolIdentity" /></applicationPoolDefaults>
    <add name="DefaultAppPool" managedRuntimeVersion="v4.0" />
    <add name="SystemPool"><processModel identityType="LocalSystem" /></add>
  </applicationPools>
  <sites>
    <site name="Default Web Site" id="1">
      <bindings><binding protocol="http" bindingInformation="*:80:www.example.test" /></bindings>
      <application path="/">
        <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" />
      </application>
      <application path="/Legacy" applicationPool="SystemPool">
        <virtualDirectory path="/" physicalPath="D:\legacy" />
      </application>
    </site>
    <applicationDefaults applicationPool="DefaultAppPool" />
  </sites>
</system.applicationHost></configuration>`

	apps, err := ParseApplicationHost(strings.NewReader(xml), func(value string) string {
		return strings.ReplaceAll(value, "%SystemDrive%", "C:")
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 {
		t.Fatalf("got %d apps, want 2", len(apps))
	}
	if apps[0].ApplicationID != "/LM/W3SVC/1/ROOT" || apps[0].Pool != "DefaultAppPool" || apps[0].IdentityType != "ApplicationPoolIdentity" || apps[0].RuntimeVersion != "v4.0" {
		t.Fatalf("unexpected root app: %#v", apps[0])
	}
	if len(apps[0].Bindings) != 1 || apps[0].Bindings[0].Information != "*:80:www.example.test" {
		t.Fatalf("unexpected bindings: %#v", apps[0].Bindings)
	}
	if apps[1].ApplicationID != "/LM/W3SVC/1/ROOT/Legacy" || apps[1].IdentityType != "LocalSystem" {
		t.Fatalf("unexpected child app: %#v", apps[1])
	}
}

func TestResolveURLUsesBindingAndLongestApplicationPath(t *testing.T) {
	t.Parallel()
	apps := []Application{
		{Site: "Default", SiteID: "1", Path: "/", Bindings: []Binding{{Protocol: "https", Information: "*:443:www.example.test"}}},
		{Site: "Default", SiteID: "1", Path: "/orders", Bindings: []Binding{{Protocol: "https", Information: "*:443:www.example.test"}}},
		{Site: "Other", SiteID: "2", Path: "/", Bindings: []Binding{{Protocol: "https", Information: "*:443:other.example.test"}}},
	}
	got, err := ResolveURL(apps, "https://www.example.test/orders/view.aspx?id=42", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Site != "Default" || got[0].Path != "/orders" {
		t.Fatalf("unexpected match: %#v", got)
	}
}

func TestResolveURLRequiresApplicationPathBoundary(t *testing.T) {
	t.Parallel()
	bindings := []Binding{{Protocol: "https", Information: "*:443:www.example.test"}}
	apps := []Application{
		{Site: "Default", SiteID: "1", Path: "/", Bindings: bindings},
		{Site: "Default", SiteID: "1", Path: "/orders", Bindings: bindings},
	}
	got, err := ResolveURL(apps, "https://www.example.test/orders-v2/page.aspx", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "/" {
		t.Fatalf("unexpected prefix match: %#v", got)
	}
}

func TestResolveURLPrefersExactHostHeader(t *testing.T) {
	t.Parallel()
	apps := []Application{
		{Site: "Wildcard", SiteID: "1", Path: "/", Bindings: []Binding{{Protocol: "https", Information: "*:443:"}}},
		{Site: "Exact", SiteID: "2", Path: "/", Bindings: []Binding{{Protocol: "https", Information: "*:443:www.example.test"}}},
	}
	got, err := ResolveURL(apps, "https://www.example.test/", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Site != "Exact" {
		t.Fatalf("unexpected binding match: %#v", got)
	}
}

func TestResolveURLReportsAmbiguousWildcardBindings(t *testing.T) {
	t.Parallel()
	apps := []Application{
		{Site: "One", SiteID: "1", Path: "/", Bindings: []Binding{{Protocol: "http", Information: "*:80:"}}},
		{Site: "Two", SiteID: "2", Path: "/", Bindings: []Binding{{Protocol: "http", Information: "*:80:"}}},
	}
	if _, err := ResolveURL(apps, "http://example.test/", ""); err == nil {
		t.Fatal("expected ambiguous bindings to fail")
	}
	got, err := ResolveURL(apps, "https://reverse-proxy.example/", "Two")
	if err != nil || len(got) != 1 || got[0].Site != "Two" {
		t.Fatalf("site override failed: got %#v, err %v", got, err)
	}
}

func TestParseMachineKey(t *testing.T) {
	t.Parallel()
	xml := `<system.web><machineKey validationKey="AutoGenerate,IsolateApps" decryptionKey="0011" validation="HMACSHA256" decryption="AES" compatibilityMode="Framework45" /></system.web>`
	got, err := ParseMachineKey([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if got.ValidationKey != "AutoGenerate,IsolateApps" || got.DecryptionKey != "0011" || got.CompatibilityMode != "Framework45" {
		t.Fatalf("unexpected config: %#v", got)
	}
}
