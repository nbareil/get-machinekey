package iis

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
)

type Application struct {
	Site            string
	SiteID          string
	Path            string
	ApplicationName string
	ApplicationID   string
	Pool            string
	IdentityType    string
	IdentityUser    string
	RuntimeVersion  string
	PhysicalPath    string
	Bindings        []Binding
}

type Binding struct {
	Protocol    string
	Information string
}

type MachineKey struct {
	ValidationKey     string `xml:"validationKey,attr" json:"validation_key_setting"`
	DecryptionKey     string `xml:"decryptionKey,attr" json:"decryption_key_setting"`
	Validation        string `xml:"validation,attr" json:"validation_algorithm"`
	Decryption        string `xml:"decryption,attr" json:"decryption_algorithm"`
	CompatibilityMode string `xml:"compatibilityMode,attr" json:"compatibility_mode"`
}

type applicationHost struct {
	System struct {
		ApplicationPools struct {
			PoolDefaults struct {
				ManagedRuntimeVersion string       `xml:"managedRuntimeVersion,attr"`
				ProcessModel          processModel `xml:"processModel"`
			} `xml:"applicationPoolDefaults"`
			Pools []pool `xml:"add"`
		} `xml:"applicationPools"`
		Sites struct {
			ApplicationDefaults applicationDefaults `xml:"applicationDefaults"`
			Items               []site              `xml:"site"`
		} `xml:"sites"`
	} `xml:"system.applicationHost"`
}

type processModel struct {
	IdentityType string `xml:"identityType,attr"`
	UserName     string `xml:"userName,attr"`
}

type pool struct {
	Name                  string       `xml:"name,attr"`
	ManagedRuntimeVersion string       `xml:"managedRuntimeVersion,attr"`
	ProcessModel          processModel `xml:"processModel"`
}

type site struct {
	Name                string              `xml:"name,attr"`
	ID                  string              `xml:"id,attr"`
	Applications        []appDeclaration    `xml:"application"`
	Bindings            []binding           `xml:"bindings>binding"`
	ApplicationDefaults applicationDefaults `xml:"applicationDefaults"`
}

type applicationDefaults struct {
	Pool string `xml:"applicationPool,attr"`
}

type binding struct {
	Protocol    string `xml:"protocol,attr"`
	Information string `xml:"bindingInformation,attr"`
}

type appDeclaration struct {
	Path               string             `xml:"path,attr"`
	Pool               string             `xml:"applicationPool,attr"`
	VirtualDirectories []virtualDirectory `xml:"virtualDirectory"`
}

type virtualDirectory struct {
	Path         string `xml:"path,attr"`
	PhysicalPath string `xml:"physicalPath,attr"`
}

func ParseApplicationHost(r io.Reader, expand func(string) string) ([]Application, error) {
	var doc applicationHost
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse applicationHost.config: %w", err)
	}

	defaultModel := doc.System.ApplicationPools.PoolDefaults.ProcessModel
	if defaultModel.IdentityType == "" {
		defaultModel.IdentityType = "ApplicationPoolIdentity"
	}
	identities := make(map[string]processModel, len(doc.System.ApplicationPools.Pools))
	runtimes := make(map[string]string, len(doc.System.ApplicationPools.Pools))
	for _, p := range doc.System.ApplicationPools.Pools {
		model := p.ProcessModel
		if model.IdentityType == "" {
			model.IdentityType = defaultModel.IdentityType
		}
		if model.UserName == "" && strings.EqualFold(model.IdentityType, "SpecificUser") {
			model.UserName = defaultModel.UserName
		}
		identities[p.Name] = model
		runtimeVersion := p.ManagedRuntimeVersion
		if runtimeVersion == "" {
			runtimeVersion = doc.System.ApplicationPools.PoolDefaults.ManagedRuntimeVersion
		}
		runtimes[p.Name] = runtimeVersion
	}

	var result []Application
	for _, s := range doc.System.Sites.Items {
		bindings := make([]Binding, 0, len(s.Bindings))
		for _, item := range s.Bindings {
			bindings = append(bindings, Binding{Protocol: item.Protocol, Information: item.Information})
		}
		for _, declaration := range s.Applications {
			poolName := declaration.Pool
			if poolName == "" {
				poolName = s.ApplicationDefaults.Pool
			}
			if poolName == "" {
				poolName = doc.System.Sites.ApplicationDefaults.Pool
			}
			path := declaration.Path
			if path == "" {
				path = "/"
			}
			physicalPath := ""
			for _, directory := range declaration.VirtualDirectories {
				if directory.Path == "/" {
					physicalPath = expand(directory.PhysicalPath)
					break
				}
			}
			model := identities[poolName]
			if model.IdentityType == "" {
				model.IdentityType = defaultModel.IdentityType
			}
			result = append(result, Application{
				Site:            s.Name,
				SiteID:          s.ID,
				Path:            path,
				ApplicationName: path,
				ApplicationID:   applicationID(s.ID, path),
				Pool:            poolName,
				IdentityType:    model.IdentityType,
				IdentityUser:    model.UserName,
				RuntimeVersion:  runtimes[poolName],
				PhysicalPath:    physicalPath,
				Bindings:        bindings,
			})
		}
	}
	return result, nil
}

// ResolveURL returns the application that IIS would select from the configured
// bindings and longest matching application path. It refuses binding ties so a
// forensic run cannot silently choose the wrong key.
func ResolveURL(apps []Application, rawURL, siteOverride string) ([]Application, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}
	target.Scheme = strings.ToLower(target.Scheme)
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("target URL scheme must be http or https, got %q", target.Scheme)
	}
	if target.Hostname() == "" {
		return nil, fmt.Errorf("target URL must contain a hostname")
	}
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	type siteMatch struct {
		score int
		apps  []Application
	}
	sites := make(map[string]siteMatch)
	for _, app := range apps {
		if siteOverride != "" && !strings.EqualFold(app.Site, siteOverride) {
			continue
		}
		match := sites[app.Site]
		if match.apps == nil {
			best := 0
			if siteOverride == "" {
				best = -1
				for _, binding := range app.Bindings {
					if score, ok := bindingScore(binding, target.Scheme, target.Hostname(), port); ok && score > best {
						best = score
					}
				}
			}
			if best < 0 {
				continue
			}
			match.score = best
		}
		match.apps = append(match.apps, app)
		sites[app.Site] = match
	}
	if len(sites) == 0 {
		if siteOverride != "" {
			return nil, fmt.Errorf("IIS site %q was not found", siteOverride)
		}
		return nil, fmt.Errorf("URL %q does not match any IIS site binding", rawURL)
	}

	bestScore := -1
	bestSites := make([]string, 0, len(sites))
	for name, match := range sites {
		if match.score > bestScore {
			bestScore = match.score
			bestSites = []string{name}
		} else if match.score == bestScore {
			bestSites = append(bestSites, name)
		}
	}
	if len(bestSites) != 1 {
		sort.Strings(bestSites)
		return nil, fmt.Errorf("URL %q ambiguously matches IIS sites %s; use -site to select one", rawURL, strings.Join(bestSites, ", "))
	}

	path := target.EscapedPath()
	if decoded, decodeErr := url.PathUnescape(path); decodeErr == nil {
		path = decoded
	}
	if path == "" {
		path = "/"
	}
	var selected *Application
	matchedApps := sites[bestSites[0]].apps
	for index := range matchedApps {
		candidate := &matchedApps[index]
		if !applicationPathMatches(candidate.Path, path) {
			continue
		}
		if selected == nil || len(strings.TrimRight(candidate.Path, "/")) > len(strings.TrimRight(selected.Path, "/")) {
			copy := *candidate
			selected = &copy
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("URL path %q does not match an application in IIS site %q", path, bestSites[0])
	}
	return []Application{*selected}, nil
}

func bindingScore(binding Binding, scheme, hostname, port string) (int, bool) {
	if !strings.EqualFold(binding.Protocol, scheme) {
		return 0, false
	}
	ip, bindingPort, hostHeader, ok := splitBindingInformation(binding.Information)
	if !ok || (bindingPort != "*" && bindingPort != port) {
		return 0, false
	}
	score := 10
	switch {
	case hostHeader == "" || hostHeader == "*":
		score++
	case strings.EqualFold(hostHeader, hostname):
		score += 100
	case strings.HasPrefix(hostHeader, "*.") && strings.HasSuffix(strings.ToLower(hostname), strings.ToLower(hostHeader[1:])):
		score += 50
	default:
		return 0, false
	}
	if targetIP := net.ParseIP(hostname); targetIP != nil {
		if ip == "" || ip == "*" {
			score++
		} else if bindingIP := net.ParseIP(strings.Trim(ip, "[]")); bindingIP != nil && bindingIP.Equal(targetIP) {
			score += 20
		} else {
			return 0, false
		}
	}
	return score, true
}

func splitBindingInformation(value string) (ip, port, host string, ok bool) {
	last := strings.LastIndex(value, ":")
	if last < 0 {
		return "", "", "", false
	}
	previous := strings.LastIndex(value[:last], ":")
	if previous < 0 {
		return "", "", "", false
	}
	return value[:previous], value[previous+1 : last], value[last+1:], true
}

func applicationPathMatches(applicationPath, requestPath string) bool {
	app := strings.TrimRight(applicationPath, "/")
	if app == "" {
		return true
	}
	request := strings.TrimRight(requestPath, "/")
	return strings.EqualFold(request, app) || (len(request) > len(app) && strings.EqualFold(request[:len(app)], app) && request[len(app)] == '/')
}

func applicationID(siteID, path string) string {
	id := "/LM/W3SVC/" + siteID + "/ROOT"
	if path != "/" {
		id += "/" + strings.Trim(path, "/")
	}
	return id
}

func ParseMachineKey(data []byte) (MachineKey, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return MachineKey{}, errorsNoMachineKey
		}
		if err != nil {
			return MachineKey{}, fmt.Errorf("parse effective machineKey configuration: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "machineKey" {
			continue
		}
		var result MachineKey
		if err := decoder.DecodeElement(&result, &start); err != nil {
			return MachineKey{}, fmt.Errorf("parse machineKey element: %w", err)
		}
		applyMachineKeyDefaults(&result)
		return result, nil
	}
}

var errorsNoMachineKey = fmt.Errorf("effective configuration did not contain a machineKey element")

func applyMachineKeyDefaults(config *MachineKey) {
	if config.ValidationKey == "" {
		config.ValidationKey = "AutoGenerate,IsolateApps"
	}
	if config.DecryptionKey == "" {
		config.DecryptionKey = "AutoGenerate,IsolateApps"
	}
	if config.Validation == "" {
		config.Validation = "HMACSHA256"
	}
	if config.Decryption == "" {
		config.Decryption = "Auto"
	}
	if config.CompatibilityMode == "" {
		config.CompatibilityMode = "Framework20SP1"
	}
}

func ConfigURL(app Application) string {
	if app.Path == "/" {
		return app.Site + "/"
	}
	return app.Site + "/" + strings.Trim(app.Path, "/")
}
