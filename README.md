# get-machinekey

`get-machinekey.exe` is a read-only Windows incident-response collector for
.NET Framework 4.x ASP.NET applications hosted by IIS. It is intended to be launched as
`NT AUTHORITY\SYSTEM` by an EDR. It inventories IIS applications, resolves
their effective `<machineKey>` configuration, and prints one JSON document to
standard output.

The output contains secrets. Treat it like a credential dump: collect it only
on systems you are authorized to investigate, restrict access to the EDR
result, and destroy it when the investigation is complete.

## What it collects

Give the collector the captured request URL. It resolves the matching IIS site
from its bindings, chooses the longest matching application path, and reports:

- the site, application path, application pool, worker identity SID, physical
  path, ASP.NET application name, and ASP.NET application ID;
- effective `validationKey`, `decryptionKey`, `validation`, `decryption`, and
  `compatibilityMode` settings, obtained from IIS `AppCmd.exe`;
- explicit hexadecimal keys, when configured;
- auto-generated ASP.NET 4.5+ application-level validation and decryption keys,
  derived with the framework's SP800-108/HMAC-SHA-512 construction; and
- final ASP.NET 4.0-and-earlier validation and decryption keys for
  `AutoGenerate`, `IsolateApps`, `IsolateByAppId`, or both modifiers; plus
- the underlying 64-byte validation and 24-byte decryption base material.

Auto-generated material is searched in the same persistence locations used by
ASP.NET:

1. `HKU\<worker SID>\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4`
2. `HKLM\SOFTWARE\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeys\<worker SID>\AutoGenKeyV4`
3. LSA private data `L$ASP.NETAutoGenKeysV44.0.30319.0` (notably LocalSystem)

The program never changes IIS configuration, registry values, services, worker
processes, or files.

## Build

Build a dependency-free Windows executable from macOS or Linux:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o get-machinekey.exe ./cmd/get-machinekey
```

For ARM64 Windows, replace `GOARCH=amd64` with `GOARCH=arm64`.

## Run

Run from an EDR as SYSTEM and capture stdout. The URL can be positional or
passed with `-url`:

```text
get-machinekey.exe https://www.example.test/orders/view.aspx?id=42
get-machinekey.exe -pretty -url https://www.example.test/orders/view.aspx?id=42
get-machinekey.exe -site "Default Web Site" https://www.example.test/app/page.aspx
```

`-site` is an optional authoritative override for reverse proxies or servers
where wildcard or overlapping bindings make the URL ambiguous. It selects the
named site and uses the URL path to choose its longest matching application.
Without a URL the program retains inventory mode and reports every application.

Exit codes:

- `0`: inventory completed; individual applications can still contain an
  `errors` array;
- `1`: inventory or URL resolution could not start, or JSON output failed;
- `2`: invalid command-line arguments.

The JSON has a `schema_version` field so an EDR parser can reject unknown
formats. Errors are data rather than prose on stdout. Diagnostics go to stderr
and never include key bytes.

## Important limits

- ASP.NET Core does not use `<machineKey>` and is outside this program's scope.
- ASP.NET 2.0/3.5 applications use a different persisted `AutoGenKey` layout;
  this version reports their auto-generated keys as unsupported rather than
  mixing incompatible formats. Explicit keys are still reported.
- The derived `aspnet45_validation_key` and `aspnet45_decryption_key` are the
  application-level keys used by the ASP.NET 4.5+ crypto provider. Page-level
  ViewState processing can additionally depend on the page virtual path,
  page type, `ViewStateUserKey`, generator, and compatibility settings.
- Legacy isolation uses the target server's installed Windows PowerShell / .NET
  Framework to execute the exact
  `StringComparer.InvariantCultureIgnoreCase.GetHashCode` operation used by
  System.Web. Input is passed through environment variables, not interpolated
  into a command. If PowerShell is unavailable or constrained, modern keys and
  legacy base material are still reported with a per-application error.
- A running worker can retain material in memory after its persisted value was
  removed or replaced. This collector deliberately does not suspend, inject
  into, or scan worker-process memory; such a mismatch is reported as a
  limitation, not silently treated as current runtime proof.
- A protected or malformed effective configuration may prevent AppCmd from
  returning the section. The application entry remains in the output with the
  error.

## Development

```sh
go test ./...
go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/get-machinekey
```

The derivation tests use synthetic lab vectors, not production keys.

## Technical basis

The implementation follows the .NET Framework reference source for
`MachineKeyMasterKeyProvider`: 32 bytes of the auto-generated material form the
encryption KDK, the following 32 bytes form the validation KDK, and optional
`IsolateApps` / `IsolateByAppId` purpose strings feed the SP800-108 derivation.
IIS `AppCmd list config <URL> /section:system.web/machineKey` is used because
it returns effective inherited configuration rather than only the nearest
`Web.config` file. The collector deliberately omits AppCmd's `/config:*`
option: that option injects IIS schema defaults such as `validation="SHA1"`
even when System.Web applies its managed default of `HMACSHA256`.

