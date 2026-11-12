module example.org/sbom-build-probe

go 1.23

require (
	golang.org/x/crypto v0.17.0
	golang.org/x/text v0.14.0
	gopkg.in/yaml.v2 v2.2.8
)

require golang.org/x/sys v0.15.0 // indirect

replace golang.org/x/text v0.3.0 => golang.org/x/text v0.3.8
