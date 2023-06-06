module github.com/costinm/meshauth/cmd

go 1.20

replace github.com/costinm/meshauth v0.0.0-20230123031534-9e635566c01e => ../

require (
	github.com/costinm/meshauth v0.0.0-20230123031534-9e635566c01e
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1
	sigs.k8s.io/yaml v1.2.0
)

require (
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
