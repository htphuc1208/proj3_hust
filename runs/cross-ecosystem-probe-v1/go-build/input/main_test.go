package main
import ("testing"; "gopkg.in/yaml.v2")
func TestYAML(t *testing.T) { _, err := yaml.Marshal(map[string]string{"a":"b"}); if err != nil { t.Fatal(err) } }
