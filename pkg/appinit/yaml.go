package appinit

import (
	"bytes"
	"os/exec"
)

// Use go Exec yq to translate to json
// Yaml is mainly used for human edit, like markdown.
// It is ok at startup to just use yq to convert.
func Yaml2JSON2(bb []byte) ([]byte, error) {
	cmd := exec.Command("yq",
		"r", "-", "-j")
	cmd.Stdin = bytes.NewReader(bb)

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		//fmt.Println("YAML2JSON", err, string(bb), string(out.Bytes()))
		return nil, err
	}
	//fmt.Println("YAML2JSON", out.String())
	return out.Bytes(), nil
}
