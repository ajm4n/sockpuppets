package main

import "encoding/json"

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func parseID(dec string) (string, error) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(dec), &result); err != nil {
		return "", err
	}
	if id, ok := result["agent_id"].(string); ok && id != "" {
		return id, nil
	}
	return "", errString("registration failed")
}

func parseCommands(dec string) ([]map[string]interface{}, error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(dec), &parsed); err != nil {
		return nil, err
	}
	if tp, _ := parsed["type"].(string); tp == "registered" {
		if id, ok := parsed["agent_id"].(string); ok && id != "" {
			return []map[string]interface{}{{"type": "reregister", "agent_id": id}}, nil
		}
	}
	if tp, _ := parsed["type"].(string); tp == "commands" {
		if cmds, ok := parsed["commands"].([]interface{}); ok {
			var out []map[string]interface{}
			for _, c := range cmds {
				if m, ok := c.(map[string]interface{}); ok {
					out = append(out, m)
				}
			}
			return out, nil
		}
	}
	return nil, nil
}

type errString string

func (e errString) Error() string { return string(e) }
