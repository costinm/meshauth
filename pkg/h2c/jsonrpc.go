package h2c

import "encoding/json"

/*

Light json-rpc:

Example from spec:
--> {"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}
<-- {"jsonrpc": "2.0", "result": 19, "id": 1}

Key/values:
--> {"jsonrpc": "2.0", "method": "subtract",
     "params": {"subtrahend": 23, "minuend": 42}, "id": 3}

Notification (no id):
--> {"jsonrpc": "2.0", "method": "update", "params": [1,2,3,4,5]}

Error:
<-- {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"}

Batch:
[
        {"jsonrpc": "2.0", "method": "notify_sum", "params": [1,2,4]},
        {"jsonrpc": "2.0", "method": "notify_hello", "params": [7]}
]

Json 1.0 lacks 'jsonrpc', but supports:
{"__jsonclass__":["constructor", [param1,...]], "prop1": ...}
Both sides can send requests.
*/

type Request struct {
	Jsonrpc string
	Method  string
	Id      string
	// Bytes - can be parsed as json
	Params json.RawMessage
}

type Response struct {
	Jsonrpc string
	Result  json.RawMessage
	Error   struct {
		Code    int
		Message string
		Data    json.RawMessage
	}
	Id string
}
