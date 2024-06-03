package meshauth

import "context"


// Modules are used with conditional compiled code, to reduce deps and binary size.
// Typically added using init()
//
// The function will be called very early - before loading any config.
//
// StartFunctions will be called during Start().
var Modules = map[string]func(ctx context.Context, gate *MeshAuth) error {}

