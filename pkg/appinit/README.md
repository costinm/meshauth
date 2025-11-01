# Application init and plugins

Unlike Java, in Golang only code that is referenced is linked into the 
binary. That is good for size - but bad for 'modular' architecture.

Caddy is a http server/reverse proxy that also doubles as a modular
application framework - and is very good, but things are tightly coupled
and few of the choices are perhaps not perfect. This package is not perfect either.

The model is very simple:
- any module must be declared in order to be linked in the binary.
- the 'appinit.Register(string, any)' allows an app to pick what to include
- go plugins, wasm and processes provide out-of-binary modules.


There is no dependency from 'modules' to the init code.

Why:
Using init() pattern from Caddy requires that each module has a dependency
on some 'application framework'. I tried using the expvar or the http 
default mux or other 'globals' in go, but it is not very elegant, and even if it worked - main() still needs to import each module.

## Configuration

Golang templates are a very powerful mechnism to 'script' both pages but
also initialization, since they allow calls via reflection.

Json is also commonly used - yaml is translated to json.

## Patterns

Once the modules are linked in the binary and known by a name, initialization happens in few steps.

- New - creates the object, with some defaults. If a struct is registered - it will be cloned or created. Builders can also be registered.
- Fields in the struct are set - using json or reflection
- Init() or Provision() are called - listeners, etc are created.
- Start() or Run() are called.
- Stop() when the server is shutting down - lame duck mode.
- Restart() if the config is reloaded.
- Close() if the object is no longer used.

For each step, there are different patterns of parameters - similar to 
go template language. The object may implement interfaces or have public
fields.

## Registries or 'Resource Stores'

Protobuf, K8S default libraries - and quite a few others - also provide 
registries of nameed objects, which can be constructed on demand and loaded
from serialized form.

## Code generation

Given a list of module names and a map of names to 'known types', it is 
also possible to generate the initialization code. 
