- move to separate git repo

- expore a 'config-driven' build/release, where a set of configs are used to generate a binary including all configured modules ( and no more ) and gets pushed along with the configs.

Config changes may push a new binary if needed, or reuse 
existing binary if it has all required modules.

- Document and import the 'native' type registry (varz)