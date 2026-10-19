These 16 YAML files are byte-for-byte embedded configuration data recovered from
`vohive_v1.5.5-10u_linux_amd64` (57,958,562 bytes), SHA-256
`2b080980c72fede3dbad1c9f8830bb51d0bc368b4acb576c4f2d27f9182eb59f`.

`manifest.json` records each Go embed FS record virtual address, data virtual
address, and exact length. REA observed the builtin preset loader at `0xdbe340`;
its embed FS table begins at `0x27d3c58`. These are recovered data, not original
source code. Runtime defaults and merge behavior are separate implementation
choices unless supported by independently recorded REA evidence.

`defaults-evidence.json` records values independently recovered from the binary's
GetGlobalDefaultConfig assembly and Go runtime type metadata; `defaults.go`
implements those defaults. Policy normalization is common.Plmn3 @0xdb0ca0 and
policy.plmnKey @0xdbec00; MCC 460/461 literals are initialized @0xdb287c and
@0xdb28a5. Preset custom-ePDG source `preset` is observed @0xdb4eac.

The independent compatibility layer's external JSON override parser is not
claimed to reproduce the binary's complete external YAML override format.
