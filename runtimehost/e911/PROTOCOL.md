# E911 entitlement compatibility

This is an independent implementation of the observed AT&T TS43 bootstrap. It
returns a URL plus POST form data for the host's websheet broker. Neither this
return nor an HTTP 200 means the user's emergency address has been registered.
No carrier endpoint, SIM, or target executable was contacted/executed in tests.

## Offline observations

Target SHA-256: `2b080980c72fede3dbad1c9f8830bb51d0bc368b4acb576c4f2d27f9182eb59f`.
The observations below are ordinary local ELF/type metadata and instruction
analysis, not recovered original source or a claim of REA decompiler coverage.
Scratch evidence: `/workspace/work/vowifi-analysis/recovered/`.

- `ts43.BuildAuthAction` at `0x139da00`: static initializer `0x27ac638`
  identifies `auth-type: EAP-AKA`, `action-name: getAuthentication`. Runtime type
  metadata gives subscriber-id, request-id, unique-id and optional token fields.
- `ts43.BuildSubscriberID` at `0x139e200`: Base64 of EAP Response/Identity,
  identifier 0; `BuildPermanentNAIIdentity` at `0x139e4a0` formats
  `0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org` (literal at `0x21fdcaf`).
- `att.buildInitialActions` at `0x13a1700`: authentication action, then optional
  `getPhoneServicesAccountStatus` when SIP username is nonempty, then
  `getEntitlement` with `entitlement-names: ["VoWiFi"]`. Action request IDs come
  from an atomic counter. Phone fields are sip-username and display-name.
- `att.runActions` at `0x13a12e0` and `ts43.DoJSONGzipRequest` at `0x139dba0`:
  POST JSON array compressed with gzip, seven observed headers reproduced in
  att.go, including x-protocol-version 2. Responses can be gzip by magic bytes.
- `att.CheckE911AddressUpdate` at `0x13a0540`: initial actions, Base64 EAP-AKA
  challenge response in a single `postChallenge` action, then renewed initial
  actions with returned token if websheet fields are absent. The original
  parser combines the TS43 fields and provider-specific address-update-url /
  address-update-url-post-data fields across response items.
- `runtimehost/entitlement.(*attSession).StartE911AddressUpdate` at `0x144b3e0`
  requires both URL and POST data (checks at `0x144b8b6` and `0x144b8d5`). Its
  success output includes `application/x-www-form-urlencoded` (literal at
  `0x21ea418`, 33 bytes). The original title literal is `E911地址`; the rewrite
  retains the configurable host-facing title/default.
- The target includes T-Mobile entitlement URLs in carrier presets, but the
  identified provider implementation and public routing are AT&T only. The
  rewrite returns ErrUnsupportedProvider for T-Mobile rather than inventing a
  successful flow from those presets.

## Deliberate implementation policies and remaining limits

- Reuse engine/eap's RFC 4187 EAP-AKA client for SIM AKA, server AT_MAC validation,
  response signing, strict ISIM selection and AUTS resynchronization. The
  original BuildChallengePayload demonstrates response signing; the rewrite's
  requirement to verify the server MAC is an explicit stricter policy. EAP-AKA'
  and encrypted attributes/fast reauthentication remain unsupported and fail.
- Accept TS43 status 1000, or 1003 with a challenge; reject absent/other statuses,
  duplicates, and unmatched response IDs. This conservative status/correlation
  policy is newly implemented, not claimed as the original parser's complete
  acceptance semantics. Carrier-specific alternative status handling needs
  authorized captured fixtures before widening it.
- Limit an operation to 45 seconds / 8 requests and each default HTTP exchange to
  20 seconds. Limit compressed and decoded response bodies to 1 MiB. Do not
  automatically forward identity/token/challenge data on HTTP redirects.
- HTTPClient remains source-compatible. HTTPRequest.Context and optional
  ContextHTTPClient carry cancellation; legacy adapters must preserve Context
  when copying requests. A custom HTTPClient and AKAProvider that block without
  observing cancellation cannot be forcefully interrupted through the legacy
  method signatures; no orphan goroutine is created to conceal that limitation.
- `public_https` checks absolute HTTPS, credentials, local hostnames and unsafe
  literal IPs without a DNS lookup. The host's existing websheet broker remains
  responsible for DNS/IP validation and safe dialing on every fetch/redirect.
- Original uTLS iPhone TLS fingerprints / HTTP2 fallback are not imitated.
  Standard Go TLS is used; live AT&T interoperability has not been established.
- No implicit environment token hooks. Only Identity.CachedToken explicitly
  supplied by a caller is used. Returned tokens remain operation-local.
