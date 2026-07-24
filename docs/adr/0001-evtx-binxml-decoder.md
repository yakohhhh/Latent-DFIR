# ADR 0001: EVTX binary XML decoder — build a focused decoder rather than reuse

- Status: accepted
- Date: 2026-07-24
- Issue: #13

## Context

An EVTX record body is binary XML: a token stream that references a template
and carries an array of typed substitution values. Latent must decode records
that were **carved in isolation** — a standalone chunk or an orphan record that
is not part of a well-formed `.evtx` file — and, crucially, it must expose the
**typed substitution array even when the template is missing**, because that
array is the useful data an analyst needs when no template can be resolved
(confidence level L4).

The plan of record (issue #13) is to evaluate a proven existing decoder before
writing one. The primary candidate is the [`evtx`] crate.

## Evaluation of the `evtx` crate (0.12)

| Criterion | Finding |
|-----------|---------|
| License | `MIT OR Apache-2.0` — compatible with our Apache-2.0 distribution. |
| Maintenance | Actively maintained, widely used, fuzz-tested. |
| Decode an isolated chunk | Supported: `EvtxChunkData::new(..).parse(..)` parses a single 64 KiB chunk without the surrounding file. |
| Programmatic template access | Not in the public API. Templates live in `pub(crate)` internals. |
| **Raw substitution array when the template is absent** | **Not exposed.** The public surface renders a record to XML/JSON *through* its template (`SerializedEvtxRecord { data: String }`); a record whose template cannot be resolved does not yield its typed substitution values through any stable API. |
| Dependency surface | Pulls `chrono`, `quick-xml`, `encoding_rs`, `winstructs`, `serde(_json)`, … — a broad transitive tree that our strict `cargo-deny` license allow-list and `cargo-audit` gate must clear on every PR. |

The decisive point is the raw-substitution requirement: the one capability
Latent needs beyond typical library usage (raw typed substitutions for
template-less carved records) is exactly the one the crate does not expose. We
would have to fork it or depend on its internals to get there, which forfeits
the maintenance benefit of reuse and still leaves us owning the hard part.

## Decision

**Build a minimal, Latent-owned binary XML decoder**, focused on what the
recovery pipeline needs:

- the template reference a record carries (id + GUID, and whether its definition
  is inline or a back-reference into the chunk),
- the **typed substitution array**, decoded whether or not the template is
  present,
- the template definitions encountered while decoding, exposed with their
  identifiers for the resolution layer (`latent-template`),
- coverage of the binary XML value types (string, ansi string, the integer
  widths, real, bool, GUID, SID, FILETIME, SYSTEMTIME, size, hex, binary and
  nested binary XML).

The decoder lives behind the `latent_carve::evtx::binxml` API. Callers depend on
that API, not on the parsing details, so the decision can be revisited — for
example delegating full XML *rendering* to the `evtx` crate in a later
milestone — without touching them.

## Consequences

- We own a security-sensitive parser of hostile input. It is written with every
  length bounded before use, returns typed errors instead of panicking, and is
  covered by unit tests over synthetic streams and a fuzz target (wired into the
  central harness in #53).
- We keep the dependency tree small and the `cargo-deny` / `cargo-audit` surface
  minimal.
- Full byte-for-byte XML rendering is explicitly *not* a goal of this decoder;
  rendering and template resolution policy live in `latent-template` (#14 and
  later). Cross-tool validation against `EvtxECmd` runs once the validation
  corpus (#20) is available.

[`evtx`]: https://crates.io/crates/evtx
