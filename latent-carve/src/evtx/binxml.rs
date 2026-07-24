//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! EVTX binary XML decoder: template references and typed substitution arrays
//!
//! A Latent-owned decoder (see docs/adr/0001-evtx-binxml-decoder.md). It does
//! not render XML; it extracts the two things the recovery pipeline needs from a
//! record body: the template it references, and its typed substitution array —
//! the latter even when the template itself is missing, which is the whole point
//! for carved, template-less records.
//!
//! Every length read from the stream is bounded against the buffer before it
//! indexes, slices or allocates. Malformed input yields a [`DecodeError`], never
//! a panic.

use thiserror::Error;

use super::format::{RECORD_HEADER_SIZE, RECORD_MAGIC};

/// Binary XML fragment header token that opens a record body.
const TOKEN_FRAGMENT_HEADER: u8 = 0x0f;
/// Template instance token.
const TOKEN_TEMPLATE_INSTANCE: u8 = 0x0c;
/// Length of a template instance's fixed header (token, version, id, offset).
const TEMPLATE_INSTANCE_HEADER: usize = 10;
/// Length of an inline template definition's fixed header (next offset, GUID,
/// data size) that precedes its binary XML body.
const TEMPLATE_DEF_HEADER: usize = 24;

/// What went wrong while decoding a record body. Any of these is a clean,
/// counted failure — the decoder never panics on hostile input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("record is truncated: needed {needed} bytes at offset {at}, buffer holds {len}")]
    Truncated {
        at: usize,
        needed: usize,
        len: usize,
    },
    #[error("not an event record (bad magic)")]
    NotARecord,
    #[error("record size {size} is out of bounds (buffer holds {len})")]
    BadRecordSize { size: usize, len: usize },
    #[error("substitution count {count} exceeds the sane bound {max}")]
    TooManySubstitutions { count: u32, max: u32 },
    #[error("malformed binary XML: {0}")]
    Malformed(String),
}

/// A value carried by a substitution slot, decoded per its binary XML type.
///
/// Types the decoder does not special-case are preserved as [`Value::Raw`] with
/// their type byte and bytes intact, so no information is lost.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    String(String),
    AnsiString(String),
    Int8(i8),
    UInt8(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Real32(f32),
    Real64(f64),
    Bool(bool),
    Binary(Vec<u8>),
    Guid(String),
    SizeT(u64),
    FileTime(u64),
    SystemTime(SystemTime),
    Sid(String),
    HexInt32(u32),
    HexInt64(u64),
    /// Nested binary XML, kept as raw bytes.
    BinXml(Vec<u8>),
    /// A value type the decoder does not decode further; bytes preserved.
    Raw {
        ty: u8,
        bytes: Vec<u8>,
    },
}

/// A decoded SYSTEMTIME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

/// One entry of a record's substitution array.
#[derive(Debug, Clone, PartialEq)]
pub struct Substitution {
    /// Position of the slot in the array.
    pub index: usize,
    /// The binary XML value type byte, as found in the descriptor.
    pub ty: u8,
    /// Whether the slot was an optional (conditional) substitution.
    pub optional: bool,
    /// The decoded value.
    pub value: Value,
}

/// The template a record references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateRef {
    pub id: u32,
    pub guid: [u8; 16],
    /// Chunk offset of the template definition data.
    pub definition_offset: u32,
    /// Whether the definition was written inline right after the reference.
    pub inline: bool,
}

/// A template definition encountered while decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateDef {
    pub id: u32,
    pub guid: [u8; 16],
    /// Offset within the containing buffer where the definition's body starts.
    pub body_offset: usize,
    /// The template's own binary XML body (the element structure).
    pub binxml: Vec<u8>,
}

/// The outcome of decoding one record body.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DecodedRecord {
    /// The record identifier from the record header.
    pub record_id: u64,
    /// The FILETIME from the record header.
    pub filetime: u64,
    /// The template the record references, if it uses one.
    pub template: Option<TemplateRef>,
    /// The typed substitution array; present even when `template` is `None` or
    /// its definition could not be located.
    pub substitutions: Vec<Substitution>,
    /// Template definitions found inline while decoding, for the resolver.
    pub template_defs: Vec<TemplateDef>,
}

/// A hard ceiling on the substitution count, to reject a corrupt length before
/// allocating. Real records have at most a few dozen substitutions.
const MAX_SUBSTITUTIONS: u32 = 4096;

/// A bounded, forward-only reader over a byte buffer between `pos` and `end`.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], start: usize, end: usize) -> Self {
        Reader {
            data,
            pos: start,
            end,
        }
    }

    fn remaining(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    fn need(&self, n: usize) -> Result<(), DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated {
                at: self.pos,
                needed: n,
                len: self.end,
            });
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        self.need(n)?;
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn peek_u8(&self) -> Option<u8> {
        (self.remaining() >= 1).then(|| self.data[self.pos])
    }
}

/// Decode the record whose header starts at `record_offset` within `buffer`.
///
/// When `chunk_context` is true, `buffer` is a whole chunk and offsets embedded
/// in the stream are interpreted against it, so an inline template definition is
/// recognised exactly. When false, `buffer` is a standalone (orphan) record and
/// the inline/back-reference distinction is made heuristically; the substitution
/// array is still recovered in both cases.
pub fn decode_record(
    buffer: &[u8],
    record_offset: usize,
    chunk_context: bool,
) -> Result<DecodedRecord, DecodeError> {
    let rec = buffer.get(record_offset..).ok_or(DecodeError::Truncated {
        at: record_offset,
        needed: RECORD_HEADER_SIZE + 4,
        len: buffer.len(),
    })?;
    if rec.len() < RECORD_HEADER_SIZE + 4 {
        return Err(DecodeError::Truncated {
            at: record_offset,
            needed: RECORD_HEADER_SIZE + 4,
            len: buffer.len(),
        });
    }
    if &rec[..4] != RECORD_MAGIC {
        return Err(DecodeError::NotARecord);
    }
    let size = u32::from_le_bytes(rec[4..8].try_into().unwrap()) as usize;
    if size < RECORD_HEADER_SIZE + 4 || size > rec.len() {
        return Err(DecodeError::BadRecordSize {
            size,
            len: rec.len(),
        });
    }
    let record_id = u64::from_le_bytes(rec[8..16].try_into().unwrap());
    let filetime = u64::from_le_bytes(rec[16..24].try_into().unwrap());

    let body_start = record_offset + RECORD_HEADER_SIZE;
    let body_end = record_offset + size - 4; // exclude the trailing size copy

    let mut out = DecodedRecord {
        record_id,
        filetime,
        ..Default::default()
    };

    let mut r = Reader::new(buffer, body_start, body_end);
    skip_fragment_header(&mut r)?;

    // A record may open directly with a template instance, or not use one.
    if r.peek_u8() == Some(TOKEN_TEMPLATE_INSTANCE) {
        decode_template_instance(&mut r, chunk_context, &mut out)?;
    }

    Ok(out)
}

/// Skip the optional 4-byte fragment header (`0x0f major minor flags`).
fn skip_fragment_header(r: &mut Reader) -> Result<(), DecodeError> {
    if r.peek_u8() == Some(TOKEN_FRAGMENT_HEADER) {
        r.take(4)?;
    }
    Ok(())
}

fn decode_template_instance(
    r: &mut Reader,
    chunk_context: bool,
    out: &mut DecodedRecord,
) -> Result<(), DecodeError> {
    let instance_start = r.pos;
    let token = r.u8()?;
    debug_assert_eq!(token, TOKEN_TEMPLATE_INSTANCE);
    let _version = r.u8()?;
    let id = r.u32()?;
    let definition_offset = r.u32()?;

    // Position right after the 10-byte instance header.
    let after_header = instance_start + TEMPLATE_INSTANCE_HEADER;

    // Decide whether the template definition is written inline here.
    let inline = if chunk_context {
        definition_offset as usize == after_header
    } else {
        looks_like_inline_definition(r)
    };

    let mut guid = [0u8; 16];
    if inline {
        // Inline definition: next offset (4), GUID (16), data size (4), body.
        let _next = r.u32()?;
        guid.copy_from_slice(r.take(16)?);
        let data_size = r.u32()? as usize;
        let body_offset = r.pos;
        let binxml = r.take(data_size)?.to_vec();
        out.template_defs.push(TemplateDef {
            id,
            guid,
            body_offset,
            binxml,
        });
    }

    out.template = Some(TemplateRef {
        id,
        guid,
        definition_offset,
        inline,
    });

    // Whether inline or a back-reference, the substitution array follows.
    decode_substitution_array(r, out)?;
    Ok(())
}

/// Heuristic for orphan records: peek at whether a coherent inline template
/// definition follows the instance header. Does not consume input.
fn looks_like_inline_definition(r: &Reader) -> bool {
    // next(4) + guid(16) + data_size(4) = 24 bytes header, then data_size bytes.
    if r.remaining() < TEMPLATE_DEF_HEADER {
        return false;
    }
    let base = r.pos;
    let data_size = u32::from_le_bytes(r.data[base + 20..base + 24].try_into().unwrap()) as usize;
    // A plausible definition fits within the remaining body and is non-empty.
    data_size > 0 && data_size <= r.remaining().saturating_sub(TEMPLATE_DEF_HEADER)
}

fn decode_substitution_array(r: &mut Reader, out: &mut DecodedRecord) -> Result<(), DecodeError> {
    if r.remaining() < 4 {
        // No substitution array present; that is allowed.
        return Ok(());
    }
    let count = r.u32()?;
    if count > MAX_SUBSTITUTIONS {
        return Err(DecodeError::TooManySubstitutions {
            count,
            max: MAX_SUBSTITUTIONS,
        });
    }
    let count = count as usize;

    // Read the descriptors: size (u16), type (u8), unknown (u8).
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        let size = r.u16()? as usize;
        let ty = r.u8()?;
        let _unknown = r.u8()?;
        descriptors.push((size, ty));
    }

    // Then the values, each exactly `size` bytes.
    out.substitutions.reserve(count);
    for (index, (size, ty)) in descriptors.into_iter().enumerate() {
        let bytes = r.take(size)?;
        let optional = false; // array substitutions are not conditional here
        let value = decode_value(ty, bytes);
        out.substitutions.push(Substitution {
            index,
            ty,
            optional,
            value,
        });
    }
    Ok(())
}

/// Decode one substitution value. `bytes` is exactly the slot's declared size,
/// already bounded by the caller; this function never reads past it.
fn decode_value(ty: u8, bytes: &[u8]) -> Value {
    // The 0x80 bit marks an array of the base type; keep those raw for now.
    if ty & 0x80 != 0 {
        return Value::Raw {
            ty,
            bytes: bytes.to_vec(),
        };
    }
    match ty {
        0x00 => Value::Null,
        0x01 => Value::String(utf16le(bytes)),
        0x02 => Value::AnsiString(String::from_utf8_lossy(bytes).into_owned()),
        0x03 => bytes
            .first()
            .map(|&b| Value::Int8(b as i8))
            .unwrap_or(Value::Null),
        0x04 => bytes
            .first()
            .map(|&b| Value::UInt8(b))
            .unwrap_or(Value::Null),
        0x05 => le_int(bytes, 2).map(|v| Value::Int16(v as i16)),
        0x06 => le_int(bytes, 2).map(|v| Value::UInt16(v as u16)),
        0x07 => le_int(bytes, 4).map(|v| Value::Int32(v as i32)),
        0x08 => le_int(bytes, 4).map(|v| Value::UInt32(v as u32)),
        0x09 => le_int(bytes, 8).map(|v| Value::Int64(v as i64)),
        0x0a => le_int(bytes, 8).map(Value::UInt64),
        0x0b => {
            if bytes.len() >= 4 {
                Value::Real32(f32::from_le_bytes(bytes[..4].try_into().unwrap()))
            } else {
                Value::Null
            }
        }
        0x0c => {
            if bytes.len() >= 8 {
                Value::Real64(f64::from_le_bytes(bytes[..8].try_into().unwrap()))
            } else {
                Value::Null
            }
        }
        0x0d => le_int(bytes, 4).map(|v| Value::Bool(v != 0)),
        0x0e => Value::Binary(bytes.to_vec()),
        0x0f => guid_string(bytes)
            .map(Value::Guid)
            .unwrap_or_else(|| raw(ty, bytes)),
        0x10 => le_int(bytes, bytes.len().min(8)).map(Value::SizeT),
        0x11 => le_int(bytes, 8).map(Value::FileTime),
        0x12 => system_time(bytes)
            .map(Value::SystemTime)
            .unwrap_or_else(|| raw(ty, bytes)),
        0x13 => sid_string(bytes)
            .map(Value::Sid)
            .unwrap_or_else(|| raw(ty, bytes)),
        0x14 => le_int(bytes, 4).map(|v| Value::HexInt32(v as u32)),
        0x15 => le_int(bytes, 8).map(Value::HexInt64),
        0x21 => Value::BinXml(bytes.to_vec()),
        _ => raw(ty, bytes),
    }
}

fn raw(ty: u8, bytes: &[u8]) -> Value {
    Value::Raw {
        ty,
        bytes: bytes.to_vec(),
    }
}

/// Read a little-endian unsigned integer of `width` bytes, zero-extended; `Null`
/// helper closure result if the slice is too short. Returned via a small wrapper
/// so callers can map into the right `Value`.
fn le_int(bytes: &[u8], width: usize) -> IntResult {
    if width == 0 || bytes.len() < width {
        return IntResult(None);
    }
    let mut v = 0u64;
    for (i, &b) in bytes[..width].iter().enumerate() {
        v |= (b as u64) << (8 * i);
    }
    IntResult(Some(v))
}

/// Wrapper enabling `le_int(..).map(Value::UInt32)`-style use with a `Null`
/// fallback for a short slice.
struct IntResult(Option<u64>);

impl IntResult {
    fn map(self, f: impl FnOnce(u64) -> Value) -> Value {
        match self.0 {
            Some(v) => f(v),
            None => Value::Null,
        }
    }
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut s = String::from_utf16_lossy(&units);
    // EVTX strings are not always NUL-terminated, but trim a trailing NUL if any.
    while s.ends_with('\0') {
        s.pop();
    }
    s
}

fn guid_string(b: &[u8]) -> Option<String> {
    if b.len() < 16 {
        return None;
    }
    Some(format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    ))
}

fn system_time(b: &[u8]) -> Option<SystemTime> {
    if b.len() < 16 {
        return None;
    }
    let f = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
    Some(SystemTime {
        year: f(0),
        month: f(2),
        day_of_week: f(4),
        day: f(6),
        hour: f(8),
        minute: f(10),
        second: f(12),
        milliseconds: f(14),
    })
}

/// Format a binary SID as `S-1-<authority>-<sub>-<sub>...`.
fn sid_string(b: &[u8]) -> Option<String> {
    if b.len() < 8 {
        return None;
    }
    let revision = b[0];
    let sub_count = b[1] as usize;
    let authority = ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) << 8)
        | (b[7] as u64);
    // Bound the sub-authority count against the slice before reading.
    if b.len() < 8 + sub_count * 4 {
        return None;
    }
    let mut s = format!("S-{revision}-{authority}");
    for i in 0..sub_count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Synthetic binary XML builders -------------------------------------

    /// Wrap a binary XML body into a full event record (header + body + tail).
    fn record(record_id: u64, filetime: u64, body: &[u8]) -> Vec<u8> {
        let mut size = RECORD_HEADER_SIZE + body.len() + 4;
        size = size.div_ceil(8) * 8;
        let mut rec = vec![0u8; size];
        rec[..4].copy_from_slice(RECORD_MAGIC);
        rec[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        rec[8..16].copy_from_slice(&record_id.to_le_bytes());
        rec[16..24].copy_from_slice(&filetime.to_le_bytes());
        rec[24..24 + body.len()].copy_from_slice(body);
        rec[size - 4..].copy_from_slice(&(size as u32).to_le_bytes());
        rec
    }

    fn descriptor(size: u16, ty: u8) -> [u8; 4] {
        let mut d = [0u8; 4];
        d[..2].copy_from_slice(&size.to_le_bytes());
        d[2] = ty;
        d
    }

    /// A body: fragment header, a back-referenced template instance, then a
    /// substitution array. `def_offset` is the (back-reference) chunk offset.
    fn body_referenced(id: u32, def_offset: u32, subs: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![TOKEN_FRAGMENT_HEADER, 0x01, 0x01, 0x00];
        b.push(TOKEN_TEMPLATE_INSTANCE);
        b.push(0x01);
        b.extend_from_slice(&id.to_le_bytes());
        b.extend_from_slice(&def_offset.to_le_bytes());
        // substitution array
        b.extend_from_slice(&(subs.len() as u32).to_le_bytes());
        for (ty, v) in subs {
            b.extend_from_slice(&descriptor(v.len() as u16, *ty));
        }
        for (_, v) in subs {
            b.extend_from_slice(v);
        }
        b
    }

    fn u16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn decodes_substitutions_without_a_template_definition() {
        // A back-reference (def offset 0): the definition is elsewhere/gone, but
        // the substitution array must still decode.
        let subs = vec![
            (0x08u8, 4660u32.to_le_bytes().to_vec()), // UInt32 = 0x1234
            (0x01u8, u16le("Security")),              // String
            (0x0au8, 42u64.to_le_bytes().to_vec()),   // UInt64
        ];
        let body = body_referenced(7, 0, &subs);
        let rec = record(1, 133_000_000_000_000_000, &body);

        let decoded = decode_record(&rec, 0, false).unwrap();
        assert_eq!(decoded.record_id, 1);
        assert_eq!(decoded.template.unwrap().id, 7);
        assert!(!decoded.template.unwrap().inline);
        assert_eq!(decoded.substitutions.len(), 3);
        assert_eq!(decoded.substitutions[0].value, Value::UInt32(0x1234));
        assert_eq!(
            decoded.substitutions[1].value,
            Value::String("Security".into())
        );
        assert_eq!(decoded.substitutions[2].value, Value::UInt64(42));
    }

    #[test]
    fn decodes_an_inline_template_definition_with_chunk_context() {
        // Build a chunk-like buffer: the record sits at a known offset so the
        // inline definition's offset field can point exactly at itself.
        let id = 99u32;
        let template_body = vec![0xAAu8; 12];
        let subs = [(0x08u8, 1u32.to_le_bytes().to_vec())];

        // Assemble the body with an inline definition. Compute the definition
        // offset once we know where the record lands in the buffer.
        let record_offset = 512usize;
        // Instance header is 10 bytes; body starts after the 4-byte fragment
        // header, so the definition begins at:
        let def_offset = record_offset + RECORD_HEADER_SIZE + 4 + TEMPLATE_INSTANCE_HEADER;

        let mut body = vec![TOKEN_FRAGMENT_HEADER, 0x01, 0x01, 0x00];
        body.push(TOKEN_TEMPLATE_INSTANCE);
        body.push(0x01);
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&(def_offset as u32).to_le_bytes());
        // inline definition: next(4), guid(16), data_size(4), body
        body.extend_from_slice(&0u32.to_le_bytes());
        let guid = [0x11u8; 16];
        body.extend_from_slice(&guid);
        body.extend_from_slice(&(template_body.len() as u32).to_le_bytes());
        body.extend_from_slice(&template_body);
        // substitution array
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&descriptor(4, 0x08));
        body.extend_from_slice(&subs[0].1);

        let rec = record(5, 133_000_000_000_000_000, &body);
        let mut buffer = vec![0u8; record_offset];
        buffer.extend_from_slice(&rec);

        let decoded = decode_record(&buffer, record_offset, true).unwrap();
        let tref = decoded.template.unwrap();
        assert!(tref.inline, "definition recognised as inline");
        assert_eq!(tref.id, 99);
        assert_eq!(decoded.template_defs.len(), 1);
        assert_eq!(decoded.template_defs[0].guid, guid);
        assert_eq!(decoded.template_defs[0].binxml, template_body);
        assert_eq!(decoded.substitutions[0].value, Value::UInt32(1));
    }

    #[test]
    fn decodes_the_documented_value_types() {
        let guid = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47,
            0x7d, 0xe4,
        ];
        // SID S-1-5-18
        let mut sid = vec![0x01, 0x01, 0, 0, 0, 0, 0, 0x05];
        sid.extend_from_slice(&18u32.to_le_bytes());
        let mut systime = Vec::new();
        for v in [2022u16, 3, 2, 15, 10, 30, 0, 500] {
            systime.extend_from_slice(&v.to_le_bytes());
        }
        let subs = vec![
            (0x00u8, vec![]),
            (0x03u8, vec![0xffu8]),                     // Int8 = -1
            (0x06u8, 300u16.to_le_bytes().to_vec()),    // UInt16
            (0x0du8, 1u32.to_le_bytes().to_vec()),      // Bool true
            (0x0fu8, guid.to_vec()),                    // Guid
            (0x11u8, 133u64.to_le_bytes().to_vec()),    // FileTime
            (0x12u8, systime),                          // SystemTime
            (0x13u8, sid),                              // Sid
            (0x14u8, 0xdeadu32.to_le_bytes().to_vec()), // HexInt32
        ];
        let body = body_referenced(1, 0, &subs);
        let rec = record(1, 133_000_000_000_000_000, &body);
        let d = decode_record(&rec, 0, false).unwrap();
        let v: Vec<&Value> = d.substitutions.iter().map(|s| &s.value).collect();
        assert_eq!(*v[0], Value::Null);
        assert_eq!(*v[1], Value::Int8(-1));
        assert_eq!(*v[2], Value::UInt16(300));
        assert_eq!(*v[3], Value::Bool(true));
        assert_eq!(
            *v[4],
            Value::Guid("12345678-1234-1234-8E79-3D69D8477DE4".into())
        );
        assert_eq!(*v[5], Value::FileTime(133));
        assert_eq!(
            *v[6],
            Value::SystemTime(SystemTime {
                year: 2022,
                month: 3,
                day_of_week: 2,
                day: 15,
                hour: 10,
                minute: 30,
                second: 0,
                milliseconds: 500
            })
        );
        assert_eq!(*v[7], Value::Sid("S-1-5-18".into()));
        assert_eq!(*v[8], Value::HexInt32(0xdead));
    }

    #[test]
    fn a_record_without_a_template_yields_no_substitutions() {
        // Body is a fragment header only, no template instance.
        let body = vec![TOKEN_FRAGMENT_HEADER, 0x01, 0x01, 0x00, 0x00];
        let rec = record(9, 133_000_000_000_000_000, &body);
        let d = decode_record(&rec, 0, false).unwrap();
        assert!(d.template.is_none());
        assert!(d.substitutions.is_empty());
    }

    #[test]
    fn a_truncated_substitution_value_is_an_error_not_a_panic() {
        // Declare a 100-byte value but provide far fewer bytes.
        let mut body = vec![TOKEN_FRAGMENT_HEADER, 0x01, 0x01, 0x00];
        body.push(TOKEN_TEMPLATE_INSTANCE);
        body.push(0x01);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes()); // one substitution
        body.extend_from_slice(&descriptor(100, 0x01)); // claims 100 bytes
        body.extend_from_slice(b"short"); // provides 5
        let rec = record(1, 133_000_000_000_000_000, &body);
        assert!(matches!(
            decode_record(&rec, 0, false),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn an_absurd_substitution_count_is_rejected_before_allocating() {
        let mut body = vec![TOKEN_FRAGMENT_HEADER, 0x01, 0x01, 0x00];
        body.push(TOKEN_TEMPLATE_INSTANCE);
        body.push(0x01);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // huge count
        let rec = record(1, 133_000_000_000_000_000, &body);
        assert!(matches!(
            decode_record(&rec, 0, false),
            Err(DecodeError::TooManySubstitutions { .. })
        ));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut x: u32 = 0xC0FF_EE00;
        for len in 0..600usize {
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *b = (x >> 24) as u8;
            }
            // With and without a valid-looking record magic at the front.
            let _ = decode_record(&buf, 0, false);
            let _ = decode_record(&buf, 0, true);
            if buf.len() >= 4 {
                buf[..4].copy_from_slice(RECORD_MAGIC);
                let _ = decode_record(&buf, 0, false);
                let _ = decode_record(&buf, 0, true);
            }
        }
    }
}
