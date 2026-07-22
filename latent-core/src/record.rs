//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Normalized record model and provenance
//!

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::confidence::{Confidence, Method};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    pub fn new(when: OffsetDateTime) -> Self {
        Timestamp(when.to_offset(time::UtcOffset::UTC))
    }

    pub fn get(self) -> OffsetDateTime {
        self.0
    }
}

impl From<OffsetDateTime> for Timestamp {
    fn from(when: OffsetDateTime) -> Self {
        Timestamp::new(when)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.format(&Rfc3339).map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        OffsetDateTime::parse(&text, &Rfc3339)
            .map(Timestamp::new)
            .map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub confidence: Confidence,
    pub method: Method,
    pub source_offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    pub reconstructed: bool,
}

impl Provenance {
    pub fn new(confidence: Confidence, method: Method, source_offset: u64) -> Self {
        Provenance {
            confidence,
            method,
            source_offset,
            source_hash: None,
            template_id: None,
            raw_sha256: None,
            record_id: None,
            channel: None,
            reconstructed: confidence.is_reconstructed(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    #[serde(
        rename = "@timestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub timestamp: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub event: Event,
    #[serde(default, skip_serializing_if = "is_default")]
    pub host: Host,
    #[serde(default, skip_serializing_if = "is_default")]
    pub user: User,
    #[serde(default, skip_serializing_if = "is_default")]
    pub process: Process,
    #[serde(default, skip_serializing_if = "is_default")]
    pub source: Source,
    pub latent: Provenance,
}

impl Record {
    pub fn new(latent: Provenance) -> Self {
        Record {
            timestamp: None,
            event: Event::default(),
            host: Host::default(),
            user: User::default(),
            process: Process::default(),
            source: Source::default(),
            latent,
        }
    }

    pub fn is_reconstructed(&self) -> bool {
        self.latent.reconstructed
    }
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample() -> Record {
        let mut r = Record::new(Provenance::new(
            Confidence::L1LocalTemplate,
            Method::SameSource,
            4096,
        ));
        r.timestamp = Some(datetime!(2024-03-01 12:30:00 UTC).into());
        r.event.code = Some("4624".into());
        r.event.provider = Some("Microsoft-Windows-Security-Auditing".into());
        r.host.name = Some("dc01".into());
        r.user.name = Some("svc_backup".into());
        r.latent.channel = Some("Security".into());
        r.latent.record_id = Some(918273);
        r
    }

    #[test]
    fn round_trips() {
        let r = sample();
        let back: Record = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn timestamp_first_latent_last_ecs_names() {
        let json = serde_json::to_string(&sample()).unwrap();
        let ts = json.find("@timestamp").unwrap();
        let event = json.find("\"event\"").unwrap();
        let latent = json.find("\"latent\"").unwrap();
        assert!(ts < event && event < latent);
    }

    #[test]
    fn empty_groups_disappear_but_latent_stays() {
        let json = serde_json::to_string(&Record::new(Provenance::new(
            Confidence::L4Raw,
            Method::RawOnly,
            0,
        )))
        .unwrap();
        assert!(!json.contains("\"host\""));
        assert!(!json.contains("\"event\""));
        assert!(json.contains("\"latent\""));
        assert!(json.contains("\"reconstructed\":true"));
    }

    #[test]
    fn a_plus_two_offset_lands_on_utc() {
        let json =
            serde_json::to_string(&Timestamp::new(datetime!(2024-03-01 14:30:00 +2))).unwrap();
        assert_eq!(json, "\"2024-03-01T12:30:00Z\"");
    }

    #[test]
    fn reconstructed_flag_follows_the_level() {
        assert!(!Provenance::new(Confidence::L0Intact, Method::LocalTemplate, 0).reconstructed);
        assert!(
            Provenance::new(Confidence::L3Structural, Method::StructuralInference, 0).reconstructed
        );
    }
}
