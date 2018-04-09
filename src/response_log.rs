use std::time::Instant;
use openssl::asn1::Asn1Time;
use openssl::string::OpensslString;
use std::fmt::Display;
use std::vec::Vec;

pub struct ResponseLog {
    events: EventLog,
}

#[derive(Debug)]
pub struct EventLog<T = String> {
    start_time: Instant,
    pub log: Vec<Event<T>>,
}

#[derive(Debug)]
pub struct Event<T> {
    seconds: u64,
    nanos: u32,
    description: String,
    metadata: Option<T>,
}

#[derive(Debug, Serialize)]
pub struct SslCertificate {
    pub subject_names: Vec<String>,
    pub subject_alt_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
}

impl SslCertificate {
    pub fn new<T: Display>(
        subject_names: Vec<String>,
        subject_alt_names: Vec<String>,
        not_before: &T,
        not_after: &T,
    ) -> SslCertificate {
        SslCertificate {
            subject_names: subject_names,
            subject_alt_names: subject_alt_names,
            not_before: format!("{:}", not_before),
            not_after: format!("{:}", not_after),
        }
    }
}

impl<T: Clone> EventLog<T> {
    pub fn new() -> EventLog {
        EventLog {
            log: Vec::new(),
            start_time: Instant::now(),
        }
    }

    pub fn add_with_metadata(&mut self, description: String, metadata: T) {
        let elapsed = self.start_time.elapsed();
        let mut event = Event {
            seconds: elapsed.as_secs(),
            nanos: elapsed.subsec_nanos(),
            description: description.clone(),
            metadata: Some(metadata.clone()),
        };
        self.log.push(event)
    }

    pub fn add(&mut self, description: &str) {
        let elapsed = self.start_time.elapsed();
        let mut event = Event {
            seconds: elapsed.as_secs(),
            nanos: elapsed.subsec_nanos(),
            description: description.to_string(),
            metadata: None,
        };
        self.log.push(event)
    }
}
