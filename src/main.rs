#![allow(unused_imports)]
extern crate ansi_term;
extern crate clap;
extern crate futures;
extern crate native_tls;
extern crate openssl;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_tls;

use std::io;
use std::io::BufRead;
use std::net::ToSocketAddrs;
use std::time::Instant;
use std::sync::Mutex;
use std::fmt::{Debug, Display};

mod response_log;

use response_log::{EventLog, SslCertificate};

use ansi_term::Colour;
use clap::{App, Arg, SubCommand};
use futures::Future;
use native_tls::{Protocol, TlsConnector};
use native_tls::backend::security_framework::TlsStreamExt;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use tokio_tls::TlsConnectorExt;
use openssl::x509::{X509, X509Name};

fn tls_protocol_from_string(s: &str) -> native_tls::Protocol {
    match s {
        "1" => Protocol::Tlsv10,
        "1.0" => Protocol::Tlsv10,
        "1.1" => Protocol::Tlsv11,
        "1.2" => Protocol::Tlsv12,
        _ => panic!("Unknown tls version"),
    }
}

fn debug_value<T: Debug>(label: &str, value: T) {
    println!("{}: {:?}", Colour::Cyan.paint(label), value);
}

fn display_value<T: Display>(label: &str, value: T) {
    println!("{}: {:}", Colour::Cyan.paint(label), value);
}

fn main() {
    let matches = App::new("Getso")
        .version("1.0")
        .author("Andrei Bocan")
        .about("Gets things from the internet")
        .arg(
            Arg::with_name("URL")
                .help("Sets the input file to use")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("with-body")
                .short("b")
                .long("with-body")
                .takes_value(false)
                .help("Display response body"),
        )
        .arg(
            Arg::with_name("tls-versions")
                .short("t")
                .long("tls")
                .takes_value(true)
                .multiple(true)
                .help("Specify tls version"),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .subcommand(
            SubCommand::with_name("get").arg(
                Arg::with_name("debug")
                    .short("d")
                    .help("print debug information verbosely"),
            ),
        )
        .get_matches();

    let url = matches.value_of("URL").unwrap();

    let tls_version_strings: Vec<&str> = matches.values_of("tls-versions").unwrap().collect();
    let tls_versions: Vec<native_tls::Protocol> = tls_version_strings
        .iter()
        .map(|x| tls_protocol_from_string(x))
        .collect();

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let addr = format!("{}:443", url)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let mut builder = TlsConnector::builder().unwrap();
    builder.supported_protocols(&tls_versions).unwrap();

    let cx = builder.build().unwrap();
    let start_time = Instant::now();
    let socket = TcpStream::connect(&addr, &handle);

    // Thing logs events, we're assuming the start event
    // has already been sent
    let event_log: Mutex<EventLog> = Mutex::new(EventLog::<String>::new());

    let tls_handshake = socket.and_then(|socket| {
        let tls = cx.connect_async(url, socket);
        event_log.lock().unwrap().add("Connection Established");
        println!(
            "[{}.{:03}] Connection established",
            start_time.elapsed().as_secs(),
            start_time.elapsed().subsec_nanos() / 1_000_000
        );
        tls.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    });

    let http_request = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url
    );

    println!("http request\n {}", http_request);

    let request = tls_handshake.and_then(|socket| {
        event_log.lock().unwrap().add("TLS Handshake");
        println!(
            "[{}.{:03}] TLS Handshake",
            start_time.elapsed().as_secs(),
            start_time.elapsed().subsec_nanos() / 1_000_000
        );

        debug_value(
            "Negotiated Protocol",
            socket
                .get_ref()
                .raw_stream()
                .context()
                .negotiated_protocol_version(),
        );

        debug_value(
            "Negotiated Cipher",
            socket.get_ref().raw_stream().context().negotiated_cipher(),
        );

        let num_certs = socket
            .get_ref()
            .raw_stream()
            .context()
            .peer_trust()
            .unwrap()
            .certificate_count();

        debug_value("Certificates present", num_certs);

        println!("{}: ", Colour::Yellow.paint("Certificates"));
        for index in 0..num_certs {
            let current_certificate = socket
                .get_ref()
                .raw_stream()
                .context()
                .peer_trust()
                .unwrap()
                .certificate_at_index(index)
                .unwrap();

            let x509 = X509::from_der(current_certificate.to_der().as_slice()).unwrap();

            println!(
                "Certificate {} {:?} {:?}",
                index + 1,
                x509.subject_name()
                    .entries_by_nid(openssl::nid::COMMONNAME)
                    .map(|x| x.data().as_utf8().ok().unwrap())
                    .collect::<Vec<openssl::string::OpensslString>>(),
                x509.subject_alt_names()
                    .map(|x| x.iter()
                        .map(|subject| String::from(subject.dnsname().unwrap()))
                        .collect::<Vec<String>>())
                    .unwrap_or(vec![])
            );
            display_value("Not Before", x509.not_before());
            display_value("Not After", x509.not_after());
            let certificate = SslCertificate::new(
                x509.subject_name()
                    .entries_by_nid(openssl::nid::COMMONNAME)
                    .map(|x| format!("{}", x.data().as_utf8().ok().unwrap()))
                    .collect::<Vec<String>>(),
                x509.subject_alt_names()
                    .map(|x| {
                        x.iter()
                            .map(|subject| String::from(subject.dnsname().unwrap()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or(vec![]),
                x509.not_after(),
                x509.not_before(),
            );
            println!("{}", serde_json::to_string(&certificate).unwrap());
        }

        tokio_io::io::write_all(socket, http_request.as_bytes())
    });

    let request_future = request.and_then(|(socket, _request)| {
        event_log.lock().unwrap().add("Reading Response");
        println!(
            "[{}.{:03}] Response",
            start_time.elapsed().as_secs(),
            start_time.elapsed().subsec_nanos() / 1_000_000
        );
        tokio_io::io::read_to_end(socket, Vec::new())
    });

    let response = core.run(request_future);
    let (_socket, data) = response.unwrap();

    event_log.lock().unwrap().add("Response fetched");
    println!(
        "[{}.{:03}] Response Fetched",
        start_time.elapsed().as_secs(),
        start_time.elapsed().subsec_nanos() / 1_000_000
    );

    let mut response_string = String::from_utf8_lossy(&data).into_owned();
    let header_boundary = response_string.find("\r\n\r\n").unwrap();
    let response_body = response_string.split_off(header_boundary);

    println!("Header: {}", response_string);

    if matches.is_present("with-body") {
        println!("{}", response_body);
    }

    println!("Event Log: {:?}", event_log.lock().unwrap().log);
}
