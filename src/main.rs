#![allow(unused_imports)]
extern crate clap;
extern crate futures;
extern crate native_tls;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_tls;

use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;

use clap::{App, Arg, SubCommand};
use futures::Future;
use native_tls::{Protocol, TlsConnector};
use native_tls::backend::security_framework::TlsStreamExt;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use tokio_tls::TlsConnectorExt;
use openssl::x509::{X509, X509Name};

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

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let addr = format!("{}:443", url)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let mut builder = TlsConnector::builder().unwrap();
    builder
        .supported_protocols(&[Protocol::Tlsv10, Protocol::Tlsv11])
        .unwrap();
    let cx = builder.build().unwrap();
    let socket = TcpStream::connect(&addr, &handle);

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    println!("Value for matches: {:?}", url);

    let tls_handshake = socket.and_then(|socket| {
        let tls = cx.connect_async(url, socket);
        tls.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    });

    let http_request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", url);

    println!("http request\n {}", http_request);

    let request = tls_handshake.and_then(|socket| {
        println!(
            "Negotiated Protocol: {:?}",
            socket
                .get_ref()
                .raw_stream()
                .context()
                .negotiated_protocol_version()
        );
        println!(
            "Negotiated Cipher: {:?}",
            socket.get_ref().raw_stream().context().negotiated_cipher()
        );

        let num_certs = socket
            .get_ref()
            .raw_stream()
            .context()
            .peer_trust()
            .unwrap()
            .certificate_count();

        println!("Certificates present: {:?}", num_certs);

        println!("Certificates: ");
        for index in 0..num_certs {
            let current_certificate = socket
                .get_ref()
                .raw_stream()
                .context()
                .peer_trust()
                .unwrap()
                .certificate_at_index(index);
            println!("Certificate at index {} {:?}", index, current_certificate);

            let x509 = X509::from_der(current_certificate.unwrap().to_der().as_slice()).unwrap();
            println!("Not Before: {:}", x509.not_before());
            println!("Not After: {:}", x509.not_after());
        }

        tokio_io::io::write_all(socket, http_request.as_bytes())
    });

    let request_future =
        request.and_then(|(socket, _request)| tokio_io::io::read_to_end(socket, Vec::new()));

    let response = core.run(request_future);
    let (_socket, data) = response.unwrap();

    let mut response_string = String::from_utf8_lossy(&data).into_owned();
    let header_boundary = response_string.find("\r\n\r\n").unwrap();
    let response_body = response_string.split_off(header_boundary);

    println!("Header: {}", response_string);

    if matches.is_present("with-body") {
        println!("{}", response_body);
    }
}
