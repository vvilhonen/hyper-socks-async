extern crate futures;
extern crate hyper;
extern crate hyper_socks_async;
extern crate tokio_core;

use futures::Future;
use futures::stream::Stream;
use hyper::Client;
use hyper_socks_async::Socksv5Connector;
use std::net::{SocketAddrV4, SocketAddr, Ipv4Addr};

fn main() {
    let mut core = tokio_core::reactor::Core::new().unwrap();
    
    // Proxy running on 127.0.0.1:9150
    let proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9150));
    let client = Client::configure()
        .connector(Socksv5Connector::new(&core.handle(), proxy_addr))
        .build(&core.handle());

    // http://example.com or http://1.2.3.4 work as well
    let url = "https://ifconfig.co/json".parse::<hyper::Uri>().unwrap();
    let response_body = client.get(url)
        .and_then(|res| res.body().concat2());
    let bytes = core.run(response_body).expect("Request failed").to_vec();
    println!("Got: {}", String::from_utf8_lossy(&bytes));
}
