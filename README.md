# hyper-socks-async

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)
[![Crates.io](https://img.shields.io/crates/v/hyper-socks-async.svg?maxAge=2592000)](https://crates.io/crates/hyper-socks-async)

Implements currently only socks V5 client with IPv4 but works with the current async hyper. 

Doesn't support authentication or IPv6. Make an issue if you would need it..

## Installation

```toml
# Cargo.toml
[dependencies]
hyper-socks-async = "0.1.0"
```

## Usage

Just configure `hyper::Client` with `Socksv5Connector`. Connector uses native-tls if url scheme is https.

Example below assumes you're running socks v5 compatible server on 127.0.0.1:9150. You can also run this example with `cargo run --example client` after cloning the project.

```rust
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
```

