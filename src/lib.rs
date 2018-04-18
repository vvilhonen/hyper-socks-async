extern crate futures;
extern crate byteorder;
extern crate hyper;
extern crate hyper_tls;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_service;
extern crate native_tls;
extern crate tokio_tls;

use hyper_tls::MaybeHttpsStream;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_io::io::{write_all, read_exact};
use tokio_service::Service;
use futures::{Future, IntoFuture};
use std::io::{self, Error, ErrorKind, Write};
use std::net::SocketAddr;
use byteorder::{BigEndian, WriteBytesExt};
use native_tls::TlsConnector;
use tokio_tls::TlsConnectorExt;

pub struct Socksv5Connector {
    handle: Handle,
    proxy_addr: SocketAddr,
    creds: Option<(Vec<u8>, Vec<u8>)>,
}

impl Socksv5Connector {
    pub fn new(handle: &Handle, proxy_addr: SocketAddr) -> Socksv5Connector {
        Socksv5Connector {
            handle: handle.clone(),
            proxy_addr,
            creds: None
        }
    }

    pub fn with_creds(mut self, creds: &(&str, &str)) -> io::Result<Socksv5Connector> {
        let &(ref username, ref password) = creds;
        let u = username.as_bytes();
        let p = password.as_bytes();
        if u.len() > 255 || p.len() > 255 {
            Err(Error::new(ErrorKind::Other, "invalid credentials"))
        } else {
            self.creds = Some((u.to_vec(), p.to_vec()));
            Ok(self)
        }
    }

    pub fn with_creds_binary(mut self, creds: &(Vec<u8>, Vec<u8>)) -> io::Result<Socksv5Connector> {
        let &(ref username, ref password) = creds;
        if username.len() > 255 || password.len() > 255 {
            Err(Error::new(ErrorKind::Other, "invalid credentials"))
        } else {
            self.creds = Some((username.to_vec(), password.to_vec()));
            Ok(self)
        }
    }
}

impl Service for Socksv5Connector {
    type Request = hyper::Uri;
    type Response = MaybeHttpsStream<TcpStream>;
    type Error = io::Error;
    type Future = Box<Future<Item=Self::Response, Error=Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        let creds = self.creds.clone();
        Box::new(TcpStream::connect(&self.proxy_addr, &self.handle)
            .and_then(move |socket| do_handshake(socket, req, creds)))
    }
}

type HandshakeFuture<T> = Box<Future<Item=T, Error=Error>>;

fn auth_negotiation(socket: TcpStream, creds: Option<(Vec<u8>, Vec<u8>)>) -> HandshakeFuture<TcpStream> {
    let (username, password) = creds.unwrap();
    let mut creds_msg: Vec<u8> = Vec::with_capacity(username.len() + password.len() + 3);
    creds_msg.push(1);
    creds_msg.push(username.len() as u8);
    creds_msg.extend_from_slice(&username);
    creds_msg.push(password.len() as u8);
    creds_msg.extend_from_slice(&password);
    Box::new(write_all(socket, creds_msg)
        .and_then( |(socket, _)| read_exact(socket, [0;2]))
        .and_then( |(socket, resp)| {
            if resp[0] == 1 && resp[1] == 0 {
                Ok(socket)
            } else {
                Err(Error::new(ErrorKind::InvalidData, "unauthorized"))
            }
        }))
}

fn answer_hello(socket: TcpStream, response: [u8;2], creds: Option<(Vec<u8>, Vec<u8>)>) -> HandshakeFuture<TcpStream> {
    if response[0] == 5 && response[1] == 0 {
        Box::new(write_all(socket, [5, 1, 0]).map( |(socket, _)| socket))
    } else if response[0] == 5 && response[1] == 2 && creds.is_some() {
        Box::new(auth_negotiation(socket, creds)
            .and_then( |socket| write_all(socket, [5, 1, 0]).map( |(socket, _)| socket)))
    } else {
        Box::new(Err(Error::new(ErrorKind::InvalidData, "wrong response from socks server")).into_future())
    }
}

fn write_addr(socket: TcpStream, req: hyper::Uri) -> HandshakeFuture<TcpStream> {
    let host = match req.host() {
        Some(host) => host,
        _ => return Box::new(Err(Error::new(ErrorKind::InvalidInput, "host missing")).into_future())
    };

    if host.len() > u8::max_value() as usize {
        return Box::new(Err(Error::new(ErrorKind::InvalidInput, "Host too long")).into_future());
    }

    let port = match req.port() {
        Some(port) => port,
        _ if req.scheme() == Some("https") => 443,
        _ if req.scheme() == Some("http") => 80,
        _ => return Box::new(Err(Error::new(ErrorKind::InvalidInput, "Supports only http/https")).into_future())
    };

    let mut packet = Vec::new();

    packet.write_u8(3).unwrap();
    packet.write_u8(host.len() as u8).unwrap();
    packet.write_all(host.as_bytes()).unwrap();
    packet.write_u16::<BigEndian>(port).unwrap();

    Box::new(write_all(socket, packet).map( |(socket, _)| socket))
}

fn read_response(socket: TcpStream, response: [u8;3]) -> HandshakeFuture<TcpStream> {
    if response[0] != 5 {
        return Box::new(Err(Error::new(ErrorKind::Other, "invalid version")).into_future());
    }
    match response[1] {
        0 => {},
        1 => return Box::new(Err(Error::new(ErrorKind::Other, "general SOCKS server failure")).into_future()),
        2 => return Box::new(Err(Error::new(ErrorKind::Other, "connection not allowed by ruleset")).into_future()),
        3 => return Box::new(Err(Error::new(ErrorKind::Other, "network unreachable")).into_future()),
        4 => return Box::new(Err(Error::new(ErrorKind::Other, "host unreachable")).into_future()),
        5 => return Box::new(Err(Error::new(ErrorKind::Other, "connection refused")).into_future()),
        6 => return Box::new(Err(Error::new(ErrorKind::Other, "TTL expired")).into_future()),
        7 => return Box::new(Err(Error::new(ErrorKind::Other, "command not supported")).into_future()),
        8 => return Box::new(Err(Error::new(ErrorKind::Other, "address kind not supported")).into_future()),
        _ => return Box::new(Err(Error::new(ErrorKind::Other, "unknown error")).into_future()),
    };

    if response[2] != 0 {
        return Box::new(Err(Error::new(ErrorKind::InvalidData, "invalid reserved byt")).into_future())
    }

    Box::new(read_exact(socket, [0;1])
        .and_then( |(socket, response)| {
            match response[0] {
                1 => read_exact(socket, [0;6]),
                _ => unimplemented!()
            }
        })
        .map( |(socket, _)| socket))
}


fn do_handshake(socket: TcpStream, req: hyper::Uri, creds: Option<(Vec<u8>, Vec<u8>)>) -> HandshakeFuture<MaybeHttpsStream<TcpStream>> {
    let is_https = req.scheme() == Some("https");
    let host = match req.host() {
        Some(host) => host.to_string(),
        _ => return Box::new(Err(Error::new(ErrorKind::InvalidInput, "Missing host")).into_future())
    };

    let method: u8 = creds.clone().map(|_| 2).unwrap_or(0);
    let established = write_all(socket, [5, 1, method])
        .and_then( |(socket, _)| read_exact(socket, [0;2]))
        .and_then( |(socket, response)| answer_hello(socket, response, creds))
        .and_then(move |socket| write_addr(socket, req))
        .and_then( |socket|  read_exact(socket, [0;3]))
        .and_then( |(socket, response)| read_response(socket, response));
    if is_https {
        Box::new(established.and_then(move |socket| {
            let tls = TlsConnector::builder().unwrap().build().unwrap();
            tls.connect_async(&host, socket)
                .map_err( |err| Error::new(ErrorKind::Other, err))
                .map( |socket| MaybeHttpsStream::Https(socket))
        }))
    } else {
        Box::new(established.map( |socket| MaybeHttpsStream::Http(socket)))
    }
}
