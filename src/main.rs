use futures::{Future, IntoFuture, Stream};
use try_future::try_future;

fn tack_on<T, E, A>(src: Result<T, E>, add: A) -> Result<(T, A), (E, A)> {
    match src {
        Ok(value) => Ok((value, add)),
        Err(err) => Err((err, add)),
    }
}

enum Error {
    NoHost,
    InvalidHostValue,

    NoRedirectFound,

    Internal,
}

impl Error {
    pub fn as_response(&self) -> Result<hyper::Response<hyper::Body>, http::Error> {
        hyper::Response::builder()
            .status(match self {
                Error::NoHost | Error::InvalidHostValue => hyper::StatusCode::BAD_REQUEST,
                Error::NoRedirectFound => hyper::StatusCode::NOT_FOUND,
                Error::Internal => hyper::StatusCode::INTERNAL_SERVER_ERROR,
            })
            .body(
                match self {
                    Error::NoHost => "Missing Host header",
                    Error::InvalidHostValue => "Invalid Host header",
                    Error::NoRedirectFound => "No redirect found for that host",
                    Error::Internal => "Internal Server Error",
                }
                .into(),
            )
    }
}

fn flatten_result<T, E>(res: Result<Result<T, E>, E>) -> Result<T, E> {
    match res {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(err),
    }
}

fn handle_internal_error(err: &dyn std::fmt::Debug) -> Error {
    eprintln!("Internal error: {:?}", err);
    Error::Internal
}

type DbPool = bb8::Pool<bb8_postgres::PostgresConnectionManager<tokio_postgres::NoTls>>;

lazy_static::lazy_static! {
    static ref ALLOW_PROXY_ADDRESS: bool = match std::env::var("ALLOW_PROXY_ADDRESS").as_ref().map(|x| x.as_ref()) {
        Ok("1") => true,
        Ok("0") => false,
        Err(std::env::VarError::NotPresent) => false,
        Ok(_) => panic!("Invalid value for ALLOW_PROXY_ADDRESS"),
        Err(other) => panic!("Failed to read env value: {:?}", other),
    };
}

fn report_visit(
    id: i32,
    db_pool: DbPool,
    req: &hyper::Request<hyper::Body>,
    addr: std::net::SocketAddr,
) -> impl Future<Item = (), Error = ()> + Send {
    let uri_path = req.uri().path().to_owned();
    let user_agent = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());
    let mut ip_address = addr.ip().to_string();

    if *ALLOW_PROXY_ADDRESS {
        if let Some(value) = req.headers().get("X-Forwarded-For") {
            if let Ok(value) = value.to_str() {
                ip_address = value.to_owned();
            }
        }
    }

    db_pool.run(move |mut conn| {
        conn.prepare("INSERT INTO visits (redirect, tstamp, ip_address, user_agent, uri_path) VALUES ($1, localtimestamp, $2, $3, $4)")
            .then(|res| tack_on(res, conn))
            .and_then(move |(stmt, mut conn)| {
                conn.execute(&stmt, &[&id, &ip_address.to_string(), &user_agent, &uri_path])
                    .then(|res| tack_on(res, conn))
            })
    })
    .map_err(|err| eprintln!("Failed to report visit: {:?}", err))
        .map(|_| ())
}

fn handle_request(
    req: hyper::Request<hyper::Body>,
    db_pool: DbPool,
    ip_addr: std::net::SocketAddr,
) -> impl Future<Item = hyper::Response<hyper::Body>, Error = http::Error> + Send {
    println!("handle_request");
    req.headers()
        .get(hyper::header::HOST)
        .cloned()
        .ok_or(Error::NoHost)
        .into_future()
        .and_then(move |host| {
            let host = try_future!(host.to_str().map_err(|_| Error::InvalidHostValue)).to_owned();
            // Ok(hyper::Response::new(hyper::Body::from(host.to_owned())))
            //

            db_pool
                .run(move |mut conn| {
                    conn.prepare("SELECT id, destination, acme_token FROM redirects WHERE host=$1")
                        .then(move |res| match res {
                            Ok(stmt) => conn
                                .query(&stmt, &[&host])
                                .into_future()
                                .then(|res| match res {
                                    Ok((row, _)) => Ok((row, conn)),
                                    Err((err, _)) => Err((err, conn)),
                                })
                                .into(),
                            Err(err) => try_future!(Err((err, conn))),
                        })
                        .and_then(|(row, conn)| {
                            Ok((
                                row.ok_or(Error::NoRedirectFound),
                                conn,
                            ))
                        })
                })
                .map_err(|err| handle_internal_error(&err))
                .then(flatten_result)
                .and_then(move |row| {
                    let id: i32 = row.get(0);

                    const ACME_CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

                    let path = req.uri().path();
                    if path.len() > ACME_CHALLENGE_PATH_PREFIX.len() {
                        let req_token = &path[ACME_CHALLENGE_PATH_PREFIX.len()..];
                        let known_token: String = row.get(2);

                        if req_token == known_token {
                            return futures::future::Either::B(db_pool.run(move |mut conn| {
                                conn.prepare("SELECT acme_key_authorization FROM redirects WHERE id=$1")
                                    .then(|res| tack_on(res, conn))
                                    .and_then(move |(stmt, mut conn)| {
                                        conn.query(&stmt, &[&id])
                                            .into_future()
                                            .map(|(row, _)| row)
                                            .map_err(|(err, _)| err)
                                            .then(|res| tack_on(res, conn))
                                    })
                            })
                                                              .map_err(|err| handle_internal_error(&err))
                                              .and_then(|row| {
                                                  row.ok_or(Error::NoRedirectFound) // this shouldn't happen unless the redirect was deleted while being handled
                                              })
                                              .and_then(|row| {
                                                  let body: String = row.get(0);

                                                  hyper::Response::builder()
                                                      .status(hyper::StatusCode::OK)
                                                      .body(body.into())
                                                      .map_err(|err| handle_internal_error(&err))
                                              })
                                              );
                        }
                    }

                    let destination: String = row.get(1);

                    tokio::spawn(report_visit(id, db_pool, &req, ip_addr));

                    let body = format!("Redirecting to {}", destination);

                    futures::future::Either::A(hyper::Response::builder()
                        .status(hyper::StatusCode::MOVED_PERMANENTLY)
                        .header(hyper::header::LOCATION, destination)
                        .body(body.into())
                        .map_err(|err| handle_internal_error(&err))
                        .into_future())
                })
                .into()
        })
        .or_else(|err| err.as_response())
}

fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "4000".to_owned())
        .parse()
        .expect("Failed to parse port");
    let database_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    let tls_port: Option<u16> = std::env::var("TLS_PORT")
        .ok()
        .map(|value| value.parse().expect("Failed to parse TLS port"));

    tokio::run(futures::lazy(move || {
        bb8::Pool::builder()
            .build(bb8_postgres::PostgresConnectionManager::new(
                database_url,
                tokio_postgres::NoTls,
            ))
            .map_err(|err| panic!("Failed to connect to database: {:?}", err))
            .and_then(move |db_pool| {
                let make_service = {
                    let db_pool = db_pool.clone();
                    hyper::service::make_service_fn(
                        move |addr_stream: &hyper::server::conn::AddrStream| {
                            let db_pool = db_pool.clone();
                            let ip_addr = addr_stream.remote_addr();
                            hyper::service::service_fn(move |req| {
                                handle_request(req, db_pool.clone(), ip_addr)
                            })
                        },
                        )
                };

                let http_server = hyper::Server::bind(&std::net::SocketAddr::from((
                    std::net::Ipv6Addr::UNSPECIFIED,
                    port,
                )))
                .serve(make_service)
                .map_err(|err| panic!("Server execution failed: {:?}", err));

                let https_server = tls_port.map(|tls_port| {
                    struct CertResolver {
                        db_pool: DbPool,
                    }

                    impl CertResolver {
                        pub fn new(db_pool: DbPool) -> Self {
                            Self { db_pool }
                        }
                    }

                    impl tokio_rustls::rustls::ResolvesServerCert for CertResolver {
                        fn resolve(&self, server_name: Option<tokio_rustls::webpki::DNSNameRef>, _sigschemes: &[tokio_rustls::rustls::SignatureScheme]) -> Option<tokio_rustls::rustls::sign::CertifiedKey> {
                            match server_name {
                                None => None,
                                Some(host) => {
                                    // Unfortunately, this has to be synchronous because rustls
                                    // itself doesn't do async.
                                    let host_str: &str = host.into();
                                    let row = self.db_pool.run(|mut conn| {
                                        conn.prepare("SELECT tls_privkey, tls_cert FROM redirects WHERE host=$1")
                                            .then(|res| tack_on(res, conn))
                                            .and_then(|(stmt, mut conn)| {
                                                conn.query(&stmt, &[&host_str])
                                                    .into_future()
                                                    .map(|(row, _)| row)
                                                    .map_err(|(err, _)| err)
                                                    .then(|res| tack_on(res, conn))
                                            })
                                    })
                                    .map_err(|err| eprintln!("Failed retrieving TLS cert: {:?}", err))
                                    .wait()
                                        .ok()
                                        .and_then(|x| x);

                                    println!("row is {}, host is {}", row.is_some(), host_str);

                                    row.and_then(|row| {
                                        let privkey = {
                                            let privkey: Option<Vec<u8>> = row.get(0);

                                            let privkey = privkey.and_then(|privkey| {
                                                tokio_rustls::rustls::internal::pemfile::pkcs8_private_keys(&mut &privkey[..])
                                                    .map_err(|_| eprintln!("Failed to read TLS privkey for host {:?}", host))
                                                    .ok()
                                                    .and_then(|keys| keys.into_iter().next())
                                            });

                                            let privkey = privkey.and_then(|privkey| {
                                                tokio_rustls::rustls::sign::RSASigningKey::new(&privkey)
                                                    .map_err(|_| eprintln!("Failed to read TLS privkey (part 2) for host {:?}", host))
                                                    .ok()
                                            });

                                            privkey.map(|privkey| -> std::sync::Arc<Box<dyn tokio_rustls::rustls::sign::SigningKey>> {
                                                std::sync::Arc::new(Box::new(privkey))
                                            })
                                        };

                                        let certs = {
                                            let cert: Option<Vec<u8>> = row.get(1);

                                            cert.and_then(|cert| {
                                                tokio_rustls::rustls::internal::pemfile::certs(&mut &cert[..])
                                                    .map_err(|_| eprintln!("Failed to read TLS cert for host {:?}", host))
                                                    .ok()
                                            })
                                        };

                                        privkey.and_then(|privkey| {
                                            certs.map(|certs| (privkey, certs))
                                        })
                                            .map(|(privkey, certs)| {
                                                tokio_rustls::rustls::sign::CertifiedKey::new(certs, privkey)
                                            })
                                    })
                                }
                            }
                        }
                    }

                    let mut tls_config = tokio_rustls::rustls::ServerConfig::new(tokio_rustls::rustls::NoClientAuth::new());
                    tls_config.cert_resolver = std::sync::Arc::new(CertResolver::new(db_pool.clone()));

                    let tls_acceptor: tokio_rustls::TlsAcceptor = std::sync::Arc::new(tls_config).into();
                    tokio::net::TcpListener::bind(&std::net::SocketAddr::from((
                                std::net::Ipv6Addr::UNSPECIFIED,
                                tls_port
                            )))
                        .expect("Failed to initialize secure server")
                        .incoming()
                        .for_each(move |stream| {
                            let tls_acceptor = tls_acceptor.clone();
                            let ip_addr = stream.peer_addr()?;
                            tokio::spawn(blocking_future::BlockingFuture::new(move || tls_acceptor.accept(stream).wait())
                                         .map_err(|e| format!("Failed to accept TLS connection: {:?}", e))
                                         .and_then(|x| x.map_err(|e| format!("Failed to accept TLS connection: {:?}", e)))
                                         .map_err(|e| eprintln!("{}", e))
                                         .and_then({
                                             let db_pool = db_pool.clone();
                                             move |stream| {
                                                 hyper::server::conn::Http::new().serve_connection(stream, hyper::service::service_fn(move |req| {
                                                     handle_request(req, db_pool.clone(), ip_addr)
                                                 }))
                                                 .map_err(|e| eprintln!("Failed serving TLS connection: {:?}", e))
                                             }
                                         }));

                            Ok(())
                        })
                    .map_err(|err| panic!("Failed running TLS server: {:?}", err))
                });

                match https_server {
                    None => futures::future::Either::A(http_server),
                    Some(https_server) => futures::future::Either::B(http_server.join(https_server).map(|_| ()))
                }
            })
    }))
}
