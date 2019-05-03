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

    InternalError,
}

impl Error {
    pub fn into_response(&self) -> Result<hyper::Response<hyper::Body>, http::Error> {
        hyper::Response::builder()
            .status(match self {
                Error::NoHost | Error::InvalidHostValue => hyper::StatusCode::BAD_REQUEST,
                Error::NoRedirectFound => hyper::StatusCode::NOT_FOUND,
                Error::InternalError => hyper::StatusCode::INTERNAL_SERVER_ERROR,
            })
            .body(
                match self {
                    Error::NoHost => "Missing Host header",
                    Error::InvalidHostValue => "Invalid Host header",
                    Error::NoRedirectFound => "No redirect found for that host",
                    Error::InternalError => "Internal Server Error",
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
    Error::InternalError
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

    if *ALLOW_PROXY_ADDRESS == true {
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
                    conn.prepare("SELECT id, destination FROM redirects WHERE host=$1")
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
                                match row {
                                    None => Err(Error::NoRedirectFound),
                                    Some(row) => {
                                        let id: i32 = row.get(0);
                                        let destination: String = row.get(1);

                                        Ok((id, destination))
                                    }
                                },
                                conn,
                            ))
                        })
                })
                .map_err(|err| handle_internal_error(&err))
                .then(flatten_result)
                .and_then(move |(id, destination)| {
                    tokio::spawn(report_visit(id, db_pool, &req, ip_addr));

                    let body = format!("Redirecting to {}", destination);

                    hyper::Response::builder()
                        .status(hyper::StatusCode::MOVED_PERMANENTLY)
                        .header(hyper::header::LOCATION, destination)
                        .body(body.into())
                        .map_err(|err| handle_internal_error(&err))
                })
                .into()
        })
        .or_else(|err| err.into_response())
}

fn main() {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "4000".to_owned())
        .parse()
        .expect("Failed to parse port");
    let database_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    tokio::run(futures::lazy(move || {
        bb8::Pool::builder()
            .build(bb8_postgres::PostgresConnectionManager::new(
                database_url,
                tokio_postgres::NoTls,
            ))
            .map_err(|err| panic!("Failed to connect to database: {:?}", err))
            .and_then(move |db_pool| {
                hyper::Server::bind(&std::net::SocketAddr::from((
                    std::net::Ipv6Addr::UNSPECIFIED,
                    port,
                )))
                .serve(hyper::service::make_service_fn(
                    move |addr_stream: &hyper::server::conn::AddrStream| {
                        let db_pool = db_pool.clone();
                        let ip_addr = addr_stream.remote_addr();
                        hyper::service::service_fn(move |req| {
                            handle_request(req, db_pool.clone(), ip_addr)
                        })
                    },
                ))
                .map_err(|err| panic!("Server execution failed: {:?}", err))
            })
    }))
}
