use futures::{Future, IntoFuture, Stream};
use try_future::try_future;

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
        .body(match self {
            Error::NoHost => "Missing Host header",
            Error::InvalidHostValue => "Invalid Host header",
            Error::NoRedirectFound => "No redirect found for that host",
            Error::InternalError => "Internal Server Error",
        }.into())
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

fn handle_request(req: hyper::Request<hyper::Body>, db_pool: bb8::Pool<bb8_postgres::PostgresConnectionManager<tokio_postgres::NoTls>>) -> impl Future<Item=hyper::Response<hyper::Body>, Error=http::Error> {
    req.headers().get(hyper::header::HOST).cloned().ok_or(Error::NoHost)
        .into_future()
        .and_then(move |host| {
            let host = try_future!(host.to_str().map_err(|_| Error::InvalidHostValue)).to_owned();
            // Ok(hyper::Response::new(hyper::Body::from(host.to_owned())))
            //

            db_pool.run(move |mut conn| {
                conn.prepare("SELECT destination FROM redirects WHERE host=$1")
                    .then(move |res| {
                        match res {
                            Ok(stmt) => {
                                conn.query(&stmt, &[&host])
                                    .into_future()
                                    .then(|res| {
                                        match res {
                                            Ok((row, _)) => Ok((row, conn)),
                                            Err((err, _)) => Err((err, conn)),
                                        }
                                    })
                                    .into()
                            },
                            Err(err) => try_future!(Err((err, conn)))
                        }
                    })
                .and_then(|(row, conn)| {
                    Ok((match row {
                        None => Err(Error::NoRedirectFound),
                        Some(row) => {
                            let destination: String = row.get(0);

                            let body = format!("Redirecting to {}", destination);

                            hyper::Response::builder()
                                .status(hyper::StatusCode::MOVED_PERMANENTLY)
                                .header(hyper::header::LOCATION, destination)
                                .body(body.into())
                                .map_err(|err| handle_internal_error(&err))
                        }
                    }, conn))
                })
            })
            .map_err(|err| handle_internal_error(&err))
                .then(flatten_result)
                .into()
        })
    .or_else(|err| {
        err.into_response()
    })
}

fn main() {
    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "4000".to_owned()).parse().expect("Failed to parse port");
    let database_url = std::env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    tokio::run(futures::lazy(move || {
        bb8::Pool::builder()
            .build(bb8_postgres::PostgresConnectionManager::new(database_url, tokio_postgres::NoTls))
            .map_err(|err| panic!("Failed to connect to database: {:?}", err))
            .and_then(move |db_pool| {
                hyper::Server::bind(&std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)))
                    .serve(move || {
                        let db_pool = db_pool.clone();
                        hyper::service::service_fn(move |req| handle_request(req, db_pool.clone()))
                    })
                .map_err(|err| panic!("Server execution failed: {:?}", err))
            })
    }))
}
