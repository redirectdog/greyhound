use futures::{Future, IntoFuture};

enum Error {
    NoHost,
    InvalidHostValue,
    InternalError,
}

impl Error {
    pub fn into_response(&self) -> Result<hyper::Response<hyper::Body>, http::Error> {
        hyper::Response::builder()
            .status(match self {
                Error::NoHost | Error::InvalidHostValue => hyper::StatusCode::BAD_REQUEST,
                Error::InternalError => hyper::StatusCode::INTERNAL_SERVER_ERROR,
            })
        .body(match self {
            Error::NoHost => "Missing Host header",
            Error::InvalidHostValue => "Invalid Host header",
            Error::InternalError => "Internal Server Error",
        }.into())
    }
}

fn main() {
    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "4000".to_owned()).parse().expect("Failed to parse port");

    let server = hyper::Server::bind(&std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)))
        .serve(|| {
            hyper::service::service_fn(|req| {
                req.headers().get(hyper::header::HOST).cloned().ok_or(Error::NoHost)
                    .into_future()
                    .and_then(|host| {
                        let host = host.to_str().map_err(|_| Error::InvalidHostValue)?;
                        Ok(hyper::Response::new(hyper::Body::from(host.to_owned())))
                    })
                .or_else(|err| {
                    err.into_response()
                })
            })
        });

    tokio::run(server.map_err(|e| panic!("{:?}", e)));
}
