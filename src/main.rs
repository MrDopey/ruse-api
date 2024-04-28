use salvo::http::header::{self, HeaderValue};
use salvo::prelude::*;
use std::collections::HashMap;
use std::env;

#[handler]
async fn hello() -> &'static str {
    "Hello World"
}

#[handler]
// async fn add_content_security_policy(host: &str) -> impl Fn(&mut Response) -> () {
async fn add_content_security_policy(res: &mut Response) -> () {
    let maps = HashMap::from([
        ("default-src", "'self' 'unsafe-inline' 'unsafe-eval'"),
        ("style-src", "'self' 'unsafe-inline' 'unsafe-eval'"),
        (
            "script-src",
            "https://appssdk.zoom.us/sdk.min.js 'self' 'unsafe-inline' 'unsafe-eval'",
        ),
        (
            "img-src",
            "'self' data: https://b7a9-124-168-11-219.ngrok-free.app",
        ),
        (
            "connect-src",
            "'self' wss://b7a9-124-168-11-219.ngrok-free.app",
        ),
        ("base-uri", "'self'"),
        ("form-action", "'self'"),
        ("font-src", "'self' https: data:"),
        ("frame-ancestors", "'self'"),
        ("object-src", "'none'"),
        ("script-src-attr", "'none'"),
        ("upgrade-insecure-requests", ""),
    ]);

    let value = maps.iter().fold("".to_owned(), |acc, it| {
        format!("{}{} {};", acc, it.0, it.1)
    });

    let headers = res.headers_mut();

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&value).unwrap(),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"), // 1 year in seconds
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );

    // Doesn't work well
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
    // headers.insert(
    //     header::X_XSS_PROTECTION,
    //     HeaderValue::from_static("0"),
    // );
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let port = match env::var("ZOOM_APP_PORT") {
        Ok(s) => s.parse::<u16>().ok(),
        _ => None,
    }
    .unwrap_or(3000);

    let acceptor = TcpListener::new(format!("127.0.0.1:{port}")).bind().await;
    Server::new(acceptor).serve(route()).await;
}

fn route() -> Router {
    Router::new().hoop(add_content_security_policy).get(hello)
}

#[cfg(test)]
mod tests {
    use salvo::prelude::*;
    use salvo::test::{ResponseExt, TestClient};

    #[tokio::test]
    async fn test_hello_word() {
        let service = Service::new(super::route());

        let content = TestClient::get(format!("http://127.0.0.1:9000/"))
            .send(&service)
            .await
            .take_string()
            .await
            .unwrap();

        assert_eq!(content, "Hello World");
    }
}
