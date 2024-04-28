use handlers::content_security_policy::ContentSecurityPolicyOption;
use salvo::prelude::*;
use std::env;
mod handlers;

#[handler]
async fn hello() -> &'static str {
    "Hello World"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let port = match env::var("ZOOM_APP_PORT") {
        Ok(s) => s.parse::<u16>().ok(),
        _ => None,
    }
    .unwrap_or(3000);

    let redirect_url = env::var("ZM_REDIRECT_URL").expect("Zoom redirect url not defined");

    let cspo = ContentSecurityPolicyOption::new(redirect_url);

    let acceptor = TcpListener::new(format!("127.0.0.1:{port}")).bind().await;
    Server::new(acceptor).serve(route(cspo)).await;
}

fn route(cspo: ContentSecurityPolicyOption) -> Router {
    Router::new()
        .hoop(cspo)
        .hoop(
            Compression::new()
                .enable_gzip(CompressionLevel::Fastest)
                .min_length(0),
        )
        .get(hello)
}

#[cfg(test)]
mod tests {
    use salvo::prelude::*;
    use salvo::test::{ResponseExt, TestClient};

    use crate::handlers::content_security_policy::ContentSecurityPolicyOption;

    #[tokio::test]
    async fn test_hello_word() {
        let cspo = ContentSecurityPolicyOption::new("https://www.test-website.com.au".to_string());
        let service = Service::new(super::route(cspo));

        let content = TestClient::get(format!("http://127.0.0.1:9000/"))
            .send(&service)
            .await
            .take_string()
            .await
            .unwrap();

        assert_eq!(content, "Hello World");
    }
}
