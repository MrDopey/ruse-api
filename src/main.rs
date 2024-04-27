use salvo::prelude::*;
use std::env;

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

    let acceptor = TcpListener::new(format!("127.0.0.1:{port}")).bind().await;
    Server::new(acceptor).serve(route()).await;
}

fn route() -> Router {
    Router::new().get(hello)
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
