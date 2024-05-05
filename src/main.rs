use handlers::{
    content_security_policy::ContentSecurityPolicyOption, zoom_api::ZoomApiOptions,
    zoom_auth::ZoomAuthOptions, zoom_context::ZoomContextOptions,
};
use salvo::prelude::*;
use std::env;
use url::Url;
mod handlers;

#[handler]
async fn hello() -> &'static str {
    "Hello World"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let (port, cspo, zco, zautho, zapio) = match parse_app_parameters() {
        Ok(x) => x,
        Err(err) => panic!("{}", err),
    };
    let acceptor = TcpListener::new(format!("127.0.0.1:{port}")).bind().await;
    Server::new(acceptor)
        .serve(route(cspo, zco, zautho, zapio))
        .await;
}

fn route(
    cspo: ContentSecurityPolicyOption,
    zco: ZoomContextOptions,
    zautho: ZoomAuthOptions,
    zapio: ZoomApiOptions,
) -> Router {
    Router::new()
        .hoop(cspo)
        .hoop(
            Compression::new()
                .enable_gzip(CompressionLevel::Fastest)
                .min_length(0),
        )
        .hoop(zco)
        .push(Router::with_path("install").get(zapio))
        .push(Router::with_path("auth").get(zautho))
        .get(hello)
}

fn parse_app_parameters() -> Result<
    (
        u16,
        ContentSecurityPolicyOption,
        ZoomContextOptions,
        ZoomAuthOptions,
        ZoomApiOptions,
    ),
    String,
> {
    let port = match env::var("ZOOM_APP_PORT") {
        Ok(s) => s.parse::<u16>().ok(),
        _ => None,
    }
    .unwrap_or(3000);

    fn get_env(key: &str) -> Result<String, String> {
        env::var(key).map_err(|x| format!("{} cannot be interpreted: {}", key, x.to_string()))
    }

    let redirect_url = get_env("ZM_REDIRECT_URL")?;

    let host = get_env("ZOOM_HOST")?;

    let host_parsed = Url::parse(&host).map_err(|x| x.to_string())?;

    let client_id = get_env("ZM_CLIENT_ID")?;
    let client_secret = get_env("ZM_CLIENT_SECRET")?;

    let cspo = ContentSecurityPolicyOption::new(redirect_url.clone());
    let zco = ZoomContextOptions::new(client_secret.clone());
    let zautho = ZoomAuthOptions::new(
        host_parsed.clone(),
        client_id.clone(),
        client_secret,
        redirect_url.clone(),
    );
    let zapio = ZoomApiOptions::new(host_parsed, client_id, redirect_url);

    Ok((port, cspo, zco, zautho, zapio))
}

#[cfg(test)]
mod tests {
    use salvo::prelude::*;
    use salvo::test::{ResponseExt, TestClient};
    use url::Url;

    use crate::handlers::content_security_policy::ContentSecurityPolicyOption;
    use crate::handlers::zoom_api::ZoomApiOptions;
    use crate::handlers::zoom_auth::ZoomAuthOptions;
    use crate::handlers::zoom_context::ZoomContextOptions;

    #[tokio::test]
    async fn test_hello_word() {
        let host_parsed = Url::parse("https://www.example.com").unwrap();
        let redirect_url = "https://www.test-website.com.au".to_string();
        let client_secret = "abc".to_string();
        let client_id = "def".to_string();

        let cspo = ContentSecurityPolicyOption::new(redirect_url.clone());
        let zco = ZoomContextOptions::new(client_secret.clone());
        let zautho = ZoomAuthOptions::new(
            host_parsed.clone(),
            client_id.clone(),
            client_secret,
            redirect_url.clone(),
        );
        let zapio = ZoomApiOptions::new(host_parsed, client_id, redirect_url);

        let service = Service::new(super::route(cspo, zco, zautho, zapio));

        let content = TestClient::get(format!("http://127.0.0.1:9000/"))
            .send(&service)
            .await
            .take_string()
            .await
            .unwrap();

        assert_eq!(content, "Hello World");
    }
}
