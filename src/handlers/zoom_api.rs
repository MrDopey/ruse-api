use base64::prelude::*;
use reqwest::{Client, Method};
use salvo::{http::cookie::Cookie, prelude::*};

use sha2::{Digest, Sha256};
use url::Url;

pub struct InstallUrl {
    url: Url,
    state: String,
    verifier: String,
}

pub struct ZoomApiOptions {
    host: Url,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    session_secret: String,
}

pub static COOKIE_STATE: &str = "state";
pub static COOKIE_VERIFIER: &str = "verifier";

impl ZoomApiOptions {
    pub fn new(
        host: Url,
        client_id: String,
        client_secret: String,
        redirect_url: String,
        session_secret: String,
    ) -> Self {
        Self {
            host,
            client_id,
            client_secret,
            redirect_url,
            session_secret,
        }
    }

    fn get_install_url(&self) -> InstallUrl {
        let state = base64_url(&BASE64_STANDARD.encode(&rand::random::<[u8; 32]>()));
        let verifier = String::from_utf8_lossy(&rand::random::<[u8; 32]>()).to_string();

        let digest = BASE64_STANDARD.encode(Sha256::digest(verifier.clone()));

        let mut url = self.host.clone();
        url.set_path("/oauth/authorize");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_url)
            .append_pair("code_challenge", &digest)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state);

        InstallUrl {
            url,
            state,
            verifier,
        }
    }
}

#[async_trait]
impl Handler for ZoomApiOptions {
    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let install_url = self.get_install_url();
        res.add_cookie(Cookie::new(COOKIE_STATE, install_url.state))
            .add_cookie(Cookie::new(COOKIE_VERIFIER, install_url.verifier));
        res.render(Redirect::found(install_url.url.as_str()));
    }
}

fn base64_url(s: &str) -> String {
    s.replace('+', "-").replace('/', "_").replace('=', "")
}

async fn token_request(
    params: &str,
    host: &str,
    client_id: &str,
    secret_id: &str,
) -> Result<String, reqwest::Error> {
    let client = Client::new();

    let response = client
        .post(&format!("{}/oauth/token", host))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(client_id, Some(secret_id))
        .body(params.to_string())
        .send()
        .await;

    response?.text().await
}

async fn api_request(
    method: Method,
    host: &str,
    endpoint: &str,
    token: &str,
    data: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = Url::parse(&format!("{}/v2{}", host, endpoint))?;
    let mut request = client.request(method, url);

    if let Some(data) = data {
        request = request
            .header("Authorization", format!("Bearer {}", token))
            .body(data.to_string());
    }

    let response = request.send().await;
    Ok(response?.text().await?)
}
