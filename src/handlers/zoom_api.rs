use base64::prelude::*;
use salvo::{http::cookie::Cookie, prelude::*};

use sha2::{Digest, Sha256};
use url::Url;

struct InstallUrl {
    url: Url,
    state: String,
    verifier: String,
}

pub struct ZoomApiOptions {
    host: Url,
    client_id: String,
    redirect_url: String,
}

pub static COOKIE_STATE: &str = "state";
pub static COOKIE_VERIFIER: &str = "verifier";

impl ZoomApiOptions {
    pub fn new(host: Url, client_id: String, redirect_url: String) -> Self {
        Self {
            host,
            client_id,
            redirect_url,
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
