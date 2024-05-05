use reqwest::{Client, Method};
use salvo::{http::cookie::Cookie, prelude::*};

use url::Url;

use super::zoom_api::{COOKIE_STATE, COOKIE_VERIFIER};

struct AuthParam {
    code: String,
    state: String,
    verifier: String,
}

pub struct ZoomAuthOptions {
    host: Url,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    session_secret: String,
}

impl ZoomAuthOptions {
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
}

#[async_trait]
impl Handler for ZoomAuthOptions {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        res.remove_cookie(COOKIE_STATE);

        let auth_param = validate_request(req);

        if let Err(err) = auth_param {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain(err));
            ctrl.skip_rest();
            return;
        };
    }
}

fn validate_request(req: &Request) -> Result<AuthParam, String> {
    let code = req
        .query::<String>("code")
        .ok_or("code must be a valid string".to_string())?;

    if code.len() < 32 || code.len() > 64 {
        return Err("code does not fit size requirements".to_string());
    }

    let state = req
        .query::<String>("state")
        .ok_or("state must be a string".to_string())?;

    let cookie_state = req
        .cookies()
        .get(COOKIE_STATE)
        .ok_or(format!("Cookie {} must be defined", COOKIE_STATE))?
        .value();

    if state != cookie_state {
        return Err("invalid state parameter".to_string());
    }

    let verifier = req
        .cookies()
        .get(COOKIE_VERIFIER)
        .ok_or(format!("Cookie {} must be defined", COOKIE_STATE))?
        .value()
        .to_string();

    return Ok(AuthParam {
        code,
        state,
        verifier,
    });
}
