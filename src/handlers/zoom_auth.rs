use reqwest::Client;
use salvo::prelude::*;

use serde::{Deserialize, Serialize};
use url::Url;

use super::zoom_api::{COOKIE_STATE, COOKIE_VERIFIER};

pub struct ZoomAuthOptions {
    host: Url,
    client_id: String,
    client_secret: String,
    redirect_url: String,
}

struct AuthParam {
    code: String,
    verifier: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Serialize)]
struct Body {
    action: ActionBody,
}

#[derive(Serialize)]
struct ActionBody {
    url: String,
    role_name: String,
    verified: u8,
    role_id: u8,
}

#[derive(Deserialize)]
struct DeepLinkRespone {
    deeplink: String,
}

impl ZoomAuthOptions {
    pub fn new(host: Url, client_id: String, client_secret: String, redirect_url: String) -> Self {
        Self {
            host,
            client_id,
            client_secret,
            redirect_url,
        }
    }

    // https://developers.zoom.us/docs/integrations/oauth/
    async fn request_access_token(
        &self,
        auth_param: AuthParam,
    ) -> Result<TokenResponse, reqwest::Error> {
        let client = Client::new();

        let mut url = self.host.clone();
        url.set_path("oauth/token");

        let body = [
            ("code", auth_param.code.as_str()),
            // ("code_verifier", auth_param.verifier.as_str()),
            ("redirect_uri", self.redirect_url.as_str()),
            ("grant_type", "authorization_code"),
        ];

        let response = client
            .post(url.to_string())
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&body)
            .send()
            .await?;

        Ok(response.json::<TokenResponse>().await?)
    }

    // https://developers.zoom.us/docs/zoom-apps/architecture/#deep-link-generation
    async fn get_deep_link(
        &self,
        token_response: TokenResponse,
    ) -> Result<DeepLinkRespone, reqwest::Error> {
        let mut url = self.host.clone();
        url.set_path("v2/zoomapp/deeplink");

        let body = ActionBody {
            url: "/".to_string(),
            role_name: "Owner".to_string(),
            verified: 1,
            role_id: 0,
        };

        println!("token: {}", token_response.access_token.clone());

        let client = Client::new();
        client
            .post(url.to_string())
            .bearer_auth(token_response.access_token)
            .json(&body)
            .send()
            .await?
            .json::<DeepLinkRespone>()
            .await
    }

    async fn internal_handle(
        &self,
        req: &mut Request,
    ) -> Result<DeepLinkRespone, (salvo::http::StatusCode, String)> {
        let auth_param = validate_request(req).map_err(|x| (StatusCode::BAD_REQUEST, x))?;

        let token = self
            .request_access_token(auth_param)
            .await
            .map_err(|x| (StatusCode::INTERNAL_SERVER_ERROR, x.to_string()))?;

        self.get_deep_link(token)
            .await
            .map_err(|x| (StatusCode::INTERNAL_SERVER_ERROR, x.to_string()))
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

        match self.internal_handle(req).await {
            Err(err) => {
                res.status_code(err.0);
                res.render(Text::Plain(format!("server error: {}", err.1)));
                ctrl.skip_rest();
            }
            Ok(deep_link) => {
                res.render(Redirect::found(deep_link.deeplink));
            }
        }
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
        .ok_or(format!("Cookie {} must be defined", COOKIE_VERIFIER))?
        .value()
        .to_string();

    return Ok(AuthParam { code, verifier });
}
