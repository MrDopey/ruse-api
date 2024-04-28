use salvo::http::header::{self, HeaderValue};
use salvo::prelude::*;
use std::collections::HashMap;

pub struct ContentSecurityPolicyOption {
    pub redirect: String,
}

#[async_trait]
impl Handler for ContentSecurityPolicyOption {
    // async fn add_content_security_policy(host: &str) -> impl Fn(&mut Response) -> () {

    async fn handle(
        &self,
        _req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let img_src = format!("'self' data: {}", self.redirect);
        let connect_src = format!("'self' wss://{}", self.redirect);
        let maps = HashMap::from([
            ("default-src", "'self' 'unsafe-inline' 'unsafe-eval'"),
            ("style-src", "'self' 'unsafe-inline' 'unsafe-eval'"),
            (
                "script-src",
                "https://appssdk.zoom.us/sdk.min.js 'self' 'unsafe-inline' 'unsafe-eval'",
            ),
            ("img-src", &img_src),
            ("connect-src", &connect_src),
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
}
