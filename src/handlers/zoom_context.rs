use base64::prelude::*;
use openssl::symm::{Cipher, Crypter, Mode};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

static HEADER: &str = "x-zoom-app-context";
static MAX_LENGTH: usize = 512;
static HOME_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="Some description">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            padding: 50px;
            font: 14px "Lucida Grande", Helvetica, Arial, sans-serif;
        }
        
        a {
            color: #00B7FF;
        }
    </style>
</head>

<body>
    <h1>Hello Browser</h1>
    <p>You're viewing your Zoom App through the browser.&nbsp;<a href="/install">Click Here</a>&nbsp;to install your app in Zoom.</p>
</body>

</html>"#;

pub struct ZoomContextOptions {
    client_secret: String,
}

impl ZoomContextOptions {
    pub fn new(client_secret: String) -> Self {
        Self { client_secret }
    }
}

#[async_trait]
impl Handler for ZoomContextOptions {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        match req.header::<String>(HEADER) {
            Some(head) => {
                if head.len() > MAX_LENGTH {
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Text::Plain(format!(
                        "Zoom App Context Header must be < {} characters",
                        MAX_LENGTH.to_string()
                    )));
                    ctrl.skip_rest();
                } else {
                    // The zoom app sets some session (cookie?) variables, but doesn't seem to be
                    // used anywhere /shrug
                    let _blah = decrypt(&head, &self.client_secret).unwrap();
                    ctrl.call_next(req, depot, res).await;
                }
            }
            None => {
                res.render(Text::Html(HOME_PAGE_HTML));
                ctrl.skip_rest();
            }
        };
    }
}

fn unpack(
    context: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Decode base64
    let buf = BASE64_STANDARD.decode(context)?;
    // Get iv length (1 byte)
    let iv_length = buf[0] as usize;
    let mut buf = &buf[1..];
    // Get iv
    let iv = buf[..iv_length].to_vec();
    buf = &buf[iv_length..];
    // Get aad length (2 bytes)
    let aad_length = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let mut buf = &buf[2..];
    // Get aad
    let aad = buf[..aad_length].to_vec();
    buf = &buf[aad_length..];
    // Get cipher length (4 bytes)
    let cipher_length = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let buf = &buf[4..];
    // Get cipherText
    let cipher_text = buf[..cipher_length].to_vec();
    // Get tag
    let tag = buf[cipher_length..].to_vec();

    Ok((iv, aad, cipher_text, tag))
}

fn decrypt(context: &str, secret: &str) -> Result<ZoomAuth, Box<dyn std::error::Error>> {
    let (iv, aad, cipher_text, tag) = unpack(context)?;
    let key = Sha256::digest(secret.as_bytes());

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;
    crypter.aad_update(&aad)?;
    crypter.set_tag(&tag)?;

    let mut decrypted = vec![0; cipher_text.len() + 16]; // Add space for authentication tag
    let len = crypter.update(&cipher_text, &mut decrypted)?;
    crypter.finalize(&mut decrypted[len..])?;

    let decrypted_str = String::from_utf8_lossy(&decrypted[..len]);
    let parsed: ZoomAuth = serde_json::from_str(&decrypted_str)?;

    Ok(parsed)
}

#[derive(Serialize, Deserialize, Debug)]
struct ZoomAuth {
    typ: String,
    uid: String,
    mid: String,
    act: String,
    ts: u64,
    exp: u64,
}
