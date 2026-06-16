use sqlx::SqlitePool;

pub const DEFAULT_WIDGET_URL: &str = "https://cdn.jsdelivr.net/npm/cap-widget";

pub struct CaptchaConfig {
    pub instance_url: String,
    pub site_key: String,
    pub secret: String,
    pub widget_url: String,
}

pub struct CaptchaVars {
    pub enabled: bool,
    pub api_endpoint: String,
    pub widget_url: String,
}

impl CaptchaVars {
    pub fn from_config(config: &Option<CaptchaConfig>) -> Self {
        Self {
            enabled: config.is_some(),
            api_endpoint: config
                .as_ref()
                .map(|c| c.api_endpoint())
                .unwrap_or_default(),
            widget_url: config
                .as_ref()
                .map(|c| c.widget_url.clone())
                .unwrap_or_else(|| DEFAULT_WIDGET_URL.to_string()),
        }
    }
}

impl CaptchaConfig {
    /// API endpoint URL passed to the <cap-widget> data-cap-api-endpoint attribute.
    pub fn api_endpoint(&self) -> String {
        format!(
            "{}/{}/",
            self.instance_url.trim_end_matches('/'),
            self.site_key
        )
    }

    /// Extract scheme+host from widget_url for use in Content-Security-Policy script-src.
    /// e.g. "https://cdn.jsdelivr.net/npm/cap-widget" → "https://cdn.jsdelivr.net"
    pub fn widget_script_origin(&self) -> String {
        extract_origin(&self.widget_url)
    }

    /// Extract scheme+host from instance_url for use in Content-Security-Policy connect-src.
    /// e.g. "https://captcha.example.com" → "https://captcha.example.com"
    pub fn instance_origin(&self) -> String {
        extract_origin(&self.instance_url)
    }
}

fn extract_origin(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return String::new();
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return String::new();
    }
    let host = parsed.host_str().unwrap_or("");
    match parsed.port() {
        Some(port) => format!("{}://{}:{}", parsed.scheme(), host, port),
        None => format!("{}://{}", parsed.scheme(), host),
    }
}

pub async fn load_captcha_config(pool: &SqlitePool, key: &[u8; 32]) -> Option<CaptchaConfig> {
    let row: Option<(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT captcha_instance_url, captcha_site_key, captcha_secret, captcha_widget_url \
             FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let (instance_url, site_key, secret_enc, widget_url) = row?;
    let instance_url = instance_url.filter(|s| !s.trim().is_empty())?;
    let site_key = site_key.filter(|s| !s.trim().is_empty())?;
    let secret_enc = secret_enc.filter(|s| !s.trim().is_empty())?;
    let secret = crate::crypto::decrypt_value(key, &secret_enc).ok()?;
    let widget_url = widget_url
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WIDGET_URL.to_string());

    Some(CaptchaConfig {
        instance_url,
        site_key,
        secret,
        widget_url,
    })
}

#[derive(serde::Serialize)]
struct VerifyRequest<'a> {
    secret: &'a str,
    response: &'a str,
}

#[derive(serde::Deserialize)]
struct VerifyResponse {
    success: bool,
}

/// Returns `Ok(())` if captcha is not configured (pass-through) or if the token
/// is valid. Returns `Err(())` if captcha is configured but the token is missing
/// or fails server-side verification.
pub async fn verify(config: &Option<CaptchaConfig>, token: Option<&str>) -> Result<(), ()> {
    let cfg = match config {
        Some(c) => c,
        None => return Ok(()),
    };

    let token = match token.filter(|t| !t.trim().is_empty()) {
        Some(t) => t,
        None => {
            tracing::warn!("captcha token missing on booking attempt");
            return Err(());
        }
    };

    let verify_url = format!("{}/siteverify", cfg.api_endpoint().trim_end_matches('/'));

    let client = reqwest::Client::new();
    let resp = match client
        .post(&verify_url)
        .json(&VerifyRequest {
            secret: &cfg.secret,
            response: token,
        })
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "captcha verification request failed");
            return Err(());
        }
    };

    match resp.json::<VerifyResponse>().await {
        Ok(r) if r.success => Ok(()),
        Ok(_) => {
            tracing::warn!("captcha token rejected by verification server");
            Err(())
        }
        Err(e) => {
            tracing::warn!(error = %e, "captcha verification response parse failed");
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- extract_origin tests ---

    #[test]
    fn extract_origin_returns_scheme_and_host() {
        assert_eq!(
            extract_origin("https://cdn.jsdelivr.net/npm/cap-widget"),
            "https://cdn.jsdelivr.net"
        );
    }

    #[test]
    fn extract_origin_handles_root_url() {
        assert_eq!(
            extract_origin("https://cap.example.com"),
            "https://cap.example.com"
        );
    }

    #[test]
    fn extract_origin_handles_trailing_slash() {
        assert_eq!(
            extract_origin("https://cap.example.com/"),
            "https://cap.example.com"
        );
    }

    #[test]
    fn extract_origin_rejects_invalid_url() {
        assert_eq!(extract_origin("not-a-url"), "");
        assert_eq!(extract_origin(""), "");
    }

    // --- api_endpoint tests ---

    #[test]
    fn api_endpoint_strips_trailing_slash_on_instance() {
        let cfg = CaptchaConfig {
            instance_url: "https://cap.example.com/".to_string(),
            site_key: "mykey".to_string(),
            secret: "s".to_string(),
            widget_url: DEFAULT_WIDGET_URL.to_string(),
        };
        assert_eq!(cfg.api_endpoint(), "https://cap.example.com/mykey/");
    }

    #[test]
    fn api_endpoint_no_trailing_slash_on_instance() {
        let cfg = CaptchaConfig {
            instance_url: "https://cap.example.com".to_string(),
            site_key: "mykey".to_string(),
            secret: "s".to_string(),
            widget_url: DEFAULT_WIDGET_URL.to_string(),
        };
        assert_eq!(cfg.api_endpoint(), "https://cap.example.com/mykey/");
    }

    // --- verify passthrough tests (no network) ---

    #[tokio::test]
    async fn verify_passes_through_when_no_config() {
        assert!(verify(&None, None).await.is_ok());
        assert!(verify(&None, Some("any-token")).await.is_ok());
    }

    #[tokio::test]
    async fn verify_fails_when_config_set_and_token_missing() {
        let cfg = Some(CaptchaConfig {
            instance_url: "https://cap.example.com".to_string(),
            site_key: "key".to_string(),
            secret: "secret".to_string(),
            widget_url: DEFAULT_WIDGET_URL.to_string(),
        });
        assert!(verify(&cfg, None).await.is_err());
    }

    #[tokio::test]
    async fn verify_fails_when_config_set_and_token_empty() {
        let cfg = Some(CaptchaConfig {
            instance_url: "https://cap.example.com".to_string(),
            site_key: "key".to_string(),
            secret: "secret".to_string(),
            widget_url: DEFAULT_WIDGET_URL.to_string(),
        });
        assert!(verify(&cfg, Some("")).await.is_err());
        assert!(verify(&cfg, Some("   ")).await.is_err());
    }
}
