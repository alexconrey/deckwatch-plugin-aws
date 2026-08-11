//! STS AssumeRoleWithWebIdentity — exchange a workload identity token for
//! temporary AWS credentials.
//!
//! This call does NOT require Sig V4 signing. The web identity token itself
//! is the authentication mechanism, making it suitable for bootstrapping
//! credentials from IRSA or any other OIDC-based identity provider.
//!
//! The plugin reads the token from extism config (`AWS_IDENTITY_TOKEN`) and
//! the role ARN from `AWS_ROLE_ARN`. Deckwatch injected `AWS_IDENTITY_TOKEN`
//! by reading the file at `$AWS_WEB_IDENTITY_TOKEN_FILE` on the host — the
//! plugin has no filesystem access and never sees the file path.

use extism_pdk::*;

use crate::AwsCredentials;

/// Try to exchange a workload identity token for temporary credentials.
///
/// Returns `Some(AwsCredentials)` if both `AWS_IDENTITY_TOKEN` and
/// `AWS_ROLE_ARN` are present in the plugin config and the STS call succeeds.
/// Returns `None` if the token or role ARN are absent (fall through to static
/// credentials). Returns `Err` if the exchange fails unexpectedly.
pub fn try_assume_role_with_web_identity(region: &str) -> Result<Option<AwsCredentials>, String> {
    let token = match config::get("AWS_IDENTITY_TOKEN")
        .map_err(|e| format!("config error: {e}"))?
    {
        Some(t) if !t.is_empty() => t,
        _ => return Ok(None), // no token — caller falls back to static creds
    };

    let role_arn = match config::get("AWS_ROLE_ARN")
        .map_err(|e| format!("config error: {e}"))?
    {
        Some(r) if !r.is_empty() => r,
        _ => return Ok(None),
    };

    let creds = call_sts(&token, &role_arn, region)?;
    Ok(Some(creds))
}

// ── STS HTTP call (unsigned — web identity token is the auth) ─────────────────

fn call_sts(token: &str, role_arn: &str, region: &str) -> Result<AwsCredentials, String> {
    // GovCloud uses regional STS endpoints; standard regions accept the global
    // endpoint. We always use the regional form for consistency.
    let host = format!("sts.{region}.amazonaws.com");
    let url = format!("https://{host}/");

    let body = format!(
        "Action=AssumeRoleWithWebIdentity\
         &Version=2011-06-15\
         &RoleArn={}\
         &RoleSessionName=deckwatch-plugin\
         &WebIdentityToken={}\
         &DurationSeconds=3600",
        url_encode(role_arn),
        url_encode(token),
    );

    let req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Host", &host);

    let resp = http::request::<String>(&req, Some(body))
        .map_err(|e| format!("STS HTTP error: {e}"))?;

    let status = resp.status_code();
    let body_bytes = resp.body();
    let body_str = String::from_utf8_lossy(&body_bytes);

    if status >= 400 {
        let msg = extract_xml_tag(&body_str, "Message")
            .unwrap_or_else(|| body_str.to_string());
        return Err(format!("STS error {status}: {msg}"));
    }

    parse_credentials(&body_str, region)
}

fn parse_credentials(xml: &str, region: &str) -> Result<AwsCredentials, String> {
    let access_key = extract_xml_tag(xml, "AccessKeyId")
        .ok_or("STS response missing AccessKeyId")?;
    let secret_key = extract_xml_tag(xml, "SecretAccessKey")
        .ok_or("STS response missing SecretAccessKey")?;
    let session_token = extract_xml_tag(xml, "SessionToken");

    Ok(AwsCredentials {
        access_key,
        secret_key,
        session_token,
        region: region.to_string(),
    })
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml[start..start + end].trim().to_string())
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── Tests (host target — no extism) ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_role_arn() {
        let arn = "arn:aws-us-gov:iam::591839118651:role/my-role";
        let encoded = url_encode(arn);
        assert!(encoded.contains("%3A")); // colons encoded
        assert!(!encoded.contains(':'));
    }

    #[test]
    fn parse_credentials_from_sample_xml() {
        let xml = r#"
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIA123</AccessKeyId>
      <SecretAccessKey>secret456</SecretAccessKey>
      <SessionToken>token789</SessionToken>
      <Expiration>2026-08-11T17:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;

        let creds = parse_credentials(xml, "us-gov-west-1").unwrap();
        assert_eq!(creds.access_key, "ASIA123");
        assert_eq!(creds.secret_key, "secret456");
        assert_eq!(creds.session_token.as_deref(), Some("token789"));
        assert_eq!(creds.region, "us-gov-west-1");
    }

    #[test]
    fn parse_credentials_missing_field_errors() {
        let xml = "<AssumeRoleWithWebIdentityResponse><Credentials></Credentials></AssumeRoleWithWebIdentityResponse>";
        assert!(parse_credentials(xml, "us-gov-west-1").is_err());
    }
}
