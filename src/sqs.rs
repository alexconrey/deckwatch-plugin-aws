//! SQS queue provisioning via the AWS SQS Query API.
//!
//! SQS uses a form-encoded query API (`application/x-www-form-urlencoded`) at
//! `https://sqs.<region>.amazonaws.com/`. Responses are XML.
//!
//! Queue ARNs are derived from the queue URL to avoid an extra
//! `GetQueueAttributes` round-trip:
//! `https://sqs.<region>.amazonaws.com/<account>/<name>` →
//! `arn:aws:sqs:<region>:<account>:<name>`

use extism_pdk::*;

use crate::{aws_sign, AwsCredentials, SqsConfig};

// ── Public types ──────────────────────────────────────────────────────────────

pub struct SqsInfo {
    pub queue_url: String,
    pub queue_arn: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Ensure an SQS queue exists, creating it if it does not.
///
/// Returns the queue URL and ARN. For FIFO queues the name is automatically
/// suffixed with `.fifo` if not already present.
pub fn ensure_queue(cfg: &SqsConfig, creds: &AwsCredentials) -> Result<SqsInfo, String> {
    let name = canonical_queue_name(&cfg.queue_name, cfg.fifo);

    if let Some(info) = get_queue_url(&name, creds)? {
        log!(
            LogLevel::Info,
            "deckwatch-plugin-aws: SQS queue {name} already exists"
        );
        return Ok(info);
    }

    create_queue(&name, cfg, creds)
}

/// Delete an SQS queue by URL.
///
/// The queue name cannot be reused for 60 seconds after deletion.
/// Messages in the queue at the time of deletion are lost.
pub fn delete_queue(queue_url: &str, creds: &AwsCredentials) -> Result<(), String> {
    let body = format!(
        "Action=DeleteQueue&Version=2012-11-05&QueueUrl={}",
        url_encode(queue_url)
    );
    sqs_query(&body, creds)?;
    log!(
        LogLevel::Info,
        "deckwatch-plugin-aws: SQS queue {queue_url} deleted"
    );
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn canonical_queue_name(name: &str, fifo: bool) -> String {
    if fifo && !name.ends_with(".fifo") {
        format!("{name}.fifo")
    } else {
        name.to_string()
    }
}

fn get_queue_url(name: &str, creds: &AwsCredentials) -> Result<Option<SqsInfo>, String> {
    let body = format!(
        "Action=GetQueueUrl&Version=2012-11-05&QueueName={}",
        url_encode(name)
    );
    let xml = sqs_query(&body, creds)?;

    if xml.contains("QueueDoesNotExist") || xml.contains("NonExistentQueue") {
        return Ok(None);
    }

    match extract_tag(&xml, "QueueUrl") {
        Some(url) => {
            let arn = arn_from_queue_url(&url, &creds.region)
                .unwrap_or_else(|| format!("arn:aws:sqs:{}:*:{name}", creds.region));
            Ok(Some(SqsInfo {
                queue_url: url,
                queue_arn: arn,
            }))
        }
        None => Ok(None),
    }
}

fn create_queue(name: &str, cfg: &SqsConfig, creds: &AwsCredentials) -> Result<SqsInfo, String> {
    let visibility = cfg.visibility_timeout.to_string();
    // SQS MessageRetentionPeriod is in seconds.
    let retention_secs = (cfg.retention_days as u64 * 86_400).to_string();

    let mut body = format!(
        "Action=CreateQueue&Version=2012-11-05&QueueName={}\
         &Attribute.1.Name=VisibilityTimeout&Attribute.1.Value={}\
         &Attribute.2.Name=MessageRetentionPeriod&Attribute.2.Value={}",
        url_encode(name),
        url_encode(&visibility),
        url_encode(&retention_secs),
    );

    if cfg.fifo {
        body.push_str(
            "&Attribute.3.Name=FifoQueue&Attribute.3.Value=true\
             &Attribute.4.Name=ContentBasedDeduplication&Attribute.4.Value=true",
        );
    }

    let xml = sqs_query(&body, creds)?;

    let queue_url = extract_tag(&xml, "QueueUrl")
        .ok_or_else(|| "SQS CreateQueue: could not parse QueueUrl from response".to_string())?;

    let queue_arn = arn_from_queue_url(&queue_url, &creds.region)
        .unwrap_or_else(|| format!("arn:aws:sqs:{}:*:{name}", creds.region));

    log!(
        LogLevel::Info,
        "deckwatch-plugin-aws: SQS queue {name} created"
    );

    Ok(SqsInfo {
        queue_url,
        queue_arn,
    })
}

/// Construct the SQS ARN from a queue URL without an extra API call.
///
/// URL format: `https://sqs.<region>.amazonaws.com/<account-id>/<queue-name>`
/// ARN format: `arn:aws:sqs:<region>:<account-id>:<queue-name>`
fn arn_from_queue_url(queue_url: &str, region: &str) -> Option<String> {
    let prefix = format!("https://sqs.{region}.amazonaws.com/");
    let path = queue_url.strip_prefix(&prefix)?;
    let mut parts = path.splitn(2, '/');
    let account_id = parts.next()?;
    let queue_name = parts.next()?;
    Some(format!("arn:aws:sqs:{region}:{account_id}:{queue_name}"))
}

fn sqs_query(body: &str, creds: &AwsCredentials) -> Result<String, String> {
    let host = format!("sqs.{}.amazonaws.com", creds.region);
    let datetime = aws_sign::utc_now_iso8601(&creds.region);
    let (auth, payload_hash) = aws_sign::authorization_header(
        "POST",
        &host,
        "/",
        "",
        body,
        &datetime,
        &creds.region,
        "sqs",
        &creds.access_key,
        &creds.secret_key,
        creds.session_token.as_deref(),
        Some("application/x-www-form-urlencoded"),
    );

    let url = format!("https://{host}/");
    let mut req = HttpRequest::new(&url)
        .with_method("POST")
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_header("Host", &host)
        .with_header("X-Amz-Content-Sha256", &payload_hash)
        .with_header("X-Amz-Date", &datetime)
        .with_header("Authorization", &auth);

    if let Some(ref tok) = creds.session_token {
        req = req.with_header("X-Amz-Security-Token", tok);
    }

    let resp = http::request::<String>(&req, Some(body.to_string()))
        .map_err(|e| format!("SQS API HTTP error: {e}"))?;

    let status = resp.status_code();
    let text = String::from_utf8_lossy(&resp.body()).to_string();

    if status >= 400 {
        let msg = extract_tag(&text, "Message")
            .or_else(|| extract_tag(&text, "message"))
            .unwrap_or_else(|| text.clone());
        return Err(format!("SQS API error {status}: {msg}"));
    }

    Ok(text)
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
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
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arn_from_standard_url() {
        let url = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue";
        assert_eq!(
            arn_from_queue_url(url, "us-east-1"),
            Some("arn:aws:sqs:us-east-1:123456789012:MyQueue".to_string())
        );
    }

    #[test]
    fn arn_from_govcloud_url() {
        let url = "https://sqs.us-gov-west-1.amazonaws.com/123456789012/MyQueue";
        assert_eq!(
            arn_from_queue_url(url, "us-gov-west-1"),
            Some("arn:aws:sqs:us-gov-west-1:123456789012:MyQueue".to_string())
        );
    }

    #[test]
    fn arn_from_fifo_url() {
        let url = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue.fifo";
        assert_eq!(
            arn_from_queue_url(url, "us-east-1"),
            Some("arn:aws:sqs:us-east-1:123456789012:MyQueue.fifo".to_string())
        );
    }

    #[test]
    fn canonical_name_adds_fifo_suffix() {
        assert_eq!(canonical_queue_name("my-queue", true), "my-queue.fifo");
        assert_eq!(canonical_queue_name("my-queue.fifo", true), "my-queue.fifo");
        assert_eq!(canonical_queue_name("my-queue", false), "my-queue");
    }
}
