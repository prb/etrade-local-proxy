//! Console interaction: print the authorize URL to stdout and read the OAuth
//! verifier from stdin once. No browser launch, no re-prompt — a single prompt
//! per the CONCEPT console-display + stdin-verifier flow.

use std::io::{BufRead, Write};

use crate::core::newtypes::Verifier;
use crate::shell::error::OauthFlowError;

/// Print the authorize URL and prompt the user to open it, then read the
/// verifier from stdin once. The verifier is trimmed of surrounding
/// whitespace; an empty result returns [`OauthFlowError::EmptyVerifier`] (no
/// re-prompt).
///
/// Reader/writer are injected so the flow is testable without touching the real
/// stdin/stdout; [`read_verifier`] wires the real streams.
pub fn prompt_verifier(
    authorize_url: &str,
    mut out: impl Write,
    input: impl BufRead,
) -> Result<Verifier, OauthFlowError> {
    writeln!(out, "\nOpen this URL in your browser to authorize the proxy:")?;
    writeln!(out, "  {authorize_url}")?;
    write!(out, "\nPaste the verifier code and press Enter: ")?;
    out.flush()?;

    let mut line = String::new();
    let mut input = input;
    input.read_line(&mut line)?;

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(OauthFlowError::EmptyVerifier);
    }
    Ok(Verifier::new(trimmed.to_string()))
}

/// Read the verifier using the real stdin/stdout.
pub fn read_verifier(authorize_url: &str) -> Result<Verifier, OauthFlowError> {
    let stdin = std::io::stdin();
    let locked = stdin.lock();
    prompt_verifier(authorize_url, std::io::stdout(), locked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn trims_and_returns_verifier() {
        let mut out = Vec::new();
        let input = Cursor::new(b"  code123  \n".to_vec());
        let v = prompt_verifier("https://authorize", &mut out, input).unwrap();
        assert_eq!(v.as_str(), "code123");
        // The URL is printed to the writer.
        let printed = String::from_utf8(out).unwrap();
        assert!(printed.contains("https://authorize"));
    }

    #[test]
    fn empty_verifier_is_error() {
        let mut out = Vec::new();
        let input = Cursor::new(b"   \n".to_vec());
        let err = prompt_verifier("https://authorize", &mut out, input).unwrap_err();
        assert!(matches!(err, OauthFlowError::EmptyVerifier));
    }

    #[test]
    fn eof_empty_is_error() {
        let mut out = Vec::new();
        let input = Cursor::new(Vec::new());
        let err = prompt_verifier("https://authorize", &mut out, input).unwrap_err();
        assert!(matches!(err, OauthFlowError::EmptyVerifier));
    }
}
