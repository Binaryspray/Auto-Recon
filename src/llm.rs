use anyhow::{anyhow, Result};
use std::path::Path;
use tokio::process::Command;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

pub async fn query(prompt: &str, _cwd: &Path) -> Result<String> {
    let mut child = Command::new("claude")
        .args(["--print", "--dangerously-skip-permissions", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(prompt.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("claude call failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
