use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::Command;

pub fn query(prompt: &str, _cwd: &Path) -> Result<String> {
    let output = Command::new("claude")
        .args(["--print", "--dangerously-skip-permissions", prompt])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("claude call failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
