use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Weights {
    pub bounty_scale: f64,
    pub web_scope: f64,
    pub program_health: f64,
    pub response_speed: f64,
    pub difficulty: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            bounty_scale: 0.20,
            web_scope: 0.30,
            program_health: 0.20,
            response_speed: 0.10,
            difficulty: 0.20,
        }
    }
}

impl Weights {
    pub fn from_config(path: &str) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|content| toml::from_str::<WeightsConfig>(&content).ok())
            .map(|c| c.weights)
            .unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
struct WeightsConfig {
    weights: Weights,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weights_sum_to_one() {
        let w = Weights::default();
        let sum = w.bounty_scale + w.web_scope + w.program_health + w.response_speed + w.difficulty;
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_weights_from_missing_config_uses_default() {
        let w = Weights::from_config("/nonexistent/path.toml");
        assert!((w.bounty_scale - 0.20).abs() < 1e-9);
        assert!((w.difficulty - 0.20).abs() < 1e-9);
    }
}
