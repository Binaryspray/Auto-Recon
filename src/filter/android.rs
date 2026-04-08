use crate::api::models::ScopeData;

pub fn has_android(scopes: &[ScopeData]) -> bool {
    scopes.iter().any(|s| s.attributes.asset_type == "ANDROID")
}

pub fn extract_android_packages(scopes: &[ScopeData]) -> Vec<String> {
    scopes
        .iter()
        .filter(|s| s.attributes.asset_type == "ANDROID")
        .map(|s| s.attributes.asset_identifier.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::*;

    fn make_scope(asset_type: &str, identifier: &str) -> ScopeData {
        ScopeData {
            id: "s1".to_string(),
            data_type: "structured-scope".to_string(),
            attributes: ScopeAttributes {
                asset_type: asset_type.to_string(),
                asset_identifier: identifier.to_string(),
                eligible_for_bounty: true,
                eligible_for_submission: true,
                max_severity: Some("critical".to_string()),
                instruction: None,
            },
        }
    }

    #[test]
    fn test_android_detected() {
        let scopes = vec![make_scope("ANDROID", "com.gm.myvehicle")];
        assert!(has_android(&scopes));
    }

    #[test]
    fn test_no_android() {
        let scopes = vec![make_scope("URL", "*.example.com")];
        assert!(!has_android(&scopes));
    }

    #[test]
    fn test_package_extraction() {
        let scopes = vec![
            make_scope("ANDROID", "com.gm.myvehicle"),
            make_scope("URL", "*.gm.com"),
            make_scope("ANDROID", "com.uber.driver"),
        ];
        let packages = extract_android_packages(&scopes);
        assert_eq!(packages, vec!["com.gm.myvehicle", "com.uber.driver"]);
    }
}
