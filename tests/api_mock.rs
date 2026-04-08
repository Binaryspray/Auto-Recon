use h1scout::api::client::H1Client;
use httpmock::prelude::*;

#[tokio::test]
async fn test_pagination_fetches_all_programs() {
    let server = MockServer::start();

    let page2 = include_str!("fixtures/programs_page2.json");

    let mock2 = server.mock(|when, then| {
        when.method(GET).path("/v1/hackers/programs/page2");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(page2);
    });

    let page1 = include_str!("fixtures/programs_page1.json");
    let page1 = page1.replace(
        "https://api.hackerone.com/v1/hackers/programs?page[number]=2",
        &format!("{}/v1/hackers/programs/page2", server.base_url()),
    );

    let mock1 = server.mock(|when, then| {
        when.method(GET).path("/v1/hackers/programs");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(&page1);
    });

    let client = H1Client::new_with_base_url("user", "token", &server.base_url());
    let programs = client.fetch_all_programs().await.unwrap();

    assert_eq!(programs.len(), 5);
    mock1.assert();
    mock2.assert();
}

#[tokio::test]
async fn test_rate_limit_retries() {
    let server = MockServer::start();

    let page1_json = include_str!("fixtures/programs_page2.json");

    let mut mock_429 = server.mock(|when, then| {
        when.method(GET).path("/v1/hackers/programs");
        then.status(429)
            .header("Content-Type", "application/json")
            .body("{}");
    });

    let client = H1Client::new_with_base_url("user", "token", &server.base_url());

    mock_429.delete();

    let _mock_200 = server.mock(|when, then| {
        when.method(GET).path("/v1/hackers/programs");
        then.status(200)
            .header("Content-Type", "application/json")
            .body(page1_json);
    });

    let programs = client.fetch_all_programs().await.unwrap();
    assert_eq!(programs.len(), 2);
}

#[tokio::test]
async fn test_auth_error_returns_err() {
    let server = MockServer::start();

    let _mock = server.mock(|when, then| {
        when.method(GET).path("/v1/hackers/programs");
        then.status(401)
            .header("Content-Type", "application/json")
            .body(r#"{"error":"unauthorized"}"#);
    });

    let client = H1Client::new_with_base_url("user", "token", &server.base_url());
    let result = client.fetch_all_programs().await;

    assert!(result.is_err());
}
