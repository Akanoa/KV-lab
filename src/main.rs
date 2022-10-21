use crate::header::HeaderMap;
use actix_session::Session;
use actix_web::web::Data;
use actix_web::{get, web, App, HttpResponse, HttpServer};
use eyre::WrapErr;
use oauth2::basic::BasicClient;
use oauth2::http::{header, Method};
use oauth2::reqwest::http_client;
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;
use std::env;

struct AppState {
    oauth: BasicClient,
    api_base_url: String,
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Deserialize, Debug)]
pub struct UserData {
    email: String,
}

#[get("/")]
async fn index() -> HttpResponse {
    HttpResponse::Ok().body("Hello")
}

#[get("/logout")]
async fn logout(session: Session) -> HttpResponse {
    session.remove("login");
    HttpResponse::Found()
        .append_header((header::LOCATION, "/".to_string()))
        .finish()
}

#[get("/login")]
async fn login(data: web::Data<AppState>) -> HttpResponse {
    // Generate a PKCE challenge
    // https://oa.dnc.global/-fr-.html?page=unarticle&id_article=148
    let (pkce_challenge, _) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, _) = &data
        .oauth
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    HttpResponse::Found()
        .append_header((header::LOCATION, auth_url.to_string()))
        .finish()
}

fn read_user(api_base_url: &str, access_token: &AccessToken) -> eyre::Result<UserData> {
    let url =
        Url::parse(format!("{}/user", api_base_url).as_str()).wrap_err("Unable to parse URL")?;
    let mut headers = HeaderMap::new();
    headers.insert("PRIVATE-TOKEN", access_token.secret().to_string().parse()?);
    let response = http_client(oauth2::HttpRequest {
        url,
        method: Method::GET,
        headers,
        body: vec![],
    })
    .wrap_err("Unable to Get user details")?;

    serde_json::from_slice(&response.body).wrap_err("Unable to deserialize")
}

#[get("/auth")]
async fn auth(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> HttpResponse {
    let code = AuthorizationCode::new(params.code.clone());
    let _state = CsrfToken::new(params.state.clone());

    let token = &data.oauth.exchange_code(code).request(http_client);
    match token {
        Ok(token) => {
            let user_info = read_user(&data.api_base_url, token.access_token());

            match user_info {
                Ok(user_info) => {
                    if let Err(_) = session.insert("login", user_info.email.clone()) {
                        return HttpResponse::InternalServerError().finish();
                    }

                    let html = format!(
                        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            You are logged
        </body>
    </html>"#
                    );

                    HttpResponse::Ok().body(html)
                }
                Err(_) => HttpResponse::BadRequest().finish(),
            }
        }
        Err(_err) => HttpResponse::BadRequest().finish(),
    }
}

#[actix_rt::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    HttpServer::new(|| {
        let application_id = ClientId::new(
            env::var("GITLAB_SSO_APP_ID").expect("Missing GITLAB_SSO_APP_ID environment variable."),
        );

        let application_secret = ClientSecret::new(
            env::var("GITLAB_SSO_APP_SECRET")
                .expect("Missing GITLAB_SSO_APP_SECRET environment variable."),
        );

        let oauth_server =
            env::var("GITLAB_SERVER").expect("Missing GITLAB_SERVER environment variable.");

        let auth_url = AuthUrl::new(format!("https://{}/oauth/authorize", oauth_server))
            .expect("Invalid authorization endpoint URL");

        let token_url = TokenUrl::new(format!("https://{}/oauth/token", oauth_server))
            .expect("Invalid token endpoint URL");

        let api_base_url = format!("https://{}/api/v4", oauth_server);

        let client = BasicClient::new(
            application_id,
            Some(application_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(
            RedirectUrl::new("http://127.0.0.1:5000/auth".to_string())
                .expect("Invalid redirect URL"),
        );

        println!("Running");

        App::new()
            .app_data(Data::new(AppState {
                oauth: client,
                api_base_url,
            }))
            .service(index)
            .service(login)
            .service(logout)
            .service(auth)
    })
    .bind("127.0.0.1:5000")
    .expect("Can not bind to port 5000")
    .run()
    .await
    .expect("Unable to run");

    println!("Hello, world!");
}
