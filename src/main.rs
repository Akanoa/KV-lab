use crate::header::HeaderMap;
use actix_files as fs;
use actix_files::NamedFile;
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::error::InternalError;
use actix_web::web::{Data, Json};
use actix_web::{delete, get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use eyre::WrapErr;
use log::debug;
use nanoid::nanoid;
use oauth2::basic::BasicClient;
use oauth2::http::{header, Method};
use oauth2::reqwest::http_client;
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;

#[derive(Serialize)]
struct Identitity {
    name: String,
    tokens: Vec<Token>,
}

#[derive(Serialize, Clone)]
struct Token {
    description: String,
    tenant: String,
    token: String,
}

#[derive(Deserialize)]
struct CreateData {
    description: String,
}

#[derive(Deserialize)]
struct DeleteData {
    tenant: String,
}

struct AppState {
    oauth: BasicClient,
    api_base_url: String,
    tokens: HashMap<String, Token>,
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Deserialize, Debug)]
pub struct UserData {
    id: u64,
    name: String,
    username: String,
    email: String,
}

#[get("/")]
async fn index(session: Session) -> Result<fs::NamedFile> {
    let login_value = session
        .get::<String>("login")
        .map_err(actix_web::error::ErrorBadRequest)?;

    if login_value.is_some() {
        Ok(NamedFile::open("assets/static/index.html")?)
    } else {
        Ok(NamedFile::open("assets/static/login.html")?)
    }
}

#[get("/logout")]
async fn logout(session: Session) -> HttpResponse {
    session.remove("login");
    HttpResponse::Found()
        .append_header((header::LOCATION, "/".to_string()))
        .finish()
}

#[get("/api/list")]
async fn list(app: Data<Mutex<AppState>>) -> Result<impl Responder> {
    if let Ok(guard) = app.lock() {
        let tokens = guard
            .tokens
            .values()
            .into_iter()
            .map(|c| c.clone())
            .collect::<Vec<Token>>();

        let identity = Identitity {
            name: "toto".to_string(),
            tokens,
        };
        Ok(Json(identity))
    } else {
        Err(actix_web::error::ErrorInternalServerError(
            "Unable to get identity",
        ))
    }
}

#[delete("/api/delete")]
async fn delete(form: web::Json<DeleteData>, app: Data<Mutex<AppState>>) -> Result<impl Responder> {
    if let Ok(mut guard) = app.lock() {
        guard.tokens.remove(&form.tenant);

        let tokens = guard
            .tokens
            .values()
            .into_iter()
            .map(|c| c.clone())
            .collect::<Vec<Token>>();

        let identity = Identitity {
            name: "toto".to_string(),
            tokens,
        };
        Ok(Json(identity))
    } else {
        Err(actix_web::error::ErrorInternalServerError(
            "Unable to get identity",
        ))
    }
}

#[post("/api/create")]
async fn create(form: web::Json<CreateData>, app: Data<Mutex<AppState>>) -> Result<impl Responder> {
    let token = Token {
        description: form.description.to_string(),
        tenant: nanoid!(5, &nanoid::alphabet::SAFE),
        token: nanoid!(128, &nanoid::alphabet::SAFE),
    };

    if let Ok(mut guard) = app.lock() {
        guard.tokens.insert(token.tenant.to_string(), token);

        let tokens = guard
            .tokens
            .values()
            .into_iter()
            .map(|c| c.clone())
            .collect::<Vec<Token>>();

        let identity = Identitity {
            name: "toto".to_string(),
            tokens,
        };
        Ok(Json(identity))
    } else {
        Err(actix_web::error::ErrorInternalServerError(
            "Unable to create token",
        ))
    }
}

#[get("/login")]
async fn login(session: Session, data: web::Data<AppState>) -> HttpResponse {
    // Generate a PKCE challenge
    // https://oa.dnc.global/-fr-.html?page=unarticle&id_article=148
    let (pkce_challenge, pcke_verifier) = PkceCodeChallenge::new_random_sha256();

    let a = session
        .insert("pkce_verifier", pcke_verifier)
        .wrap_err("Unable to save pkce verifier");

    if let Err(err) = a {
        debug!("{:?}", err)
    }

    let (auth_url, _) = &data
        .oauth
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("read_user".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    HttpResponse::Found()
        .append_header((header::LOCATION, auth_url.to_string()))
        .finish()
}

fn read_user(api_base_url: &str, access_token: &AccessToken) -> eyre::Result<UserData> {
    let url = Url::parse(
        format!(
            "{}/user?access_token={}",
            api_base_url,
            access_token.secret()
        )
        .as_str(),
    )
    .wrap_err("Unable to parse URL")?;
    let headers = HeaderMap::new();

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

    let pkce_verifier = session
        .get("pkce_verifier")
        .expect("Unable to get pkce verifier from session");

    match pkce_verifier {
        Some(pkce_verifier) => {
            let token = &data
                .oauth
                .exchange_code(code)
                .set_pkce_verifier(pkce_verifier)
                .request(http_client);
            match token {
                Ok(token) => {
                    let user_info = read_user(&data.api_base_url, token.access_token());

                    match user_info {
                        Ok(user_info) => {
                            if let Err(_) = session.insert("login", user_info.email.clone()) {
                                return HttpResponse::InternalServerError().finish();
                            }

                            HttpResponse::Found()
                                .append_header(("Location", "/"))
                                .finish()
                        }
                        Err(err) => {
                            log::error!("{:?}", err);
                            log::warn!("Unable to get user data");
                            HttpResponse::BadRequest().finish()
                        }
                    }
                }
                Err(err) => {
                    log::error!("{:?}", err);
                    log::warn!("Unable to get user data");
                    HttpResponse::BadRequest().finish()
                }
            }
        }
        None => {
            dbg!("Unable to found pkce verifier");
            HttpResponse::BadRequest().finish()
        }
    }
}

fn get_secret() -> Key {
    let secret = env::var("APP_SECRET").expect("Missing APP_SECRET environment variable");
    Key::from(secret.as_bytes())
}

#[actix_rt::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let app_host = env::var("APP_HOST").expect("Missing APP_HOST  environment variable.");

    let app_port = env::var("APP_PORT").expect("Missing APP_PORT  environment variable.");

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

        let redirect_url = env::var("GITLAB_SSO_REDIRECT_URL")
            .expect("Missing GITLAB_SSO_REDIRECT_URL environment variable.");

        let api_base_url = format!("https://{}/api/v4", oauth_server);

        let client = BasicClient::new(
            application_id,
            Some(application_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).expect("Invalid redirect URL"));

        println!("Running");

        App::new()
            .app_data(Data::new(Mutex::new(AppState {
                oauth: client,
                api_base_url,
                tokens: HashMap::new(),
            })))
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                get_secret(),
            ))
            .service(
                fs::Files::new("/static", "./assets/static")
                    .show_files_listing()
                    .index_file("login.html"),
            )
            .service(index)
            .service(login)
            .service(logout)
            .service(auth)
            .service(create)
            .service(list)
            .service(delete)
    })
    .bind(format!("{}:{}", app_host, app_port))
    .expect(format!("Can not bind to port {}", app_port).as_str())
    .run()
    .await
    .expect("Unable to run");
}
