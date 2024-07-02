use std::{fs::File, io::BufReader};

use actix_web::{http::header, middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use actix_cors::Cors;
use log::debug;
use rustls::{pki_types::PrivateKeyDer, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct HealthStatus {
    status: String,
}

#[derive(Debug, Serialize)]
struct GetHealthResponse {
    data: HealthStatus,
}

async fn health(req: HttpRequest) -> HttpResponse {
    debug!("{req:?}");
    log::info!("Request passed!");

    let response = GetHealthResponse {
        data: HealthStatus {
            status: "alive".to_string(),
        },
    };
    HttpResponse::Ok().json(response)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let config = load_rustls_config();

    log::info!("starting HTTPS server at https://localhost:8443");

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
            .allowed_header(header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // enable CORS
            .wrap(cors)
            // register simple handler, handle all methods
            .service(web::resource("/admin-api/health").to(health))
    })
    .bind_rustls_0_23("127.0.0.1:8443", config)?
    .run()
    .await
}

fn load_rustls_config() -> rustls::ServerConfig {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let config = ServerConfig::builder().with_no_client_auth();
    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("key.pem").unwrap());

    let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>().unwrap();
    let mut keys = pkcs8_private_keys(key_file)
        .map(|key| key.map(PrivateKeyDer::Pkcs8))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    if keys.is_empty() {
        eprintln!("Could not locate PKCS 8 private keys.");
        std::process::exit(1);
    }

    config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
}
