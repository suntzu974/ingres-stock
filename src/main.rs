#[macro_use]
extern crate lazy_static;

use actix_web::{  web, App, HttpServer, Error, dev::ServiceRequest};
//use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_web_httpauth::extractors::bearer::{BearerAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use actix_web_httpauth::middleware::HttpAuthentication;
use core::pin::Pin;
use actix_web::middleware::Logger;
use env_logger::{Builder, Target};



mod ecomrun;


async fn bearer_auth_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    let config = req
        .app_data::<Config>()
        .map(|data| Pin::new(data).get_ref().clone())
        .unwrap_or_else(Default::default);
    match validate_token(credentials.token()) {
        Ok(res) => {
            if res == true {
                Ok(req)
            } else {
                Err(AuthenticationError::from(config).into())
            }
        }
        Err(_) => Err(AuthenticationError::from(config).into()),
    }
}
fn validate_token(str: &str) -> Result<bool, std::io::Error>
{
    if str.eq("a-secure-token")
    {
        return Ok(true);
    }
    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Authentication failed!"));
}


  
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::set_var("RUST_LOG", "actix_web=info");

    let mut builder_log = Builder::from_default_env();
    builder_log.target(Target::Stdout);

    builder_log.init();

    let host = std::env::var("HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = std::env::var("PORT").expect("PORT NOT FOUND");
   
    HttpServer::new(move || {
        let _auth = HttpAuthentication::bearer(bearer_auth_validator);
        App::new()
        //.wrap(auth)
        //.wrap(Logger::new("%a %{User-Agent}i size:%b  time:%T"))
        .data(web::JsonConfig::default().limit(4096))
        .configure(ecomrun::init_routes)
    })
    .bind(format!("{}:{}" ,host,port,) /*, builder*/)?
//    .bind_openssl(format!("{}:{}" ,host,port,), builder)?
    .run()
    .await
}

