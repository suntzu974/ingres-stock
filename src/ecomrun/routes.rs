use crate::ecomrun::{ArticleTarif,ResponseStock,ResponseTarif,QueryStock,QueryTarif,QueryTransfert,ResponseAppro};
use actix_web::{post,error,web, Error, HttpResponse};

use futures::{StreamExt};
const MAX_SIZE: usize = 524_288; // max payload size is 512k

#[post("/stockingres")]
pub async fn query(mut payload: web::Payload) ->  Result<HttpResponse, Error>  {

    let ip_tomcat = std::env::var("IP_TOMCAT").expect("IP TOMCAT NOT FOUND");
    let ip_tomcat_port = std::env::var("IP_TOMCAT_PORT").expect("IP TOMCAT PORT NOT FOUND");
    let ip_tomcat_app = std::env::var("IP_TOMCAT_APP").expect("IP TOMCAT APP NOT FOUND");

    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
         return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk); 
    }
    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<QueryStock>(&body)?;
    let client = reqwest::blocking::Client::new();
    let stocks:ResponseStock =  client.post(format!("{}://{}:{}/{}/{}","http",ip_tomcat,ip_tomcat_port,ip_tomcat_app,"stockingres"))
    .json(&obj)
    .send().unwrap()
    .json().unwrap();

    Ok(HttpResponse::Ok().json(stocks)) // <- send response
}
#[post("/tarif")]
pub async fn query_tarif(mut payload: web::Payload) ->  Result<HttpResponse, Error>  {

    let ip_tomcat = std::env::var("IP_TOMCAT").expect("IP TOMCAT NOT FOUND");
    let ip_tomcat_port = std::env::var("IP_TOMCAT_PORT").expect("IP TOMCAT PORT NOT FOUND");
    let ip_tomcat_app = std::env::var("IP_TOMCAT_APP").expect("IP TOMCAT APP NOT FOUND");

    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
         return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk); 
    }
    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<QueryTarif>(&body)?;
    let client = reqwest::blocking::Client::new();
    let tarifs:ResponseTarif =  client.post(format!("{}://{}:{}/{}/{}","http",ip_tomcat,ip_tomcat_port,ip_tomcat_app,"tarif"))
    .json(&obj)
    .send().unwrap()
    .json().unwrap();

    Ok(HttpResponse::Ok().json(tarifs)) // <- send response
}
#[post("/stocks")]
pub async fn query_by_gencod(mut payload: web::Payload) ->  Result<HttpResponse, Error>  {

    let ip_tomcat = std::env::var("IP_TOMCAT").expect("IP TOMCAT NOT FOUND");
    let ip_tomcat_port = std::env::var("IP_TOMCAT_PORT").expect("IP TOMCAT PORT NOT FOUND");
    let ip_tomcat_app = std::env::var("IP_TOMCAT_APP").expect("IP TOMCAT APP NOT FOUND");

    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
         return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk); 
    }
    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<QueryStock>(&body)?;
    let client = reqwest::blocking::Client::new();
    let stocks:ResponseStock =  client.post(format!("{}://{}:{}/{}/{}","http",ip_tomcat,ip_tomcat_port,ip_tomcat_app,"stocks"))
    .json(&obj)
    .send().unwrap()
    .json().unwrap();

    Ok(HttpResponse::Ok().json(stocks)) // <- send response
}

#[post("/transfert")]
pub async fn build_appro(mut payload: web::Payload) ->  Result<HttpResponse, Error>  {
    let ip_tomcat = std::env::var("IP_TOMCAT").expect("IP TOMCAT NOT FOUND");
    let ip_tomcat_port = std::env::var("IP_TOMCAT_PORT").expect("IP TOMCAT PORT NOT FOUND");
    let ip_tomcat_app = std::env::var("IP_TOMCAT_APP").expect("IP TOMCAT APP NOT FOUND");
    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
         return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk); 
    }
    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<QueryTransfert>(&body)?;
    let client = reqwest::blocking::Client::new();
    let appro:ResponseAppro = client.post(format!("{}://{}:{}/{}/{}","http",ip_tomcat,ip_tomcat_port,ip_tomcat_app,"transfert"))
    .json(&obj)
    .send().unwrap()
    .json().unwrap();

    Ok(HttpResponse::Ok().json(appro)) // <- send response
}

#[post("/newproducts")]
pub async fn new_products(mut payload: web::Payload) ->  Result<HttpResponse, Error>  {
    let ip_tomcat = std::env::var("IP_TOMCAT").expect("IP TOMCAT NOT FOUND");
    let ip_tomcat_port = std::env::var("IP_TOMCAT_PORT").expect("IP TOMCAT PORT NOT FOUND");
    let ip_tomcat_app = std::env::var("IP_TOMCAT_APP").expect("IP TOMCAT APP NOT FOUND");
    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
         return Err(error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk); 
    }
    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<QueryTransfert>(&body)?;
    let client = reqwest::blocking::Client::new();
    let appro:ResponseAppro = client.post(format!("{}://{}:{}/{}/{}","http",ip_tomcat,ip_tomcat_port,ip_tomcat_app,"newproducts"))
    .json(&obj)
    .send().unwrap()
    .json().unwrap();

    Ok(HttpResponse::Ok().json(appro)) // <- send response
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(query);
    cfg.service(query_tarif);
    cfg.service(query_by_gencod);
    cfg.service(build_appro);
    cfg.service(new_products);
}