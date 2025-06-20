use actix_web::{web, App, HttpServer, HttpResponse};
use std::sync::{Arc, Mutex}; 
use crate::web::handlers; 

#[derive(Clone)]
pub struct AppState {
    pub captured_data: Arc<Mutex<Vec<String>>>, 
}

pub async fn start_server(state: AppState) -> std::io::Result<()> {
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/", web::get().to(handlers::index)) 
    })
    .bind("0.0.0.0:8080")?  
    .run()
    .await
}