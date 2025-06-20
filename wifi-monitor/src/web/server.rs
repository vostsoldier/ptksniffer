use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use std::sync::{Arc, Mutex}; 

#[derive(Clone)]
pub struct AppState {
    pub captured_data: Arc<Mutex<Vec<String>>>, 
}

async fn index(data: web::Data<AppState>) -> HttpResponse {
    let captured_data = data.captured_data.lock().unwrap();
    let response = captured_data.join("<br>");
    HttpResponse::Ok().body(format!("Captured Data:<br>{}", response))
}

pub async fn start_server(state: AppState) -> std::io::Result<()> {
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/", web::get().to(index))
    })
    .bind("0.0.0.0:8080")?  
    .run()
    .await
}