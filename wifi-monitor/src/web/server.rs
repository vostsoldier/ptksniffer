use actix_web::{web, App, HttpServer, Responder};
use std::sync::Mutex;

#[derive(Clone)] 
struct AppState {
    captured_data: Mutex<Vec<String>>, // Store captured data
}

async fn index(data: web::Data<AppState>) -> impl Responder {
    let captured_data = data.captured_data.lock().unwrap();
    let response = captured_data.join("<br>");
    format!("Captured Data:<br>{}", response)
}

pub async fn start_server(state: AppState) -> std::io::Result<()> {
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}