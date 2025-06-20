use actix_web::{web, HttpResponse, Responder};

pub async fn index() -> HttpResponse {
    HttpResponse::Ok().body("Welcome to the Wi-Fi Monitor!")
}

pub async fn capture_data() -> HttpResponse {
    HttpResponse::Ok().body("Capturing data...")
}

pub async fn parse_data() -> HttpResponse {
    HttpResponse::Ok().body("Parsing data...")
}

pub async fn inject_frame() -> HttpResponse {
    HttpResponse::Ok().body("Injecting frame...")
}

pub async fn log_results() -> HttpResponse {
    HttpResponse::Ok().body("Logging results...")
}