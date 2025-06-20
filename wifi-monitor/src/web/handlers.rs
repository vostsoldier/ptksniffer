mod handlers {
    use actix_web::{web, HttpResponse, Responder};

    pub async fn index() -> impl Responder {
        HttpResponse::Ok().body("Welcome to the Wi-Fi Monitor!")
    }

    pub async fn capture_data() -> impl Responder {
        HttpResponse::Ok().body("Capturing data...")
    }

    pub async fn parse_data() -> impl Responder {
        HttpResponse::Ok().body("Parsing data...")
    }

    pub async fn inject_frame() -> impl Responder {
        HttpResponse::Ok().body("Injecting frame...")
    }

    pub async fn log_results() -> impl Responder {
        HttpResponse::Ok().body("Logging results...")
    }
}