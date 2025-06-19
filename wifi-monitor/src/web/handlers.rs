mod handlers {
    use actix_web::{web, HttpResponse, Responder};

    pub async fn index() -> impl Responder {
        HttpResponse::Ok().body("Welcome to the Wi-Fi Monitor!")
    }

    pub async fn capture_data() -> impl Responder {
        // Logic to capture and return data
        HttpResponse::Ok().body("Capturing data...")
    }

    pub async fn parse_data() -> impl Responder {
        // Logic to parse and return parsed data
        HttpResponse::Ok().body("Parsing data...")
    }

    pub async fn inject_frame() -> impl Responder {
        // Logic to inject a crafted frame
        HttpResponse::Ok().body("Injecting frame...")
    }

    pub async fn log_results() -> impl Responder {
        // Logic to log results
        HttpResponse::Ok().body("Logging results...")
    }
}