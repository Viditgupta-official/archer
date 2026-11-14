#[actix_web::main]
async fn main() -> std::io::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("--analysis-worker") => {
            if archer::api::worker_main().is_err() {
                std::process::exit(1);
            }
            Ok(())
        }
        Some("--print-openapi") => {
            println!("{}", archer::api::openapi::document());
            Ok(())
        }
        None => archer::api::run().await,
        _ => Err(std::io::Error::other(
            "Only --print-openapi is supported; configuration uses ARCHER_* environment variables",
        )),
    }
}
