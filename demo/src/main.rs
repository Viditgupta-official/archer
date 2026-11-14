//! Executable authorization demonstration, not production credential handling.
//! Fixed public demo tokens intentionally make HTTP behavior reproducible.
use actix_web::{error::ErrorForbidden, web, App, Error, HttpRequest, HttpResponse, HttpServer};

fn check_role(req: &HttpRequest, role: &str) -> Result<(), Error> {
    let token = req.headers().get("authorization").and_then(|v| v.to_str().ok());
    let allowed = match role {
        "Admin" => token == Some("Bearer demo-admin"),
        "Member" => token == Some("Bearer demo-member"),
        _ => false,
    };
    if !allowed { return Err(ErrorForbidden("role denied")); }
    Ok(())
}
fn require_auth(req: &HttpRequest, _kind: &str) -> Result<(), Error> {
    let token = req.headers().get("authorization").and_then(|v| v.to_str().ok());
    if token != Some("Bearer demo-admin") && token != Some("Bearer demo-member") {
        return Err(ErrorForbidden("credential denied"));
    }
    Ok(())
}
fn is_owner(req: &HttpRequest, id: &str) -> bool {
    req.headers().get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer demo-owner") && id == "owned"
}
async fn role_one(req: HttpRequest) -> Result<HttpResponse, Error> {
    check_role(&req, "Admin")?;
    Ok(HttpResponse::Ok().finish())
}
async fn role_two(req: HttpRequest) -> Result<HttpResponse, Error> {
    check_role(&req, "Admin")?;
    Ok(HttpResponse::Ok().finish())
}
async fn role_three(req: HttpRequest) -> Result<HttpResponse, Error> {
    check_role(&req, "Admin")?; // ARCHER_ROLE_MUTATION
    Ok(HttpResponse::Ok().finish())
}
async fn auth_one(req: HttpRequest) -> Result<HttpResponse, Error> {
    require_auth(&req, "session")?;
    Ok(HttpResponse::Ok().finish())
}
async fn auth_two(req: HttpRequest) -> Result<HttpResponse, Error> {
    require_auth(&req, "session")?;
    Ok(HttpResponse::Ok().finish())
}
async fn auth_three(req: HttpRequest) -> Result<HttpResponse, Error> {
    require_auth(&req, "session")?; // ARCHER_AUTH_MUTATION
    Ok(HttpResponse::Ok().finish())
}
async fn owner_one(req: HttpRequest, id: web::Path<String>) -> Result<HttpResponse, Error> {
    if !is_owner(&req, &id) { return Err(ErrorForbidden("owner denied")); }
    Ok(HttpResponse::Ok().finish())
}
async fn owner_two(req: HttpRequest, id: web::Path<String>) -> Result<HttpResponse, Error> {
    if !is_owner(&req, &id) { return Err(ErrorForbidden("owner denied")); }
    Ok(HttpResponse::Ok().finish())
}
async fn owner_three(req: HttpRequest, id: web::Path<String>) -> Result<HttpResponse, Error> {
    if !is_owner(&req, &id) { return Err(ErrorForbidden("owner denied")); } // ARCHER_OWNER_MUTATION
    Ok(HttpResponse::Ok().finish())
}
async fn member_profile(req: HttpRequest) -> Result<HttpResponse, Error> {
    check_role(&req, "Member")?;
    Ok(HttpResponse::Ok().finish())
}
async fn admin_profile(req: HttpRequest) -> Result<HttpResponse, Error> {
    check_role(&req, "Admin")?;
    Ok(HttpResponse::Ok().finish())
}
async fn public_info() -> HttpResponse { HttpResponse::Ok().body("public") }
pub fn configure_app(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/roles")
        .route("/{id}", web::get().to(role_one))
        .route("/{id}", web::put().to(role_two))
        .route("/{id}", web::delete().to(role_three)))
      .service(web::scope("/sessions")
        .route("/{id}", web::get().to(auth_one))
        .route("/{id}", web::put().to(auth_two))
        .route("/{id}", web::delete().to(auth_three)))
      .service(web::scope("/documents")
        .route("/{id}", web::get().to(owner_one))
        .route("/{id}", web::put().to(owner_two))
        .route("/{id}", web::delete().to(owner_three)))
      .service(web::scope("/profiles")
        .route("/{id}", web::get().to(member_profile))
        .route("/{id}", web::delete().to(admin_profile)))
      .route("/public/info", web::get().to(public_info));
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().configure(configure_app)).bind(("127.0.0.1", 8088))?.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[actix_web::test]
    async fn actual_request_enforcement_and_legitimate_policy_differences() {
        let app = actix_web::test::init_service(App::new().configure(configure_app)).await;
        for (path, token, expected) in [
            ("/roles/owned", "demo-member", 403),
            ("/roles/owned", "demo-admin", 200),
            ("/sessions/owned", "invalid", 403),
            ("/sessions/owned", "demo-member", 200),
            ("/documents/owned", "demo-owner", 200),
            ("/documents/another", "demo-owner", 403),
            ("/documents/owned", "demo-member", 403),
            ("/profiles/owned", "demo-member", 200),
            ("/profiles/owned", "demo-admin", 403),
            ("/public/info", "invalid", 200),
        ] {
            let req = actix_web::test::TestRequest::default().method(if path.starts_with("/profiles") || path.starts_with("/public") {actix_web::http::Method::GET} else {actix_web::http::Method::DELETE}).uri(path).insert_header(("authorization",format!("Bearer {token}"))).to_request();
            assert_eq!(actix_web::test::call_service(&app,req).await.status().as_u16(),expected,"{path} {token}");
        }
    }
}
