use actix_web::{web, App, HttpResponse, HttpServer, Responder};

// ============================================================================
// Authorization & Security Primitives
// ============================================================================

struct AdminGuard;
struct AuthorizationMiddleware;
struct AuthenticatedUser {
    pub id: String,
    pub role: String,
}

fn require_admin() {}
fn check_permission(_perm: &str) {}
fn is_owner(_resource_id: &str) -> bool { true }
fn verify_ownership(_resource_id: &str) {}

// ============================================================================
// Handlers: Admin Scope
// ============================================================================

async fn admin_get_users() -> impl Responder {
    require_admin();
    HttpResponse::Ok().body("users list")
}

async fn admin_get_reports() -> impl Responder {
    HttpResponse::Ok().body("reports")
}

async fn admin_get_audit_logs() -> impl Responder {
    HttpResponse::Ok().body("audit logs")
}

// Security Flaw (Drift): Missing authorization check under /api/v1/admin
async fn admin_get_analytics() -> impl Responder {
    HttpResponse::Ok().body("sensitive financial analytics")
}

// Intentionally public operational status endpoint
async fn admin_get_status() -> impl Responder {
    HttpResponse::Ok().body("healthy")
}

// ============================================================================
// Handlers: Parameterized Resource Scope (Documents)
// ============================================================================

async fn get_document_by_id(path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    is_owner(&id);
    HttpResponse::Ok().body("document content")
}

async fn delete_document_by_id(path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    verify_ownership(&id);
    HttpResponse::Ok().body("document deleted")
}

// Security Flaw (IDOR Drift): Parameterized route lacks ownership check
async fn update_document_by_id(_user: web::ReqData<AuthenticatedUser>, path: web::Path<String>) -> impl Responder {
    let _id = path.into_inner();
    // Vulnerable: user is authenticated, but ownership is never validated!
    HttpResponse::Ok().body("document updated")
}

// ============================================================================
// Handlers: Settings Scope
// ============================================================================

async fn get_security_settings() -> impl Responder {
    check_permission("settings.admin");
    HttpResponse::Ok().body("security settings")
}

// Security Flaw (Auth-Only Drift): Has AuthenticatedUser but missing permission check
async fn get_backup_settings(_user: web::ReqData<AuthenticatedUser>) -> impl Responder {
    HttpResponse::Ok().body("database backup configuration")
}

// ============================================================================
// Service Configuration
// ============================================================================

pub fn configure_app(cfg: &mut web::ServiceConfig) {
    // 1. Administrative Scope
    cfg.service(
        web::scope("/api/v1/admin")
            .route("/users", web::get().to(admin_get_users))
            .route("/reports", web::get().guard(AdminGuard).to(admin_get_reports))
            .route("/audit_logs", web::get().wrap(AuthorizationMiddleware).to(admin_get_audit_logs))
            .route("/analytics", web::get().to(admin_get_analytics))
            .route("/status", web::get().to(admin_get_status))
    );

    // 2. Documents Parameterized Scope
    cfg.service(
        web::scope("/api/v1/documents")
            .route("/{id}", web::get().to(get_document_by_id))
            .route("/{id}", web::delete().to(delete_document_by_id))
            .route("/{id}", web::put().to(update_document_by_id))
    );

    // 3. System Settings Scope
    cfg.service(
        web::scope("/api/v1/settings")
            .route("/security", web::get().to(get_security_settings))
            .route("/backup", web::get().to(get_backup_settings))
    );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().configure(configure_app))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
