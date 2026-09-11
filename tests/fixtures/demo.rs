use actix_web::{web, App};

fn require_admin() {}

fn get_users() {
    require_admin();
}
fn get_orders() {}
fn get_reports() {}
fn get_payments() {}
fn post_audit() {}

fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/users", web::get().to(get_users))
            .route("/orders", web::get().wrap(AuthorizationMiddleware).to(get_orders))
            .route("/reports", web::get().guard(AdminGuard).to(get_reports))
            .route("/payments", web::get().to(get_payments))
            .route("/audit", web::post().to(post_audit))
    );
}
