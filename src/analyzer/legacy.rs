//! Frozen prototype behavior retained only for regression tests.
use super::*;

pub(super) fn build_analysis_layers(
    routes: &[Route],
) -> (
    Vec<PeerGroup>,
    Vec<AuthorizationInvariant>,
    Vec<Finding>,
    Vec<String>,
) {
    let mut grouped_routes: Vec<Vec<&Route>> = Vec::new();
    for route in routes {
        if is_authentication_route(route)
            || is_operational_public_route(route)
            || grouped_routes.iter().any(|group| {
                group
                    .iter()
                    .any(|candidate| route_identity(candidate) == route_identity(route))
            })
        {
            continue;
        }
        let peers = unique_routes(
            routes
                .iter()
                .filter(|candidate| same_peer_group(route, candidate)),
        );
        if peers.len() >= 2 && peers.iter().any(|peer| peer.is_authorized()) {
            grouped_routes.push(peers);
        }
    }

    let mut peer_groups = Vec::new();
    let mut invariants = Vec::new();
    let mut finding_details = Vec::new();
    let mut findings = Vec::new();

    for (index, peers) in grouped_routes.iter().enumerate() {
        let id = format!("peer-group-{:03}", index + 1);
        let first = peers[0];
        let description = format!(
            "{} {} routes under {}",
            first.method,
            route_shape_description(first),
            if first.scope_prefix.is_empty() {
                "/"
            } else {
                &first.scope_prefix
            }
        );
        let references: Vec<RouteReference> = peers.iter().map(|route| (*route).into()).collect();
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: description.clone(),
            routes: references.clone(),
        });

        let authorized = peers.iter().filter(|route| route.is_authorized()).count();
        let unknown = peers
            .iter()
            .filter(|route| matches!(route.security_status(), RouteSecurityStatus::Unknown { .. }))
            .count();
        let unauthorized = peers.len().saturating_sub(authorized + unknown);

        let mut evidence_patterns: Vec<String> = peers
            .iter()
            .flat_map(|route| {
                route
                    .authorization
                    .iter()
                    .map(|evidence| evidence.mechanism.clone())
            })
            .collect();
        evidence_patterns.sort();
        evidence_patterns.dedup();

        let is_parameterized = dynamic_segment_shape(first).iter().any(|d| *d);
        let scope_backing_authorized = if !first.scope_prefix.is_empty() {
            routes
                .iter()
                .filter(|r| {
                    r.scope_prefix == first.scope_prefix
                        && r.method == first.method
                        && r.is_authorized()
                })
                .count()
        } else {
            0
        };

        let has_sufficient_backing = authorized >= 2
            || (is_parameterized && authorized >= 1 && scope_backing_authorized >= 2);

        let strength = invariant_strength(authorized, peers.len());

        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Peer routes under {} consistently contain authorization evidence.",
                if first.scope_prefix.is_empty() {
                    "/"
                } else {
                    &first.scope_prefix
                }
            ),
            total_routes: peers.len(),
            routes_with_authorization: authorized,
            routes_without_authorization: unauthorized,
            evidence_patterns,
            strength,
        };
        invariants.push(invariant.clone());

        if !has_sufficient_backing || unauthorized == 0 {
            continue;
        }

        for route in peers
            .iter()
            .filter(|route| matches!(route.security_status(), RouteSecurityStatus::Unprotected))
        {
            let authorized_peer_routes: Vec<RouteReference> = peers
                .iter()
                .filter(|peer| peer.is_authorized())
                .map(|peer| (*peer).into())
                .collect();

            let category = if route
                .authorization
                .iter()
                .any(|e| matches!(e.kind, AuthEvidenceKind::IdentityExtraction))
            {
                DriftCategory::AuthenticationOnlyWithoutAuthorization
            } else if dynamic_segment_shape(route).iter().any(|d| *d)
                && peers.iter().any(|p| {
                    p.authorization
                        .iter()
                        .any(|e| matches!(e.kind, AuthEvidenceKind::OwnershipCheck))
                })
            {
                DriftCategory::MissingOwnershipValidation
            } else if peers.iter().any(|p| {
                p.authorization
                    .iter()
                    .any(|e| matches!(e.kind, AuthEvidenceKind::RoleCheck))
            }) && route
                .authorization
                .iter()
                .any(|e| matches!(e.kind, AuthEvidenceKind::RoleCheck))
            {
                DriftCategory::InconsistentRoleOrPermission
            } else if peers.iter().all(|p| {
                p.authorization.iter().any(|e| {
                    matches!(
                        e.kind,
                        AuthEvidenceKind::AuthorizationGuard
                            | AuthEvidenceKind::AuthorizationMiddleware
                    )
                })
            }) && !route.authorization.is_empty()
            {
                DriftCategory::InconsistentMechanism
            } else {
                DriftCategory::MissingEnforcement
            };

            let confidence = match invariant.strength {
                AuthStrength::Strong => DriftConfidence::High,
                AuthStrength::Medium => DriftConfidence::Medium,
                AuthStrength::Weak => DriftConfidence::Low,
            };

            let (explanation, remediation) = match &category {
                DriftCategory::AuthenticationOnlyWithoutAuthorization => (
                    "Route extracts identity or claims (authentication) but lacks authorization enforcement (role, permission, guard, or middleware check). Authenticated users can access this endpoint regardless of privileges.".to_string(),
                    "Add an explicit authorization check (e.g. `require_admin(&user)`), permission check, or guard to verify authorization following identity extraction.".to_string(),
                ),
                DriftCategory::MissingOwnershipValidation => (
                    "Peer parameterized resource routes enforce resource ownership validation, but this route does not validate that the authenticated entity owns the requested resource (IDOR risk).".to_string(),
                    "Add ownership verification logic (e.g. `check_ownership(user_id, resource_id)`) before serving sensitive resource data.".to_string(),
                ),
                DriftCategory::InconsistentRoleOrPermission => (
                    "Route authorization policy enforces a role or permission that deviates from the consensus role required by its peer routes.".to_string(),
                    "Align the required role or permission with the peer group invariant.".to_string(),
                ),
                DriftCategory::InconsistentMechanism => (
                    "Peer routes consistently use route-level guards or middleware, but this route uses ad-hoc or disparate mechanisms, violating architectural consistency.".to_string(),
                    "Standardize on the peer group's architectural protection mechanism (e.g. guard or middleware).".to_string(),
                ),
                DriftCategory::MissingEnforcement => (
                    format!(
                        "Route in scope '{}' lacks recognized authorization protection while {} peer routes consistently enforce authorization.",
                        if first.scope_prefix.is_empty() { "/" } else { &first.scope_prefix },
                        authorized
                    ),
                    "Apply the inferred authorization invariant to this route via a guard, middleware, or handler check.".to_string(),
                ),
                DriftCategory::UnresolvedSecurityPosture => (
                    "Route handler could not be uniquely resolved or analyzed; posture is unknown.".to_string(),
                    "Verify handler path and export scope so static analysis can inspect authorization checks.".to_string(),
                ),
            };

            finding_details.push(Finding {
                peer_group_id: id.clone(),
                invariant: invariant.clone(),
                suspicious_route: (*route).into(),
                suspicious_route_evidence: route.authorization.clone(),
                authorized_peer_routes,
                category,
                confidence,
                explanation,
                remediation,
            });

            let peer_lines = peers
                .iter()
                .filter(|peer| peer.is_authorized())
                .map(|peer| {
                    format!(
                        "    - {} {}\n      {}",
                        peer.method,
                        peer.path,
                        format_evidence(peer)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            findings.push(format!(
                "  Suspicious route: {} {} ({}:{})\n\
  Inferred invariant: {}\n\
  Authorized peer evidence ({} route(s)):\n{}\n\
  Suspicious route evidence: {}.",
                route.method,
                route.path,
                route.file.display(),
                route.line,
                invariant.description,
                authorized,
                peer_lines,
                format_evidence(route)
            ));
        }
    }

    (peer_groups, invariants, finding_details, findings)
}

#[allow(dead_code)]

pub(super) fn infer_prototype_drift(routes: &[Route]) -> Vec<String> {
    build_analysis_layers(routes).3
}

pub(super) fn invariant_strength(authorized: usize, total: usize) -> AuthStrength {
    if authorized == total || authorized >= 3 {
        AuthStrength::Strong
    } else if authorized >= 2 {
        AuthStrength::Medium
    } else {
        AuthStrength::Weak
    }
}

pub(super) fn route_shape_description(route: &Route) -> String {
    if dynamic_segment_shape(route).iter().any(|dynamic| *dynamic) {
        "parameterized".into()
    } else {
        "static".into()
    }
}

pub(super) fn format_evidence(route: &Route) -> String {
    if route.authorization.is_empty() {
        return "No recognized authorization evidence".into();
    }
    route
        .authorization
        .iter()
        .map(|evidence| {
            format!(
                "{:?}: {} at {}:{} ({:?})",
                evidence.kind,
                evidence.mechanism,
                evidence.file.display(),
                evidence.line,
                evidence.strength
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn same_peer_group(route: &Route, candidate: &Route) -> bool {
    if route.scope_prefix != candidate.scope_prefix
        || route_segment_count(route) != route_segment_count(candidate)
        || dynamic_segment_shape(route) != dynamic_segment_shape(candidate)
    {
        return false;
    }

    if is_authentication_route(route) || is_authentication_route(candidate) {
        return route.path == candidate.path;
    }

    if is_operational_public_route(route) || is_operational_public_route(candidate) {
        return route.path == candidate.path;
    }

    if route.method != candidate.method {
        let is_parameterized = dynamic_segment_shape(route).iter().any(|d| *d);
        if !(is_parameterized && route.path == candidate.path) {
            return false;
        }
    }

    true
}

pub(super) fn route_segment_count(route: &Route) -> usize {
    route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

pub(super) fn unique_routes<'a, I>(routes: I) -> Vec<&'a Route>
where
    I: IntoIterator<Item = &'a Route>,
{
    let mut unique: Vec<&'a Route> = Vec::new();
    for route in routes {
        if !unique
            .iter()
            .any(|candidate| route_identity(candidate) == route_identity(route))
        {
            unique.push(route);
        }
    }
    unique
}

pub(super) fn route_identity(route: &Route) -> (&str, &str, &str, Option<&str>) {
    (
        &route.method,
        &route.path,
        &route.scope_prefix,
        route.handler.as_deref(),
    )
}
