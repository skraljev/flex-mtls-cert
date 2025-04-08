// Copyright 2023 Salesforce, Inc. All rights reserved.
mod generated;
use anyhow::{anyhow, Result};
use pdk::hl::*;
use std::collections::HashMap;

const EMAIL_SUBJECT_PREAMBLE: &str = "emailAddress=";
const NAME_SUBJECT_PREAMBLE: &str = "CN=";
const ORGANIZATION_SUBJECT_PREAMBLE: &str = "O=";
const ORGANIZATION_UNIT_PREAMBLE: &str = "OU=";
const COUNTRY_PREAMBLE: &str = "C=";
const LOCALITY_PREAMBLE: &str = "L=";
const STATE_PREAMBLE: &str = "ST=";

/// This function reads the property "path" from the StreamProperties and returns is as a String.
fn read_property(stream: &StreamProperties, path: &[&str]) -> String {
    let bytes = stream.read_property(path).unwrap_or_default();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Struct that contains the data we are interested in extracted from the subject field.
pub struct Subject {
    name: Option<String>,
    email: Option<String>,
    organization: Option<String>,
    organization_unit: Option<String>,
    country: Option<String>,
    locality: Option<String>,
    state: Option<String>,
    errors: Vec<String>,
}

/// Struct for holding SAN attributes
pub struct SanAttributes {
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
    email_addresses: Vec<String>,
    uri_sans: Vec<String>,
}

/// This function extracts the name, email, and additional attributes from the given subject field.
fn parse_subject(subject_field: &str) -> Subject {
    let split = subject_field.split(',');
    let mut email = None;
    let mut name = None;
    let mut organization = None;
    let mut organization_unit = None;
    let mut country = None;
    let mut locality = None;
    let mut state = None;
    let mut errors = Vec::new();

    for segment in split {
        let trimmed_segment = segment.trim();
        // We extract the email.
        if trimmed_segment.starts_with(EMAIL_SUBJECT_PREAMBLE) {
            email = Some(trimmed_segment.split_at(EMAIL_SUBJECT_PREAMBLE.len()).1.to_string())
        }
        // We extract the name.
        else if trimmed_segment.starts_with(NAME_SUBJECT_PREAMBLE) {
            name = Some(trimmed_segment.split_at(NAME_SUBJECT_PREAMBLE.len()).1.to_string())
        }
        // Extract organization
        else if trimmed_segment.starts_with(ORGANIZATION_SUBJECT_PREAMBLE) {
            organization = Some(trimmed_segment.split_at(ORGANIZATION_SUBJECT_PREAMBLE.len()).1.to_string())
        }
        // Extract organization unit
        else if trimmed_segment.starts_with(ORGANIZATION_UNIT_PREAMBLE) {
            organization_unit = Some(trimmed_segment.split_at(ORGANIZATION_UNIT_PREAMBLE.len()).1.to_string())
        }
        // Extract country
        else if trimmed_segment.starts_with(COUNTRY_PREAMBLE) {
            country = Some(trimmed_segment.split_at(COUNTRY_PREAMBLE.len()).1.to_string())
        }
        // Extract locality/city
        else if trimmed_segment.starts_with(LOCALITY_PREAMBLE) {
            locality = Some(trimmed_segment.split_at(LOCALITY_PREAMBLE.len()).1.to_string())
        }
        // Extract state/province
        else if trimmed_segment.starts_with(STATE_PREAMBLE) {
            state = Some(trimmed_segment.split_at(STATE_PREAMBLE.len()).1.to_string())
        }
    }

    // Check for missing required attributes and add errors
    if name.is_none() {
        errors.push("Common name missing from peer cert".to_string());
    }
    
    if email.is_none() {
        errors.push("Email address missing from peer cert".to_string());
    }

    Subject {
        name,
        email,
        organization,
        organization_unit,
        country,
        locality,
        state,
        errors,
    }
}

/// This function parses SAN attributes from the certificate
fn parse_san_attributes(stream: &StreamProperties) -> SanAttributes {
    let mut san_attributes = SanAttributes {
        dns_names: Vec::new(),
        ip_addresses: Vec::new(),
        email_addresses: Vec::new(),
        uri_sans: Vec::new(),
    };

    // Parse DNS SANs
    let dns_sans = read_property(stream, &["connection", "dns_sans_peer_certificate"]);
    if !dns_sans.is_empty() {
        san_attributes.dns_names = dns_sans.split(',').map(|s| s.trim().to_string()).collect();
    }

    // Parse URI SANs
    let uri_sans = read_property(stream, &["connection", "uri_sans_peer_certificate"]);
    if !uri_sans.is_empty() {
        san_attributes.uri_sans = uri_sans.split(',').map(|s| s.trim().to_string()).collect();
    }
    
    // Parse IP SANs - assuming they're available in a similar format
    let ip_sans = read_property(stream, &["connection", "ip_sans_peer_certificate"]);
    if !ip_sans.is_empty() {
        san_attributes.ip_addresses = ip_sans.split(',').map(|s| s.trim().to_string()).collect();
    }

    // Parse email SANs
    let email_sans = read_property(stream, &["connection", "email_sans_peer_certificate"]);
    if !email_sans.is_empty() {
        san_attributes.email_addresses = email_sans.split(',').map(|s| s.trim().to_string()).collect();
    }

    san_attributes
}

/// This filter reads the subject field from the peer certificate and adds attributes as headers.
async fn request_filter(request_state: RequestState, stream: StreamProperties) -> Flow<()> {
    let headers_state = request_state.into_headers_state().await;
    let subject_field = read_property(&stream, &["connection", "subject_peer_certificate"]);
    
    // Set header to indicate if certificate is present
    if subject_field.is_empty() {
        headers_state.handler().set_header("X-Peer-Certificate-Present", "false");
        return Flow::Continue(());
    }
    
    headers_state.handler().set_header("X-Peer-Certificate-Present", "true");
    
    // Parse subject and set headers
    let subject = parse_subject(&subject_field);
    
    // Set basic subject headers if available
    if let Some(name) = &subject.name {
        headers_state.handler().set_header("X-Peer-Name", name);
    }
    
    if let Some(email) = &subject.email {
        headers_state.handler().set_header("X-Peer-Email", email);
    }
    
    // Set optional subject headers if available
    if let Some(org) = &subject.organization {
        headers_state.handler().set_header("X-Peer-Organization", org);
    }
    
    if let Some(ou) = &subject.organization_unit {
        headers_state.handler().set_header("X-Peer-OrganizationUnit", ou);
    }
    
    if let Some(country) = &subject.country {
        headers_state.handler().set_header("X-Peer-Country", country);
    }
    
    if let Some(locality) = &subject.locality {
        headers_state.handler().set_header("X-Peer-Locality", locality);
    }
    
    if let Some(state) = &subject.state {
        headers_state.handler().set_header("X-Peer-State", state);
    }
    
    // Add error messages if there are any
    if !subject.errors.is_empty() {
        headers_state.handler().set_header("X-Peer-Certificate-Errors", subject.errors.join("; ").as_str());
    }
    
    // Parse and set SAN attributes
    let san_attributes = parse_san_attributes(&stream);
    
    // Add DNS SANs
    if !san_attributes.dns_names.is_empty() {
        headers_state.handler().set_header("X-Peer-SAN-DNS", san_attributes.dns_names.join(",").as_str());
        // Add first DNS SAN as a separate header for convenience
        if let Some(primary_dns) = san_attributes.dns_names.first() {
            headers_state.handler().set_header("X-Peer-Primary-DNS", primary_dns);
        }
    }
    
    // Add IP SANs
    if !san_attributes.ip_addresses.is_empty() {
        headers_state.handler().set_header("X-Peer-SAN-IP", san_attributes.ip_addresses.join(",").as_str());
        // Add first IP SAN as a separate header
        if let Some(primary_ip) = san_attributes.ip_addresses.first() {
            headers_state.handler().set_header("X-Peer-Primary-IP", primary_ip);
        }
    }
    
    // Add Email SANs (might duplicate the subject email, but included for completeness)
    if !san_attributes.email_addresses.is_empty() {
        headers_state.handler().set_header("X-Peer-SAN-Email", san_attributes.email_addresses.join(",").as_str());
    }
    
    // Add URI SANs
    if !san_attributes.uri_sans.is_empty() {
        headers_state.handler().set_header("X-Peer-SAN-URI", san_attributes.uri_sans.join(",").as_str());
    }
    
    // Always continue the flow
    Flow::Continue(())
}

#[entrypoint]
async fn configure(launcher: Launcher) -> Result<()> {
    let filter = on_request(request_filter);
    launcher.launch(filter).await?;
    Ok(())
}