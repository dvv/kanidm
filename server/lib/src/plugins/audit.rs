// A plugin that dumps to stdout the essense of create/update/delete operation.

use std::sync::Arc;

use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;

use std::thread;
use reqwest;

#[instrument(level = "info", skip_all)]
fn push_mercure(data: String) {
    if let Ok(mercure_url) = std::env::var("MERCURE_URL") {
        thread::spawn(move || {
            let params = [("topic", std::env::var("MERCURE_TOPIC").unwrap_or("passport".into())), ("data", data)];
            let client = reqwest::blocking::Client::new();
            client.post(mercure_url)
                .form(&params)
                .send()
                .or_else(|e| { admin_error!("MERCURE: {}", e); Err(e) })
        });
    }
}

fn log(record: serde_json::Value) {
    let payload = record.to_string();
    if let Ok(audit_perfix) = std::env::var("AUDIT_PREFIX") {
        println!("{}: {}", audit_perfix, &payload);
    }
    push_mercure(payload);
}

fn source_to_str(source: &Source) -> String {
    match source {
        Source::Internal => "0.0.0.0".into(),
        Source::Https(a) => a.to_string(),
        Source::Ldaps(a) => a.to_string(),
    }
}

fn modlist_to_json(mods: &ModifyList<ModifyValid>) -> serde_json::Value {
    mods.iter().fold(serde_json::json!({}), |mut a, m| {
        match m {
            Modify::Present(n, _) => { a[n.to_string()] = "update".into(); a },
            Modify::Removed(n, _) => { a[n.to_string()] = "remove".into(); a },
            Modify::Purged(n) => { a[n.to_string()] = "delete".into(); a },
            _ => a,
        }
    })
}

pub struct Audit {}

impl Plugin for Audit {
    fn id() -> &'static str {
        "plugin_poorman_audit"
    }

    fn post_create(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we committed that was valid?
        cand: &[EntrySealedCommitted],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Ok(match &ce.ident.origin {
            IdentType::Internal => (),
            IdentType::Synch(_u) => (),
            IdentType::User(u) => {
                log(serde_json::json!({
                    "kopid": sketching::tracing_forest::id(),
                    "event": "create",
                    "username": u.entry.get_uuid2spn().to_proto_string_clone(),
                    "user": u.entry.get_uuid(),
                    "session": &ce.ident.session_id,
                    "source": source_to_str(&ce.ident.source),
                    "entries": cand.iter().map(|x| x.get_uuid()).collect::<Vec<Uuid>>(),
                    // "data": format!("{:?}", ce.entries),
                }))
            },
        })
    }

    fn post_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Ok(match &me.ident.origin {
            IdentType::Internal => (),
            IdentType::Synch(_u) => (),
            IdentType::User(u) => {
                log(serde_json::json!({
                    "kopid": sketching::tracing_forest::id(),
                    "event": "update",
                    "username": u.entry.get_uuid2spn().to_proto_string_clone(),
                    "user": u.entry.get_uuid(),
                    "session": &me.ident.session_id,
                    "source": source_to_str(&me.ident.source),
                    "entries": cand.iter().map(|x| x.get_uuid()).collect::<Vec<Uuid>>(),
                    "data": modlist_to_json(&me.modlist),
                }))
            },
        })
    }

    fn post_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Ok(match &me.ident.origin {
            IdentType::Internal => (),
            IdentType::Synch(_u) => (),
            IdentType::User(u) => {
                log(serde_json::json!({
                    "kopid": sketching::tracing_forest::id(),
                    "event": "update",
                    "username": u.entry.get_uuid2spn().to_proto_string_clone(),
                    "user": u.entry.get_uuid(),
                    "session": &me.ident.session_id,
                    "source": source_to_str(&me.ident.source),
                    "entries": cand.iter().map(|x| x.get_uuid()).collect::<Vec<Uuid>>(),
                    "data": me.modset.iter().fold(serde_json::json!({}), |mut a, (i, &ref x)| { a[i.to_string()] = modlist_to_json(&x); a }),
                }))
            },
        })
    }

    fn post_delete(
        _qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Ok(match &de.ident.origin {
            IdentType::Internal => (),
            IdentType::Synch(_u) => (),
            IdentType::User(u) => {
                log(serde_json::json!({
                    "kopid": sketching::tracing_forest::id(),
                    "event": "delete",
                    "username": u.entry.get_uuid2spn().to_proto_string_clone(),
                    "user": u.entry.get_uuid(),
                    "session": &de.ident.session_id,
                    "source": source_to_str(&de.ident.source),
                    "entries": cand.iter().map(|x| x.get_uuid()).collect::<Vec<Uuid>>(),
                }))
            },
        })
    }
}
