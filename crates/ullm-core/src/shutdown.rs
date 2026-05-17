// SPDX-License-Identifier: Apache-2.0
//! Cross-platform graceful-shutdown signal helper.
//!
//! The TEE and gateway binaries both run as long-lived servers. Without
//! a SIGTERM/SIGINT handler they ignore the standard "please stop"
//! signal and orchestrators (systemd, Kubernetes, Docker) end up
//! SIGKILL-ing them after the grace period — dropping in-flight
//! sessions and leaving the transparency log without a final fsync.
//!
//! `shutdown_signal()` resolves when **either** SIGINT (Ctrl-C) or
//! SIGTERM (Unix only) fires, so the server can:
//!
//! 1. Stop accepting new connections.
//! 2. Wait (with a deadline) for in-flight sessions to drain.
//! 3. Let `Drop` impls flush + zeroize state.
//! 4. Exit 0.
//!
//! Windows doesn't have SIGTERM; only Ctrl-C is honoured there.
//!
//! ## `ShutdownBroadcaster`
//!
//! P10-FIX-A: binaries with **multiple listeners** (TEE protocol + TEE
//! mgmt, gateway public + gateway mgmt) used to share a single SIGTERM
//! via `Arc<tokio::sync::Notify>` + `notify_waiters()`. The P10 audit
//! found this had a registration race: the spawned task that calls
//! `notify_waiters()` could resolve **before** the `notified()`
//! futures inside `with_graceful_shutdown(...)` were polled for the
//! first time — `Notify::notify_waiters` only wakes *currently
//! registered* waiters. The signal would be silently missed and the
//! binary would never start draining.
//!
//! `ShutdownBroadcaster` solves this with `tokio::sync::watch::channel(bool)`
//! which **retains** the latest sent value. A subscriber that calls
//! `.subscribe()` AFTER `set_fired()` ran still sees `true` on its
//! first poll and resolves immediately. Same idempotence as `Notify`
//! but with the late-subscriber guarantee.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// P10-FIX-D: refuse to bind the management `/metrics` listener to a
/// non-loopback address unless the operator explicitly opts in via
/// `ULLM_METRICS_ALLOW_PUBLIC=1`. Sharing operator-internal gauges
/// across a network requires a deliberate choice, not a typo.
///
/// Returns `Ok(addr)` on loopback, `Ok(addr)` on non-loopback when the
/// override env-var is set (with a `tracing::warn!`), and `Err` on
/// non-loopback without override.
pub fn validate_metrics_addr(addr: SocketAddr, var_name: &str) -> Result<SocketAddr, String> {
    if addr.ip().is_loopback() {
        return Ok(addr);
    }
    match std::env::var("ULLM_METRICS_ALLOW_PUBLIC").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") => {
            tracing::warn!(
                ?addr,
                env = var_name,
                "binding /metrics to a non-loopback address (ULLM_METRICS_ALLOW_PUBLIC=1). \
                 Gauges leak operator-internal state — protect this listener with \
                 ULLM_METRICS_TOKEN + a firewall."
            );
            Ok(addr)
        }
        _ => Err(format!(
            "{var_name} = {addr} is not a loopback address. Refusing to expose /metrics \
             on the public network. Set ULLM_METRICS_ALLOW_PUBLIC=1 to override (and \
             ULLM_METRICS_TOKEN to gate access)."
        )),
    }
}

/// Wakes multiple async tasks on the first SIGTERM/SIGINT. Cheap to
/// clone (one Arc) and safe to subscribe from any number of tasks.
///
/// Construction spawns ONE signal-handler task that races SIGINT vs
/// SIGTERM (Unix); on first fire the watch value flips to `true` and
/// every present-or-future subscriber's `.wait().await` returns.
#[derive(Clone)]
pub struct ShutdownBroadcaster {
    rx: watch::Receiver<bool>,
}

impl ShutdownBroadcaster {
    /// Install signal handlers and return a broadcaster.
    ///
    /// **MUST be called from within a tokio runtime context.** Both
    /// `#[tokio::main]` and `Runtime::block_on(...)` provide one;
    /// calling this from a synchronous `fn main()` panics inside
    /// `tokio::spawn` and (on Windows) inside the `ctrl_c()`
    /// constructor.
    ///
    /// P11-FIX-A: the original implementation installed both signal
    /// streams *inside* the spawned task — a SIGTERM that arrived
    /// during the brief window between `tokio::spawn(...)` and the
    /// task's first poll was delivered to the process under the OS
    /// default disposition (terminate the process), bypassing our
    /// drain entirely. We now install the streams synchronously on
    /// the caller's thread, then `tokio::spawn` only the `.await`
    /// loop. Pre-spawn signals are queued in the stream and delivered
    /// on the first poll.
    ///
    /// P12-FIX-E: parity between platforms — both unix and windows
    /// now install their signal streams synchronously via fallible
    /// constructors that surface errors out of `install()`. The
    /// previous Windows path constructed the `ctrl_c()` future
    /// eagerly but any failure surfaced inside the spawned task
    /// (caller saw `Ok(Self)` with a silently-dead handler).
    pub fn install() -> std::io::Result<Self> {
        let (tx, rx) = watch::channel(false);
        let tx = Arc::new(tx);

        // Install signal streams eagerly (on the caller's thread)
        // before spawning the wait task. This closes the
        // "signal-during-spawn-setup" race where the OS would
        // deliver the signal under default disposition.
        #[cfg(unix)]
        let (mut sigint, mut sigterm) = {
            use tokio::signal::unix::{signal, SignalKind};
            (
                signal(SignalKind::interrupt())?,
                signal(SignalKind::terminate())?,
            )
        };
        // Windows path: install via `tokio::signal::windows::ctrl_c`
        // which returns `io::Result<CtrlC>` — install errors surface
        // synchronously, matching the unix branch's behavior.
        // Windows graceful shutdown only handles `CTRL_C_EVENT` +
        // `CTRL_BREAK_EVENT`; `CTRL_CLOSE_EVENT` (taskkill graceful)
        // and `CTRL_SHUTDOWN_EVENT` (system reboot) bypass our handler
        // and the binary terminates without drain — acceptable per
        // OPERATIONS.md (Linux/systemd-only deploy).
        #[cfg(not(unix))]
        let mut ctrl_c_stream = tokio::signal::windows::ctrl_c()?;

        tokio::spawn(async move {
            #[cfg(unix)]
            {
                tokio::select! {
                    _ = sigint.recv() => tracing::info!("received SIGINT, beginning graceful shutdown"),
                    _ = sigterm.recv() => tracing::info!("received SIGTERM, beginning graceful shutdown"),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = ctrl_c_stream.recv().await;
                tracing::info!("received Ctrl-C, beginning graceful shutdown");
            }
            // `send` returns Err only if all receivers dropped — safe to ignore.
            let _ = tx.send(true);
        });
        Ok(Self { rx })
    }

    /// Resolves the first time the signal handler flips the watch
    /// value to `true`. Repeat calls on the same receiver after fire
    /// return immediately (the value is sticky).
    ///
    /// P11-FIX-A: distinguish a real signal-fired flip from a
    /// sender-dropped error. If the spawned signal-handler task
    /// panics or the tokio runtime is being torn down, the sender
    /// drops and `changed()` returns `Err`. Treating that as "signal
    /// fired" makes every subscriber drain gracefully even though the
    /// signal subsystem is actually dead — a misleading soft-shutdown
    /// that masks a real failure. Instead, log and `pending().await`
    /// forever so the runtime's forcible abort is the visible outcome.
    pub async fn wait(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        match self.rx.changed().await {
            Ok(()) => {}
            Err(_) => {
                tracing::error!(
                    "shutdown broadcaster sender dropped without signal — \
                     signal-handler task likely panicked. Refusing to start \
                     drain; awaiting forcible runtime abort."
                );
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Resolves on the first SIGINT or SIGTERM (Unix) the process receives.
/// Logs the signal that fired so operators can audit which one
/// orchestration sent.
///
/// Prefer `ShutdownBroadcaster::install()` for binaries with multiple
/// listeners — this raw helper is left for single-listener cases and
/// for the broadcaster's internal use.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => tracing::info!("received SIGINT, beginning graceful shutdown"),
            Err(e) => tracing::warn!(error = %e, "failed to install Ctrl-C handler"),
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                tracing::info!("received SIGTERM, beginning graceful shutdown");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for P10-FIX-A: a subscriber that polls AFTER the
    /// signal has fired must still see the broadcast. The pre-fix
    /// `Notify::notify_waiters()` did not satisfy this; the new
    /// `watch::channel` does because the latest value is retained.
    #[tokio::test]
    async fn late_subscriber_sees_fired_signal() {
        let (tx, rx) = watch::channel(false);
        // Simulate the signal firing before any subscriber polls.
        tx.send(true).unwrap();
        let mut b = ShutdownBroadcaster { rx };
        // Should resolve essentially immediately.
        tokio::time::timeout(std::time::Duration::from_millis(100), b.wait())
            .await
            .expect("late subscriber missed already-fired signal");
    }

    /// Regression for P11-FIX-A: when the signal-handler task drops
    /// its sender without firing (panic, runtime tear-down), `wait()`
    /// MUST NOT resolve — masking a dead signal subsystem as "graceful
    /// drain started" lets a binary exit cleanly when it should be
    /// alerting/aborting. We verify by constructing a broadcaster,
    /// dropping the sender immediately, then asserting `wait()` does
    /// NOT resolve within a short window.
    #[tokio::test]
    async fn sender_drop_does_not_masquerade_as_signal() {
        let (tx, rx) = watch::channel(false);
        let mut b = ShutdownBroadcaster { rx };
        // Drop the sender without sending — simulates a panicked
        // signal-handler task.
        drop(tx);
        // `wait()` should fall into the `Err` branch and `pending`
        // forever. We give it 100ms; if it resolves in that window,
        // the bug is present.
        let res = tokio::time::timeout(std::time::Duration::from_millis(100), b.wait()).await;
        assert!(
            res.is_err(),
            "wait() resolved on sender-drop instead of pending — \
             a dead signal subsystem would silently trigger drain"
        );
    }
}
