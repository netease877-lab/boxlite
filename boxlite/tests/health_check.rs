//! Integration tests for health check functionality.
//!
//! # Prerequisites
//!
//! These tests require a real VM environment:
//! 1. Build the runtime: `make runtime-debug`
//! 2. Run with: `cargo test -p boxlite --test health_check -- --test-threads=1`

use boxlite::BoxliteRuntime;
use boxlite::litebox::HealthState;
use boxlite::runtime::advanced_options::{AdvancedBoxOptions, HealthCheckOptions};
use boxlite::runtime::options::{BoxOptions, BoxliteOptions, RootfsSpec};
use boxlite::runtime::types::BoxStatus;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

// ============================================================================
// TEST FIXTURES
// ============================================================================

/// Test context with isolated runtime and automatic cleanup.
struct TestContext {
    runtime: BoxliteRuntime,
    _temp_dir: TempDir,
}

impl TestContext {
    fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let options = BoxliteOptions {
            home_dir: temp_dir.path().to_path_buf(),
            image_registries: vec!["docker.m.daocloud.io".into()],
        };
        let runtime = BoxliteRuntime::new(options).expect("Failed to create runtime");
        Self {
            runtime,
            _temp_dir: temp_dir,
        }
    }

    /// Create a box with health check enabled
    async fn create_box_with_health_check(
        &self,
        interval: Duration,
        timeout: Duration,
        retries: u32,
        start_period: Duration,
    ) -> boxlite::LiteBox {
        let options = BoxOptions {
            rootfs: RootfsSpec::Image("alpine:latest".into()),
            advanced: AdvancedBoxOptions {
                health_check: Some(HealthCheckOptions {
                    interval,
                    timeout,
                    retries,
                    start_period,
                }),
                ..Default::default()
            },
            auto_remove: false,
            ..Default::default()
        };
        self.runtime
            .create(options, None)
            .await
            .expect("Failed to create box with health check")
    }
}

// ============================================================================
// CORE INTEGRATION TESTS
// ============================================================================

#[tokio::test]
async fn health_check_transitions_to_healthy_after_startup() {
    let ctx = TestContext::new();

    let handle = ctx
        .create_box_with_health_check(
            Duration::from_secs(2),
            Duration::from_secs(1),
            2,
            Duration::from_secs(1),
        )
        .await;

    // Start the box
    handle.start().await.expect("Failed to start box");

    // Initially in Starting state during start_period
    let info = ctx
        .runtime
        .get_info(handle.id().as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(info.health_status.state, HealthState::Starting);

    // Wait for start period to pass and first health check to complete
    sleep(Duration::from_secs(4)).await;

    // Should transition to Healthy after successful ping
    let info = ctx
        .runtime
        .get_info(handle.id().as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        info.health_status.state,
        HealthState::Healthy,
        "Expected health state to be Healthy, got {:?}",
        info.health_status.state
    );
    assert_eq!(info.health_status.failures, 0);

    // Cleanup
    handle.stop().await.unwrap();
    ctx.runtime
        .remove(handle.id().as_str(), false)
        .await
        .unwrap();
}

#[tokio::test]
async fn health_check_becomes_unhealthy_when_shim_killed() {
    let ctx = TestContext::new();

    let handle = ctx
        .create_box_with_health_check(
            Duration::from_secs(2),
            Duration::from_secs(1),
            2,
            Duration::from_secs(1),
        )
        .await;

    let box_id = handle.id().clone();

    // Start the box
    handle.start().await.expect("Failed to start box");

    // Wait for health check to become healthy
    sleep(Duration::from_secs(4)).await;

    // Verify initial healthy state
    let info = ctx
        .runtime
        .get_info(box_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(info.health_status.state, HealthState::Healthy);

    // Find and kill the shim process using BoxInfo
    let shim_pid = info.pid.expect("No shim PID found");
    println!("Killing shim process with PID: {}", shim_pid);

    Command::new("kill")
        .arg("-9")
        .arg(shim_pid.to_string())
        .output()
        .expect("Failed to kill shim process");

    // Wait for health check to detect the failure
    sleep(Duration::from_secs(5)).await;

    // Box should be stopped
    let info = ctx
        .runtime
        .get_info(box_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        info.status,
        BoxStatus::Stopped,
        "Expected box status to be Stopped, got {:?}",
        info.status
    );

    // Health status should be cleared or show unhealthy state
    // (depending on implementation - health check task stops when box stops)
    let health_status = info.health_status;
    println!(
        "Health status after shim killed: state={:?}, failures={}",
        health_status.state, health_status.failures
    );
    // Health status should indicate failures or unhealthy state
    assert!(
        health_status.state == HealthState::Unhealthy || health_status.failures > 0,
        "Expected unhealthy state or failures, got state={:?}, failures={}",
        health_status.state,
        health_status.failures
    );

    // Cleanup
    ctx.runtime.remove(box_id.as_str(), false).await.unwrap();
}
