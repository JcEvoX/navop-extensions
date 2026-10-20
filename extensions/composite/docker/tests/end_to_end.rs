use std::{fs, path::Path, sync::Arc, time::Duration};

use extension_host::{
    HostError, NegotiationConfig, ProcessRpcSession, ProcessRpcSessionConfig, SpawnConfig,
    UniversalPluginClient,
};
use extension_protocol::{
    resource::{ResourceCloseParams, ResourceInvokeParams, ResourceOpenParams},
    result_ref::ResultRef,
};
use serde_json::{Value, json};

fn copy_executable(source: &Path, destination: &Path) {
    // 不用 `fs::copy`:它在 Linux 上走 copy_file_range,overlayfs(GitHub runner 的
    // 根文件系统)上目标 inode 的写引用可能还没释放,紧接着 execve 就偶发 ETXTBSY。
    // 显式 read/write + sync_all,在 spawn 之前把写入彻底收尾。
    let bytes = fs::read(source).expect("read provider executable");
    {
        use std::io::Write;
        let mut file = fs::File::create(destination).expect("create provider executable");
        file.write_all(&bytes).expect("write provider executable");
        file.sync_all().expect("flush provider executable");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(destination).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(destination, permissions).unwrap();
    }
}

/// Linux 上 execve 返回 ETXTBSY(`Text file busy`)当目标文件仍被写引用:
/// 报错本身是瞬时的,重试即可恢复,不能当成真实失败。
fn is_executable_busy(error: &HostError) -> bool {
    matches!(
        error,
        HostError::Io(io) if io.kind() == std::io::ErrorKind::ExecutableFileBusy
    )
}

/// 起 provider 进程;对 ETXTBSY 做有限重试(见 `is_executable_busy`)。
async fn start_session(config: ProcessRpcSessionConfig) -> Arc<ProcessRpcSession> {
    const MAX_ATTEMPTS: u32 = 6;
    let mut attempt = 0;
    loop {
        match ProcessRpcSession::start(config.clone()).await {
            Ok(session) => return Arc::new(session),
            Err(error) if is_executable_busy(&error) && attempt + 1 < MAX_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
            }
            Err(error) => panic!("start provider: {error:?}"),
        }
    }
}

#[tokio::test]
#[ignore = "requires NAVOP_DOCKER_SOCKET pointing to a live Docker daemon"]
async fn live_docker_provider_smoke() {
    let socket = std::env::var("NAVOP_DOCKER_SOCKET")
        .expect("NAVOP_DOCKER_SOCKET is required, e.g. unix://~/.docker/run/docker.sock");
    let root = tempfile::tempdir().unwrap();
    let bin_dir = root.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    copy_executable(
        Path::new(env!("CARGO_BIN_EXE_docker-provider")),
        &bin_dir.join("docker-provider"),
    );
    let spawn = SpawnConfig::new(bin_dir.join("docker-provider"))
        .with_program_root(root.path())
        .with_ready_timeout(Duration::from_secs(5));
    let config = ProcessRpcSessionConfig::new(
        spawn,
        NegotiationConfig::new("0.17.0", "docker-e2e").offer_api("extension", "1.0"),
    )
    .with_request_timeout(Duration::from_secs(10))
    .with_shutdown_grace_ms(2_500)
    .with_label("com.navop.docker::main");
    let session = start_session(config).await;
    let client = UniversalPluginClient::new(Arc::clone(&session));
    let opened = client
        .open_resource(&ResourceOpenParams {
            resource_type: "docker".into(),
            config: json!({"socket": socket}),
            metadata: None,
        })
        .await
        .expect("open Docker resource");

    assert!(opened.capabilities.contains(&"docker/system/info".into()));
    // 容器生命周期与镜像管理能力必须全部声明。
    for capability in [
        "docker/container/start",
        "docker/container/stop",
        "docker/container/restart",
        "docker/container/remove",
        "docker/container/logs",
        "docker/image/list",
        "docker/image/remove",
    ] {
        assert!(
            opened.capabilities.contains(&capability.into()),
            "capability {capability} must be declared"
        );
    }
    let info = invoke(
        &client,
        &opened.resource_id,
        "docker/system/info",
        Value::Null,
    )
    .await;
    assert!(
        info.is_object(),
        "Docker info must be a JSON object: {info}"
    );
    let listed = invoke(
        &client,
        &opened.resource_id,
        "docker/container/list",
        Value::Null,
    )
    .await;
    let containers = listed["containers"].as_array().expect("container array");
    if let Some(id) = containers
        .first()
        .and_then(|container| container["id"].as_str())
    {
        let inspected = invoke(
            &client,
            &opened.resource_id,
            "docker/container/inspect",
            json!({"id": id}),
        )
        .await;
        assert!(
            inspected.is_object(),
            "container inspect must return a JSON object: {inspected}"
        );
        // 日志读取(只读):退出容器同样有日志可读。
        let logs = invoke(
            &client,
            &opened.resource_id,
            "docker/container/logs",
            json!({"id": id, "tail": "50"}),
        )
        .await;
        assert!(
            logs["logs"].is_string(),
            "container logs must return a string payload: {logs}"
        );
    }

    // 镜像列表(只读):任何 daemon 都至少有一个镜像。
    let images = invoke(
        &client,
        &opened.resource_id,
        "docker/image/list",
        Value::Null,
    )
    .await;
    let image_rows = images["images"].as_array().expect("image array");
    assert!(
        !image_rows.is_empty(),
        "daemon must report at least one image"
    );
    assert!(
        image_rows[0]["name"].is_string() && image_rows[0]["id"].is_string(),
        "image rows must expose name/id: {image_rows:?}"
    );

    client
        .close_resource(&ResourceCloseParams {
            resource_id: opened.resource_id,
        })
        .await
        .expect("close Docker resource");
    session.shutdown().await;
}

async fn invoke(
    client: &extension_host::UniversalPluginClient,
    resource_id: &str,
    method: &str,
    params: Value,
) -> Value {
    let result = client
        .invoke_resource(&ResourceInvokeParams {
            resource_id: resource_id.into(),
            method: method.into(),
            params,
        })
        .await
        .unwrap_or_else(|error| panic!("{method} failed: {error}"));
    let ResultRef::Inline { value } = result.result else {
        panic!("{method} must return inline JSON")
    };
    value
}
