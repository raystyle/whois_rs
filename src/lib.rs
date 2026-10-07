//! whois-binding: napi-rs 绑定 whois-rust(TCP 43 WHOIS),TypeScript 只看 Promise<string>。
//! 同步 lookup 是阻塞 TCP:走 AsyncTask(libuv 线程池),不用 async fn 套 tokio(双运行时打架)。
//! servers.json 经 include_str! 编进二进制,安装后无需找文件。

use napi::bindgen_prelude::*;
use napi_derive::napi;
use once_cell::sync::Lazy;
use whois_rust::{WhoIs, WhoIsLookupOptions};

static WHOIS: Lazy<WhoIs> = Lazy::new(|| {
    WhoIs::from_string(include_str!("../servers.json")).expect("servers.json is valid")
});

pub struct LookupTask {
    query: String,
}

#[napi]
impl Task for LookupTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let opts = WhoIsLookupOptions::from_string(&self.query)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        WHOIS
            .lookup(opts)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    fn resolve(&mut self, _env: Env, out: Self::Output) -> Result<Self::JsValue> {
        Ok(out)
    }
}

/// WHOIS lookup over TCP 43. Returns the raw whois text.
#[napi]
pub fn lookup(query: String) -> AsyncTask<LookupTask> {
    AsyncTask::new(LookupTask { query })
}
