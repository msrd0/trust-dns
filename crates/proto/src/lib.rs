// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
// Copyright 2017 Google LLC.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// LIBRARY WARNINGS
#![warn(
    clippy::default_trait_access,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::unimplemented,
    clippy::use_self,
    missing_copy_implementations,
    missing_docs,
    non_snake_case,
    non_upper_case_globals,
    rust_2018_idioms,
    unreachable_pub
)]
#![allow(
    clippy::single_component_path_imports,
    clippy::upper_case_acronyms, // can be removed on a major release boundary
    clippy::bool_to_int_with_if,
)]
#![recursion_limit = "2048"]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! Hickory DNS Protocol library

macro_rules! try_ready_stream {
    ($e:expr) => {{
        match $e {
            Poll::Ready(Some(Ok(t))) => t,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(From::from(e)))),
        }
    }};
}

#[cfg(feature = "dnssec-ring")]
pub mod dnssec;
mod error;
#[cfg(feature = "dns-over-https-rustls")]
pub mod h2;
#[cfg(feature = "dns-over-h3")]
pub mod h3;
#[cfg(any(feature = "dns-over-https-rustls", feature = "dns-over-h3"))]
pub mod http;
#[cfg(feature = "mdns")]
pub mod multicast;
pub mod op;
#[cfg(all(feature = "dns-over-quic", feature = "tokio-runtime"))]
pub mod quic;
pub mod rr;
pub mod runtime;
#[cfg(feature = "dns-over-rustls")]
pub mod rustls;
pub mod serialize;
pub mod tcp;
#[cfg(any(test, feature = "testing"))]
pub mod tests;
pub mod udp;
pub mod xfer;

#[doc(hidden)]
pub use crate::xfer::dns_handle::{DnsHandle, DnsStreamHandle};
#[doc(hidden)]
pub use crate::xfer::dns_multiplexer::DnsMultiplexer;
#[doc(hidden)]
pub use crate::xfer::retry_dns_handle::RetryDnsHandle;
#[doc(hidden)]
pub use crate::xfer::BufDnsStreamHandle;
#[cfg(feature = "backtrace")]
pub use error::{ExtBacktrace, ENABLE_BACKTRACE};
pub use error::{ForwardData, ForwardNSData, ProtoError, ProtoErrorKind};

#[cfg(feature = "dns-over-rustls")]
mod private {
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        server::{ResolvesServerCert, WantsServerCert},
        ConfigBuilder, ServerConfig,
    };
    use std::sync::Arc;

    pub trait CertificateAndKey {
        fn apply_to(
            self,
            builder: ConfigBuilder<ServerConfig, WantsServerCert>,
        ) -> Result<ServerConfig, rustls::Error>;
    }

    impl CertificateAndKey for (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        fn apply_to(
            self,
            builder: ConfigBuilder<ServerConfig, WantsServerCert>,
        ) -> Result<ServerConfig, rustls::Error> {
            let (cert, key) = self;
            builder.with_single_cert(cert, key)
        }
    }

    impl CertificateAndKey for Arc<dyn ResolvesServerCert> {
        fn apply_to(
            self,
            builder: ConfigBuilder<ServerConfig, WantsServerCert>,
        ) -> Result<ServerConfig, rustls::Error> {
            Ok(builder.with_cert_resolver(self))
        }
    }
}

#[cfg(feature = "dns-over-rustls")]
pub trait CertificateAndKey: private::CertificateAndKey {}

#[cfg(feature = "dns-over-rustls")]
impl<T: private::CertificateAndKey> CertificateAndKey for T {}
