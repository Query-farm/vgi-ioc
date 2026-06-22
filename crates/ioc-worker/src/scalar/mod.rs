//! Scalar functions exposed by the ioc worker, registered under `ioc.main`.

mod classify;
mod extract;
mod fang;
mod version;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(version::IocVersion);

    // Defang / refang text transforms.
    worker.register_scalar(fang::Fang::defang());
    worker.register_scalar(fang::Fang::refang());

    // LIST(VARCHAR) extractors, one per indicator type.
    worker.register_scalar(extract::Extract::ipv4());
    worker.register_scalar(extract::Extract::ipv6());
    worker.register_scalar(extract::Extract::domains());
    worker.register_scalar(extract::Extract::urls());
    worker.register_scalar(extract::Extract::emails());
    worker.register_scalar(extract::Extract::hashes());
    worker.register_scalar(extract::Extract::cves());

    // Classifiers / predicates.
    worker.register_scalar(classify::HashType);
    worker.register_scalar(classify::IsIoc);
}
