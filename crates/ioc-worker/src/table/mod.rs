//! Table functions exposed by the ioc worker, registered under `ioc.main`.

mod extract_iocs;

use vgi::Worker;

/// Register every table function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_table(extract_iocs::ExtractIocs);
}
