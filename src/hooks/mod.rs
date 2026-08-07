pub mod connect;
pub mod host_lookup;
pub mod mem;

pub unsafe fn hook() {
    host_lookup::hook_host_lookup();
    connect::hook();
}
