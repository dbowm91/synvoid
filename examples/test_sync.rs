fn assert_sync<T: ?Sized + Sync>() {}
fn main() {
    assert_sync::<synvoid::waf::WafCore>();
}
