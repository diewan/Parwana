/// Typestate compile-fail tests for csv-algebra
/// 
/// These tests verify that illegal state transitions are compile errors.
/// The typestate pattern in csv-algebra::state should make impossible
/// transitions fail at compile time, not runtime.

#[test]
fn illegal_transitions_are_compile_errors() {
    let t = trybuild::TestCases::new();
    
    // Test that backward transitions fail to compile
    t.compile_fail("tests/compile_fail/algebra_minting_to_locked.rs");
    t.compile_fail("tests/compile_fail/algebra_skip_awaiting_finality.rs");
    t.compile_fail("tests/compile_fail/algebra_proof_validated_to_locked.rs");
    
    // Test that invalid state methods don't exist
    t.compile_fail("tests/compile_fail/algebra_locked_to_minting.rs");
    t.compile_fail("tests/compile_fail/algebra_completed_to_proof_building.rs");
}
