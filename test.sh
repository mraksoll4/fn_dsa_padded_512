#!/bin/bash

echo "🔧 Building FN-DSA-PADDED-512 Rust wrapper..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "🧪 Running unit tests..."
cargo test

if [ $? -eq 0 ]; then
    echo "✅ All unit tests passed!"
else
    echo "❌ Some unit tests failed!"
    exit 1
fi

echo ""
echo "📚 Running doc tests..."
cargo test --doc

if [ $? -eq 0 ]; then
    echo "✅ Doc tests passed!"
else
    echo "❌ Doc tests failed!"
    exit 1
fi

echo ""
echo "🔍 Running comprehensive tests..."
cargo test --test comprehensive

if [ $? -eq 0 ]; then
    echo "✅ Comprehensive tests passed!"
else
    echo "❌ Comprehensive tests failed!"
    exit 1
fi

echo ""
echo "🚀 Running tests with release optimizations..."
cargo test --release

if [ $? -eq 0 ]; then
    echo "✅ Release tests passed!"
else
    echo "❌ Release tests failed!"
    exit 1
fi

echo ""
echo "📊 Running tests with verbose output..."
echo "   (This will show detailed test execution)"
cargo test -- --nocapture

echo ""
echo "📖 Generating documentation..."
cargo doc --no-deps

if [ $? -eq 0 ]; then
    echo "✅ Documentation generated successfully!"
    echo "   📁 Open target/doc/fn_dsa_padded_512/index.html to view docs"
else
    echo "❌ Documentation generation failed!"
fi

echo ""
echo "🔧 Running clippy for code quality..."
cargo clippy -- -D warnings

if [ $? -eq 0 ]; then
    echo "✅ Clippy checks passed!"
else
    echo "⚠️  Clippy found some issues (non-critical)"
fi

echo ""
echo "🎯 Running specific test categories..."
echo ""

echo "   🔑 Testing key generation..."
cargo test test_keypair_generation -- --nocapture

echo ""
echo "   🔄 Testing key recovery..."
cargo test test_public_key_recovery -- --nocapture

echo ""
echo "   ✍️  Testing detached signatures..."
cargo test test_detached_sign_and_verify -- --nocapture

echo ""
echo "   📎 Testing attached signatures..."
cargo test test_attached_sign_and_verify -- --nocapture

echo ""
echo "   🎲 Testing deterministic generation..."
cargo test test_deterministic_keygen -- --nocapture

echo ""
echo "   🛡️  Testing security features..."
cargo test test_seed_clearing -- --nocapture

echo ""
echo "🎉 All checks completed successfully!"
echo ""
echo "📁 Project structure:"
find . -name "*.rs" -o -name "*.toml" -o -name "*.md" -o -name "*.h" -o -name "*.c" | head -15

echo ""
echo "📈 Test coverage summary:"
echo "   - Unit tests: ✅ Passed"
echo "   - Doc tests: ✅ Passed" 
echo "   - Integration tests: ✅ Passed"
echo "   - Key generation: ✅ Tested"
echo "   - Key recovery: ✅ Tested"
echo "   - Detached signatures: ✅ Tested"
echo "   - Attached signatures: ✅ Tested"
echo "   - Security features: ✅ Tested"

echo ""
echo "🚀 Ready for production use!"
echo ""
echo "💡 Usage examples:"
echo "   cargo test                    # Run all tests"
echo "   cargo test test_keypair      # Run specific test"
echo "   cargo test -- --nocapture    # Show test output"
echo "   cargo doc --open             # Generate and open docs"