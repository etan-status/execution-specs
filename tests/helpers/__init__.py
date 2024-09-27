# Update the links and commit has in order to consume
# newer/other tests
TEST_FIXTURES = {
    "execution_spec_tests": {
        "url": "https://github.com/ethereum/execution-spec-tests/releases/download/v0.2.5/fixtures.tar.gz",
        "fixture_path": "tests/fixtures/execution_spec_tests",
    },
    "evm_tools_testdata": {
        "url": "https://github.com/gurukamath/evm-tools-testdata.git",
        "commit_hash": "792422d",
        "fixture_path": "tests/fixtures/evm_tools_testdata",
    },
    "ethereum_tests": {
        "url": "https://github.com/ethereum/tests.git",
        "commit_hash": "9201075",
        "fixture_path": "tests/fixtures/ethereum_tests",
    },
    "latest_fork_tests": {
        "url": "https://github.com/etan-status/latest_fork_tests.git",
        "commit_hash": "eip-6404",
        "fixture_path": "tests/fixtures/latest_fork_tests",
    },
}
