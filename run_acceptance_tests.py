
import unittest


def main():
    print("=" * 60)
    print("SECURESCAN ACCEPTANCE TEST SUITE")
    print("=" * 60)
    print("Testing Flask, Semgrep wrapper, and AI integration...")
    print()

    suite = unittest.defaultTestLoader.discover(
        start_dir="tests",
        pattern="test_*.py"
    )

    result = unittest.TextTestRunner(verbosity=2).run(suite)

    print()
    print("=" * 60)
    print("ACCEPTANCE TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("Status: " + ("PASSED" if result.wasSuccessful() else "FAILED"))

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
