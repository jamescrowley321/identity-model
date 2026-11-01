# Pre-release Testing Guide

This guide explains how to create and test pre-release versions of py-identity-model before publishing to PyPI.

## Overview

Pre-releases allow you to:
- Test new features in realistic environments before official release
- Get feedback from early adopters
- Verify packaging and distribution works correctly
- Test installation in various environments

## Pre-release Workflow

### 1. Open a Pull Request

Pre-releases are created automatically for every pull request against `main`
(from a branch in this repository — fork PRs are skipped). No manual tagging is
needed.

The pre-release version is derived from the latest stable `py-v*` tag and the
conventional commits in the PR (`feat` → minor, `fix`/`perf` → patch, `!` →
major), with the PR number and short commit SHA appended:

```
X.Y.Z-rc.<PR number>.<short sha>     # e.g. 4.2.0-rc.123.abc1234
```

Each new push to the PR replaces that PR's previous pre-release.

### 2. Automatic Publishing to GitHub Releases

On each PR push, GitHub Actions automatically:
1. Runs the CI suite (including Descope integration and example tests)
2. Builds the distribution packages (wheel and source distribution)
3. Creates a GitHub pre-release tagged with the generated version
4. Attaches the distribution files as release assets
5. Posts installation instructions in the release notes and as a PR comment

**Workflow file:** `.github/workflows/publish-prerelease.yml`

**Note:** Pre-releases are published to GitHub Releases only, not PyPI or TestPyPI. This provides:
- Direct installation from GitHub without TestPyPI complexity
- No dependency on TestPyPI's limited storage and retention policies
- Simpler installation commands for downstream testing

### 3. Installing from GitHub Releases

Once published, you have several options for installing the pre-release:

**Option 1: Install from GitHub Release (Recommended)**

This installs the pre-built wheel directly from the GitHub release. Copy the
exact command from the PR comment or release notes; the shape is:

```bash
# Using pip
pip install https://github.com/jamescrowley321/identity-model/releases/download/<version>/<wheel filename>

# Using uv
uv pip install https://github.com/jamescrowley321/identity-model/releases/download/<version>/<wheel filename>
```

**Option 2: Install from the PR Branch**

This builds the package from source. The Python package lives in the `py/`
subdirectory of the repository:

```bash
# Using pip
pip install "git+https://github.com/jamescrowley321/identity-model.git@<branch>#subdirectory=py"

# Using uv
uv pip install "git+https://github.com/jamescrowley321/identity-model.git@<branch>#subdirectory=py"
```

**Option 3: Install in Editable Mode for Development**

For active development and testing:

```bash
git clone https://github.com/jamescrowley321/identity-model.git
cd identity-model
git checkout <branch>
pip install -e py
```

**Finding the Wheel URL:**

1. Go to the [Releases page](https://github.com/jamescrowley321/identity-model/releases)
2. Find the pre-release version
3. Copy the link to the `.whl` file from the Assets section
4. The release notes (and the PR comment) also include the exact installation command

### 4. Testing in a Clean Environment

Always test pre-releases in a clean virtual environment:

```bash
# Create a test environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate

# Install the pre-release (Option 1 - from GitHub release)
pip install https://github.com/jamescrowley321/identity-model/releases/download/<version>/<wheel filename>

# Or Option 2 - from the PR branch
pip install "git+https://github.com/jamescrowley321/identity-model.git@<branch>#subdirectory=py"

# Run your tests
python your_test_script.py
```

### 5. Testing in a Real Application

To test in an existing application:

```bash
# In your application directory
cd /path/to/your/app

# Install pre-release (Option 1 - from GitHub release)
pip install https://github.com/jamescrowley321/identity-model/releases/download/<version>/<wheel filename>

# Or Option 2 - from the PR branch
pip install "git+https://github.com/jamescrowley321/identity-model.git@<branch>#subdirectory=py"

# Test your application
pytest
# or
python manage.py test  # Django
# or
python -m flask run    # Flask

# When done, reinstall stable version
pip install --force-reinstall py-identity-model
```

## Pre-release Checklist

Before opening (or marking ready) the PR that produces a pre-release:

- [ ] All tests passing locally (`make test-unit`, `make test-integration-ory`)
- [ ] CHANGELOG updated with new features and breaking changes
- [ ] Documentation updated
- [ ] Version number follows semantic versioning
- [ ] Breaking changes clearly documented
- [ ] Migration guide updated (if needed)

## GitHub Releases vs PyPI

### GitHub Releases (Pre-releases)
- **URL:** https://github.com/jamescrowley321/identity-model/releases
- **Purpose:** Testing package distribution before official release
- **Retention:** Releases can be deleted or updated as needed
- **Usage:** Pre-release testing only
- **Installation:** Direct URL to wheel file or git tag

### PyPI (Official Releases)
- **URL:** https://pypi.org/
- **Purpose:** Official package distribution
- **Retention:** Packages are permanent (cannot be deleted)
- **Usage:** Production use
- **Installation:** Standard `pip install py-identity-model`

## Troubleshooting

### "Package not found" or 404 Error

If you get a 404 error when installing from GitHub:

```bash
# Verify the release exists
# Go to: https://github.com/jamescrowley321/identity-model/releases

# Check the exact wheel filename in the release assets
# The filename format is: py_identity_model-{version}-py3-none-any.whl
# The release tag and the wheel's version can differ in spelling, so copy
# the wheel link from the release assets (or the PR comment) rather than
# building the URL by hand.
```

### Version Already Exists

Pre-release versions include the PR number and commit SHA, and the workflow
deletes the PR's previous pre-release before creating a new one, so pushing a
new commit to the PR is enough to get a fresh pre-release.

### Git Install Fails

If installing from git tag fails:

```bash
# Make sure git is installed
git --version

# Try with verbose output to see the error
pip install -v "git+https://github.com/jamescrowley321/identity-model.git@<branch>#subdirectory=py"

# Alternative: Install from the wheel URL instead
```

## Promoting Pre-release to Stable

Once testing is complete:

1. **Merge the PR into `main`.** Stable versions are not tagged by hand.

2. **GitHub Actions will automatically** (`.github/workflows/release.yml`):
   - Run the CI suite and the OIDF conformance regression
   - Run `python-semantic-release`, which bumps the version from the
     conventional commits, updates the CHANGELOG, pushes a `py-v{version}` tag
     and creates the GitHub release with the built distribution attached

3. **The `py-v{version}` tag triggers `.github/workflows/publish-dist.yml`**,
   which builds the distribution and publishes it to PyPI (not TestPyPI) via
   trusted publishing.

## Examples

### Testing Async Features

```python
# test_prerelease_async.py
import asyncio
from py_identity_model import DiscoveryDocumentRequest
from py_identity_model.aio import get_discovery_document

async def test_async_discovery():
    request = DiscoveryDocumentRequest(
        address="https://demo.duendesoftware.com/.well-known/openid-configuration"
    )
    response = await get_discovery_document(request)

    assert response.is_successful
    print(f"Issuer: {response.issuer}")
    print(f"JWKS URI: {response.jwks_uri}")

asyncio.run(test_async_discovery())
```

### Testing Thread Safety

```python
# test_thread_safety.py
from concurrent.futures import ThreadPoolExecutor
from py_identity_model import TokenValidationConfig, validate_token

def validate_token_wrapper(token):
    config = TokenValidationConfig(
        perform_disco=True,
        audience="my-api"
    )
    return validate_token(
        jwt=token,
        token_validation_config=config,
        disco_doc_address="https://auth.example.com/.well-known/openid-configuration"
    )

# Test with 50 concurrent threads
with ThreadPoolExecutor(max_workers=50) as executor:
    tokens = [get_test_token() for _ in range(100)]
    results = list(executor.map(validate_token_wrapper, tokens))

print(f"Successfully validated {len(results)} tokens concurrently")
```

## Resources

- [TestPyPI](https://test.pypi.org/)
- [PyPI Packaging Guide](https://packaging.python.org/)
- [Semantic Versioning](https://semver.org/)
- [py-identity-model Documentation](https://github.com/jamescrowley321/identity-model/tree/main/docs)

## Getting Help

- Open an issue: https://github.com/jamescrowley321/identity-model/issues
- Check existing discussions
- Review CHANGELOG for breaking changes
