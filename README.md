![](https://github.com/aws-samples/aws-kms-xks-proxy/actions/workflows/makefile.yml/badge.svg)

## aws-kms-xks-proxy

This package provides a sample implementation of the [AWS KMS External Keystore (XKS) Proxy API](https://github.com/aws/aws-kms-xksproxy-api-spec) for reference by external customers against any [Hardware Security Module](https://en.wikipedia.org/wiki/Hardware_security_module) (HSM) that supports [PKCS#11 v2.40](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).

The current implementation is written in [Rust](https://www.rust-lang.org/) and is known to work with the following types of HSM:
* `LunaSA 7.4.0` (via Thales eLab)
* `Luna 7 Network HSM` (hardware device)
* `Entrust nShield XC HSM`
* [SoftHSMv2](https://github.com/opendnssec/SoftHSMv2)
* [AWS CloudHSM](https://aws.amazon.com/cloudhsm/)

## Quick Start

Build `xks-proxy` into a [Docker](https://www.docker.com/) image to serve http traffic, with [SoftHSMv2](https://github.com/opendnssec/SoftHSMv2) pre-installed and pre-generated with a single AES key named `foo`:
```bash
docker build -t xks-proxy:latest .
```
Run `xks-proxy` as a Docker container:
```bash
docker run --rm --name xks-proxy -d -p 0.0.0.0:80:80 xks-proxy:latest
```
Verify the server is up and running:
```bash
curl localhost/ping
```
You should see the response:

>pong from xks-proxy v3.1.2-unknown

which indicates the server is now up and running.  You can monitor the logs with:
```bash
docker logs -f xks-proxy
```
Using another terminal, download a [curl](https://curl.se/) based client and `cd` to it:
``` bash
git clone https://github.com/aws-samples/aws-kms-xksproxy-test-client.git
cd aws-kms-xksproxy-test-client
```
(Note you'd need to have `curl 7.75+` installed for the following.)

Run tests locally against the `xks-proxy`:
```bash
export XKS_PROXY_HOST="localhost"
export URI_PREFIX="example/uri/path/prefix"
# Access key ID must have between 20 and 30 characters. Valid characters are uppercase A-Z and 2-7
export SIGV4_ACCESS_KEY_ID="BETWEEN2TENAND3TENCHARACTERS"
# Secret access key must have between 43 and 64 characters. Valid characters are a-z, A-Z, 0-9, /, +, and =
export SIGV4_SECRET_ACCESS_KEY="PleaseReplaceThisWithSomeSecretOfLength43To64"
export KEY_ID="foo"
export SCHEME=
./test-xks-proxy
```
You should see `All 35 tests PASSED` at the end.

To stop the Docker container running `xks-proxy`:
```bash
docker container stop xks-proxy
```
More information about the use of docker can be found at [docker/README.md](docker/README.md).

## Details

The [XKS Proxy API spec](https://github.com/aws/aws-kms-xksproxy-api-spec) assumes you have already set up the vendor specific HSM with the necessary cryptographic keys created.  Once that is done, set up a configuration file at `/var/local/xks-proxy/.secret/settings.toml`.  A number of sample configuration files for different types of HSM's can be found under the `xks-axum/configuration` folder.

Then, to run the XKS Proxy server for debugging purposes:

```bash
# Under the xks-axum directory
XKS_PROXY_SETTINGS_TOML=/var/local/xks-proxy/.secret/settings.toml cargo run
```

### Unit tests

To run the unit tests, type
```bash
# Under the xks-axum directory
cargo test
```
### Generate [RPM](https://en.wikipedia.org/wiki/RPM_Package_Manager) for Centos Linux

To generate the [RPM](https://en.wikipedia.org/wiki/RPM_Package_Manager) for `xks-proxy` for installation on a `Centos Linux x86_64` platform, type:
```bash
# Under the root directory
make
```

### Install via RPM

To install the generated [RPM](https://en.wikipedia.org/wiki/RPM_Package_Manager) on a `Centos Linux x86_64` platform:
```bash
# For example
sudo yum install -y xks-proxy-3.1.2-0.el7.x86_64.rpm
```

### Configuration

Specify the configuration file path, such as `/var/local/xks-proxy/.secret/settings.toml`, by setting the environment variable `XKS_PROXY_SETTINGS_TOML`.

See the `xks-axum/configuration` folders for some sample configuraions for various HSM's such as `Thales Luna HSM`, `Entrust nShield HSM`, `AWS CloudHSM` and `SoftHSMv2`.

### Manage `xks-proxy` as a systemd unit

Once the `xks-proxy` RPM has been installed, you can manage it as a `systemd unit`.  For example

```bash
# Show the backing file
sudo systemctl cat xks-proxy

# Display the status
systemctl status xks-proxy

# The default systemd unit configuration for xks-proxy can be found at /etc/systemd/system/xks-proxy.service.
# To override the configuration:
sudo systemctl edit xks-proxy

# To start xks-proxy
sudo systemctl start xks-proxy

# To stop
sudo systemctl stop xks-proxy

# Display the system journal log
sudo journalctl -xef --unit xks-proxy
```

### Clean logs via `xks-proxy_cleanlogs.timer`

If you choose to output logging of `xks-proxy` to a file (with `is_file_writer_enabled = true` in `settings.toml`), you can have the log files automatically removed perodically via a `systemd timer`.

```bash
# Show the backing file for the timer
sudo systemctl cat xks-proxy_cleanlogs.timer

# Display the status of the cleaning service driven by the timer
systemctl status xks-proxy_cleanlogs

# Display the status of the timer
systemctl status xks-proxy_cleanlogs.timer

# The default systemd unit configuration for the timer can be found at /etc/systemd/system/xks-proxy_cleanlogs.timer.
# To override the (default hourly timer) configuration:
sudo systemctl edit xks-proxy_cleanlogs.timer

# To start the timer
sudo systemctl start xks-proxy_cleanlogs.timer

# Display the system journal log of the cleaning service
sudo journalctl -xef --unit xks-proxy_cleanlogs

# Display the system journal log of the timer
sudo journalctl -xef --unit xks-proxy_cleanlogs.timer
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
