# iamlive

> Generate an IAM policy from AWS, Azure, or Google Cloud (GCP) calls using client-side monitoring (CSM) or embedded proxy

![](https://raw.githubusercontent.com/iann0036/iamlive/assets/iamlive.gif)

> [!IMPORTANT]  
> The Azure and Google Cloud providers are in preview and may produce incorrect outputs at this time

## Installation

### Pre-built binaries

Pre-built binaries for Windows, macOS and Linux are available for download in the project [releases](https://github.com/iann0036/iamlive/releases).

Once downloaded, place the extracted binary in your $PATH (or execute in-place). For macOS users, you may need to allow the application to run via System Preferences.

### Build with Go

To build and install this application, clone this repository and execute the following from it's base:

```
go install
```

You must have Go 1.16 or later installed for the build to work.

### Homebrew

You may also install this application using a Homebrew tap with the following command:

```
brew install iann0036/iamlive/iamlive
```

### Other Methods

* [Lambda Extension](https://github.com/iann0036/iamlive-lambda-extension) _(AWS only)_
* [Docker](https://meirg.co.il/2021/04/23/determining-aws-iam-policies-according-to-terraform-and-aws-cli/)
* [GitHub Action (with Terraform)](https://github.com/scott-doyland-burrows/gha-composite-terraform-iamlive)
* [LocalStack](https://github.com/rulio/iamlive-localstack/)

## Usage

To start the listener, simply run `iamlive` in a separate window to your CLI / SDK application. You can use Ctrl+C to exit when you are done.

### CLI Arguments

You can optionally also include the following arguments to the `iamlive` command:

**--provider:** the cloud service provider to intercept calls for (`aws`,`azure`,`gcp`) (_default: aws_)

**--set-ini:** when set, the `.aws/config` file will be updated to use the CSM monitoring or CA bundle and removed when exiting (_default: false_) (_AWS only_)

**--profile:** use the specified profile when combined with `--set-ini` (_default: default_) (_AWS only_)

**--fails-only:** when set, only failed AWS calls will be added to the policy, csm mode only (_default: false_) (_AWS only_)

**--output-file:** specify a file that will be written to on SIGHUP or exit (_default: unset_)

**--refresh-rate:** instead of flushing to console every API call, do it this number of seconds (_default: 0_)

**--sort-alphabetical:** sort actions alphabetically (_default: false for AWS, otherwise true_)

**--host:** host to listen on for CSM (_default: 127.0.0.1_)

**--background:** when set, the process will return the current PID and run in the background without output (_default: false_)

**--force-wildcard-resource:** when set, the Resource will always be a wildcard (_default: false_) (_AWS only_)

**--mode:** the listening mode (`csm`,`proxy`) (_default: csm for aws, otherwise proxy_)

**--bind-addr:** the bind address for proxy mode (_default: 127.0.0.1:10080_)

**--ca-bundle:** the CA certificate bundle (PEM) to use for proxy mode (_default: ~/.iamlive/ca.pem_)

**--ca-key:** the CA certificate key to use for proxy mode (_default: ~/.iamlive/ca.key_)

**--account-id:** the AWS account ID to use in policy outputs within proxy mode (_default: 123456789012 unless detected_) (_AWS only_)

**--override-aws-map:** overrides the embedded AWS mapping JSON file with the filepath provided (_AWS only_)

**--debug:** dumps associated HTTP requests when set in proxy mode (_default: false_)

_Basic Example (CSM Mode)_

```
iamlive --set-ini
```

_Basic Example (Proxy Mode)_

```
iamlive --set-ini --mode proxy
```

_Basic Example (Azure)_

```
iamlive --provider azure
```

_Basic Example (Google Cloud)_

```
iamlive --provider gcp
```

_Comprehensive Example (CSM Mode)_

```
iamlive --set-ini --profile myprofile --fails-only --output-file policy.json --refresh-rate 1 --sort-alphabetical --host 127.0.0.1 --background
```

_Comprehensive Example (Proxy Mode)_

```
iamlive --set-ini --mode proxy --profile myprofile --output-file policy.json --refresh-rate 1 --sort-alphabetical --bind-addr 127.0.0.1:10080 --ca-bundle ~/.iamlive/ca.pem --ca-key ~/.iamlive/ca.key --account-id 123456789012 --background --force-wildcard-resource
```

The arguments may also be specified in an INI file located at `~/.iamlive/config`.

### CSM Mode

Client-side monitoring mode is the default behaviour for AWS and will use [metrics](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/metrics.html) delivered locally via UDP to capture policy statements with the `Action` key only (`Resource` is only available in proxy mode).

CSM mode is only available for the AWS provider.

#### CLI

To enable CSM in the AWS CLI, you should either use the `--set-ini` option or add the following to the relevant profile in `.aws/config`:

```
csm_enabled = true
```

Alternatively, you can run the following in the window executing your CLI commands:

```
export AWS_CSM_ENABLED=true
```

#### SDKs

To enable CSM in the various AWS SDKs, you can run the following in the window executing your application prior to it starting:

```
export AWS_CSM_ENABLED=true
export AWS_CSM_PORT=31000
export AWS_CSM_HOST=127.0.0.1
```

### Proxy Mode

Proxy mode will serve a local HTTP(S) server (by default at `http://127.0.0.1:10080`) that will inspect requests sent to the AWS endpoints before forwarding on to generate IAM policy statements. The CA key/certificate pair will be automatically generated and stored within `~/.iamlive/` by default.

#### AWS CLI

To set the appropriate CA bundle in the AWS CLI, you should either use the `--set-ini` option or add the following to the relevant profile in `.aws/config`:

```
ca_bundle = ~/.iamlive/ca.pem
```

Alternatively, you can run the following in the window executing your CLI commands:

```
export AWS_CA_BUNDLE=~/.iamlive/ca.pem
```

You must also set the proxy settings for your session by running the following in the window executing your CLI commands:

```
export HTTP_PROXY=http://127.0.0.1:10080
export HTTPS_PROXY=http://127.0.0.1:10080
```

#### AWS SDKs

To enable proxy mode in the various AWS SDKs, you can run the following in the window executing your application prior to it starting:

For AWS SDKs:

```
export HTTP_PROXY=http://127.0.0.1:10080
export HTTPS_PROXY=http://127.0.0.1:10080
export AWS_CA_BUNDLE=~/.iamlive/ca.pem
```

Check the [official docs](https://docs.aws.amazon.com/credref/latest/refdocs/setting-global-ca_bundle.html) for further details on setting the CA bundle.

#### Azure CLI and SDKs

To enable proxy mode in the Azure CLI or SDK, you can run the following in the window executing your application prior to it starting:

```
export HTTP_PROXY=http://127.0.0.1:10080
export HTTPS_PROXY=http://127.0.0.1:10080
export REQUESTS_CA_BUNDLE=~/.iamlive/ca.pem
```

#### Google Cloud CLI and SDKs

To enable proxy mode in the Google Cloud CLI or SDKs, you can run the following in the window executing your application prior to it starting:

```
gcloud config set proxy/type http
gcloud config set proxy/address 127.0.0.1
gcloud config set proxy/port 10080
gcloud config set core/custom_ca_certs_file ~/.iamlive/ca.pem
```

## FAQs

_I get a message "package embed is not in GOROOT" when attempting to build myself_

This project requires Go 1.16 or above to be built correctly (due to embedding feature).

## Acknowledgements

This project makes use of [Parliament](https://github.com/duo-labs/parliament) and was assisted by Scott Piper's [CSM explainer](https://summitroute.com/blog/2020/05/25/client_side_monitoring/). Thanks also to Noam Dahan's [research](https://ermetic.com/whats-new/blog/auditing-passrole-a-problematic-privilege-escalation-permission/) into missing `iam:PassRole` dependant actions.
