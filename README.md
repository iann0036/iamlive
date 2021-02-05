# iamlive

> Generate a basic IAM policy from AWS client-side monitoring (CSM)

![](https://raw.githubusercontent.com/iann0036/iamlive/assets/iamlive.gif)

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

## Usage

To start the listener, simply run `iamlive` in a separate window to your CLI / SDK application. You can use Cmd+C / Ctrl+C to exit when you are done.

### CLI Arguments

You can optionally also include the following arguments to the `iamlive` command:

**--set-ini:** when set, the `.aws/config` file will be updated to use the CSM monitoring and removed when exiting (_default: false_)

**--profile:** use the specified profile when combined with `--set-ini` (_default: default_)

**--fails-only:** when set, only failed AWS calls will be added to the policy (_default: false_)

_Example_

```
iamlive --set-ini --profile myprofile --fails-only
```

### CSM Enabling

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

## FAQs

_I get a message "package embed is not in GOROOT" when attempting to build myself_

This project requires Go 1.16 or above to be built correctly (due to embedding feature).

_Can we include specifics for the Resource and Condition fields?_

No, the CSM protocol does not support it and cannot be changed.

## Acknowledgements

This project makes heavy use of [Parliament](https://github.com/duo-labs/parliament) and was assisted by Scott Piper's [CSM explainer](https://summitroute.com/blog/2020/05/25/client_side_monitoring/).