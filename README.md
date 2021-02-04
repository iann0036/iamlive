# iamlive

:construction: EXPERIMENTAL - WORK IN PROGRESS :construction:

> Generate a basic IAM policy from AWS client-side monitoring (CSM)

## Installation

```
go install
```

## Usage

To start the listener, simply run `iamlive` in a separate window to your CLI / SDK application. You can use Cmd+C / Ctrl+C to exit when you are done.

### CLI Arguments

You can optionally also include the following arguments to the `iamlive` command:

**--setini:** when set, the `.aws/config` file will be updated to use the CSM monitoring and removed when exiting (default: false)

**--profile:** use the specified profile when combined with `--setini` (default: default)

**--failsonly:** when set, only failed AWS calls will be added to the policy (default: false)

_Example_

```
iamlive --setini --profile myprofile --failsonly
```

### CSM Enabling

#### CLI

To enable CSM in the AWS CLI, you should either use the `--setini` option or add the following to the relevant profile in `.aws/config`:

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
