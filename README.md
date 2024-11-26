# boats's personal barricade

This is a tool to automatically sign git commits, replacing gpg for that
purpose. It is very opinionated, and only useful if you use gpg the same way I
do.

## `pkgx` Updates

- Updated to edition 2021 by pkgx
- Stores the private key in the macOS keychain such that only this tool (when
  codesigned) can access it.

### TODO

- [ ] Move keychain identifiers out to build variables in `config.rs`
- [ ] Move keychain identifier out to a build variable in `keychain.rs`

## How to Install

```sh
git clone https://github.com/pkgxdev/bpb-pkgx
cd bpb-pkgx
cargo install --path .
```

## How to Set Up

Once you've installed this program, you should run the `bpb init` subcommand.
This command expects you to pass a userid argument. For example, this is how I
would init it:

```sh
bpb init "withoutboats <boats@mozilla.com>"
```

You can pass any string you want as your userid, but `"$NAME <$EMAIL>"` is the
conventional standard for OpenPGP userids.

This will create a file at ~/.bpb_keys.toml. This file contains your public
key.

The private and public keys are output as JSON. This is the only time this
tool will expose your private key publicly.

You can print your public key more times with:

```sh
bpb print
```

If you want to use it to sign git commits, you also need to inform git to call
it instead of gpg. You can do this with this command:

```sh
git config --global gpg.program bpb_pkgx
```

You should also provide the public key to people who want to verify your
commits. Personally, I just upload the public key to GitHub; you may have
other requirements.

## How it Replaces GPG

If this program receives a `-s` argument, it reads from stdin and then writes
a signature to stdout. If it receives any arguments it doesn't recognize, it
delegates to the gpg binary in your path.

This means that this program can be used to replace gpg as a signing tool, but
it does not replace any other functionality. For example, if you want to
verify the signatures on other peoples' git commits, it will shell out to gpg.
