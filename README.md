# boats's personal barricade

This is a tool to automatically sign `git` commits, replacing `gpg` for that
purpose. It is very opinionated, and only useful if you use `gpg` the same way
I do.

## `pkgx` Updates

- Updated to edition 2021 by pkgx
- Stores the private key in the macOS keychain such that only this tool (when
  codesigned) can access it.

## How to Install

```sh
git clone https://github.com/pkgxdev/bpb
cd bpb
cargo install --path bpb
```

## Getting Started

Once you've installed this program, you should run the `bpb init` subcommand.
This command expects you to pass a userid argument. For example, this is how I
would init it:

```sh
bpb init "withoutboats <boats@mozilla.com>"
```

You can pass any string you want as your userid, but `"$NAME <$EMAIL>"` is the
conventional standard for OpenPGP userids.

`bpb init` creates `~/.config/pkgx/bpb.toml`. This file contains your public
signing metadata. Your private key is securely stored in the macOS keychain.
No other tool but the `pkgx` `bpb` fork can access it enforced via Apple code
signing.

> [!NOTE]
> Currently the only way to obtain our codesigned `bpb` is via [teaBASE].

### Configure Commit Signing

```sh
git config --global commit.gpgsign true
git config --global gpg.program bpb
```

You should also provide the public key to people who want to verify your
commits. Personally, I just upload the public key to GitHub; you may have
other requirements.

### Print Public Key

```sh
bpb print
```

### Print Private Key

```sh
security find-generic-password -s "xyz.tea.BASE.bpb" -w
# ^^ prompts for your login password
```


## Security Considerations

> [!IMPORTANT]
> Our mechanism rests at the apex of security and convenience.
> However, the security of your private key is dependent on the following:
>
> * The strength of your macOS user password.
> * The security of your iCloud account.

Someone desiring your GPG private key would need to steal your computer and
then brute force your login password. So you should check how long that would
take.

Your macOS Keychain *may* sync to iCloud. In which case your security also
depends on the security of your iCloud account. Apple encrypt your keychain
remotely but that is obviously decrypted by a valid iCloud authentication.

Practically speaking the security of your iCloud account is more important as
physical theft is an order of magnitude less likely than a remote attack. That
can be mitigated by preventing iCloud Keychain sync but that’s pretty useful
so maybe just have a secure iCloud account.

> [!IMPORTANT]
> Ensure two factor authentication is enabled on your iCloud account!

However, if someone were to steal your hardware they can engineer it so they
have infinite time to brute force your password.


## How it Replaces GPG

If this program receives a `-s` argument, it reads from stdin and then writes
a signature to stdout. If it receives any arguments it doesn't recognize, it
delegates to the gpg binary in your path.

This means that this program can be used to replace gpg as a signing tool, but
it does not replace any other functionality. For example, if you want to
verify the signatures on other peoples' git commits, it will shell out to gpg.


## TODO

- [ ] Move keychain identifiers out to build variables in `main.rs`


[teaBASE]: https://github.com/teaxyz/teaBASE
