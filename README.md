# gitcrypto

Incremental, encrypted backups for git.

# tour

Let's start off with a quick tour demonstrating how `gitcrypto` works. First, let's make a new temporary directory and load up the gitcrypto project as well as a medium-sized git repository called `toybox`, that we will attempt to encrypt using `gitcrypto`.  While `gitcrypto.rb` can be installed locally, in this tutorial we will only run it from the cloned repository.

```
mkdir -p /tmp/gitcrypto-tour
cd /tmp/gitcrypto-tour
git clone https://github.com/AndreiBorac/gitcrypto.git
git clone https://github.com/landley/toybox.git
```

Since we must be in a git repository when running `gitcrypto.rb keygen`, let's hop into `toybox` and do that. During key generation, you will be prompted for a passphrase. The passphrase is required to decrypt (no passphrase is required merely to encrypt). A public key file will be stored in `./.gitcrypto/cfg/pubkey`. Though technically a "public key", this key should be kept secret, as anyone with the public key can encrypt (and thus potentially alter your data in malicious or confusing ways).

```
cd toybox
./../gitcrypto/gitcrypto.rb keygen
```

Now we're ready to encrypt:

```
./../gitcrypto/gitcrypto.rb backup
```

About 3 minutes later, you should have the backups in `./.gitcrypto/tmp/export`. From there you could use `rsync` to transfer them incrementally to a remote host, but that is beyond the scope of the tour. Note that `gitcrypto` is deterministic - if you unmount `./.gitcrypto/tmp` (it's a `tmpfs`), losing contents, and run `gitcrypto.rb backup` again, you should get exactly the same contents in the "export" directory. In fact, you will get exactly the same contents in the "export" directory if you restart from the `keygen` step - even the key derivation is deterministic.

Now let's pretend we lost our git repository, and we want `gitcrypto` to recover it based on the "export" directory we just created:

```
mv ./.git ./.git0
./../gitcrypto/gitcrypto.rb rescue ./.gitcrypto/tmp/export
git checkout HEAD -- .
```

That last command (the `git checkout ...`) is very important. It is required to bring `git` up-to-date from an empty repository to the newly added decrypted commits.
