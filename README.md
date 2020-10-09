# Private Key Recovery Tool

A command line tool and Golang library to recover private keys from insecurely generated elliptic
curve signatures if they were generated with flaws which allow it. It also provides a tool to
generate insecure signatures for testing the tool and analyzing them.

See the Trail of Bits [post on ECDSA](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
to learn more about the type of attacks implemented.

## Supported Curves & Signatures

| Curve      | Signature                     |
| :--------: | :---------------------------: |
| secp256k1  | ECDSA-SHA256, ECDSA-KECCAK256 |
| P256       | ECDSA-SHA256, ECDSA-KECCAK256 |
| P384       | ECDSA-SHA256, ECDSA-KECCAK256 |
| P521       | ECDSA-SHA512                  |

## Attacks

### Nonce Reuse

```sh
$ bin/keyrecovery generate --curve=P256 --sig-type=ECDSA-SHA256 --mode=nonce-reuse | tee sigs.txt
c7c88a612961672296961826db7860482016c2788e83c4b54905fce744564746a82c70e1e60ec1ed8c93e327288bdbb75d5d5625c66d758b9301bf14c776286d8e2aa0ffa3b57ef13860f138ed535e46c89799a448d7e3becd3974e0d05261ec398943a917b9c7f504db89e31e2b24319aa96c353d275f2588347cbefa79810d6578616d706c65206e6f6e63652d726575736520736967202331
c7c88a612961672296961826db7860482016c2788e83c4b54905fce744564746a82c70e1e60ec1ed8c93e327288bdbb75d5d5625c66d758b9301bf14c776286d8e2aa0ffa3b57ef13860f138ed535e46c89799a448d7e3becd3974e0d05261ec392bcc70cd3aba11d325240c742b75f6ab0e44096ee04aae14dc8b90d100533f6578616d706c65206e6f6e63652d726575736520736967202332

$ cat sigs.txt | bin/keyrecovery recover --curve=P256 --sig-type=ECDSA-SHA256 --mode=nonce-reuse
Recovered private key:
   pub: c7c88a612961672296961826db7860482016c2788e83c4b54905fce744564746a82c70e1e60ec1ed8c93e327288bdbb75d5d5625c66d758b9301bf14c776286d
  priv: 548f9ae92d49e3855aa81abaca8581e1df35d4a377a3b776226865b4f7095ff7
```

### Nonce Bias

TODO: Implement fixed bit bias recovery with LLL
