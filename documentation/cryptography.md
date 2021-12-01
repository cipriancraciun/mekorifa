
# **mekorifa** -- Cryptography




## Goals


### Initial goals

* password protect a single small sensitive token (be it another password, FDE key, API token, or small file, etc.);
  (we call this sensitive data the "token plaintext";)
* "small" means up to 1 MiB;  (this is not a file encryption tool;)

* support attaching a random 128 bit identifier (unencrypted), for example to be used in a password store as a handle for this token;
  (we call this the "token identifier" and it is part of the "token meta-data";)
* support attaching additional textual data (unencrypted), for example to be used as a hint of what represents this token;
  (we call this the "token description" and it is part of the "token meta-data";)

* detect changes to the attached identifier or description (i.e. the token meta-data), for example due an attacker that copy-pasted one token ciphertext over another;  (i.e. using AEAD;)
* detect corruption of the envelope (i.e. the JSON serialization), without requiring the password, for example due to transmission or disk errors;
* as a disaster recovery measure, add an authenticator only for the token ciphertext;  (thus one only needs the `scrypt` parameters, the token ciphertext, and this authenticator;)

* support a simple envelope, one that can be read, queryied, aggregated or manipulated with usual tools;  thus JSON;
  (JSON is only a used for serialization, and is not used as input in any of the cryptographic building blocks;)
* support changing the envelope (i.e. JSON serialization) without breaking the authentication;

* support backward / forward compatibility of the envelope;  thus include a schema as part of the envelope;


### Future goals

* support multiple sub-tokens, perhaps encrypted with multiple different keys, to allow granular access only to particular tokens;
  (for example for an AWS IAM account one could have a username and password for dashboard access, an access and secret key used for API's, a pair of Git credential, a pair of SMTP credentials;  each should be accessible individually;)

* (in relation to the above) support a public-key cryptography identity, just like `age` does;

* (in relation to the above) support multiple passwords / identities for the same token;

* support an "agent" similar to SSH or GnuPG, that provides an socket-based API to access tokens;




## Building blocks

* password -- `scrypt` (with `Nlog2 = 20`, `r = 8`, `p = 1`, and 512 bit random salt);
* encryption -- `ChaCha20` (with key and nonce derived with `scrypt`);
* hashing -- `BLAKE3` (both unkeyed, and keyed derived with `scrypt`);
* padding -- as described in RFC 5116, or with canonicalization;
* envelope -- JSON, with Base64-URL for binary data;  (the JSON output is ASCII only, although it supports to encode Unicode strings, i.e. "\uFFFD" instead of the replacement character;)




## Serialization

~~~~
{
    "schema" : "mekorifa-token-scrypt-v1",
    "identifier" : "da74070468a74fe97f4816ac47680518",
    "description" : [
        "some very important secret",
    ],
    "parameters" : {
        "n" : 20,
        "r" : 8,
        "p" : 1,
        "s" : "9cb393826b770eb61d75885ab41d81401fc3e858a7972e919bd550ec1710bf754e739f83170751d8856717009046382101b86b928d785a37cfa2137e2304b893"
    },
    "token" : [
        "rxbhgRLzPK+L/iDaxzYWT7q5HF0tNK8/ypfmoh8ZnrXIQl9vLqNxeYplYK1IocI1q3X9JQYSnKoG0Ac05T7scEKXv84FXwy/g/z+7VqXSBfLJI7sF0O0asYWXk00Tn5L",
        "SIw8jlmshi7xnkOwSqVbrik+p9qqZaDfetsIDiq0dIi+CFifg7PUlEa9jTu7xLffMnndC7vM8XNK2hG1muSBWd1Pru2yUJh9uJ5v4+Zvr1zKlUlvw0G5NopuVMd/nSB3",
        "k6v23GwWcGpSAch1atlthxpXmUoHNSwBUmx9FBNism3Ob3bo9u/2vhT689w5ZFGsnll22RAxxVqHFbD+EdVXDgtfDQjz3qVkZKtRDTGzvIHz0lEonGjUbXUojEUdv6gC",
        "n1y+uBBYXdrHOU9RvSGs/GNRbDpwZ7q5tD6AZbxP5GEWkJcL1h7NB2iD71Bbi2Ed68Q56cumPZKklV58UuQFlv/xyGRjWkG8F3PufNRxe+Txm52AWznwksURdVJtz5Mt",
        "yLLOL0eAFYmtUDPZLIgU6+4SYcSQAz0FBLpgWfHVBSYN0pXhyNmiZ0g6RAEcsalDC4m6YcOJr6V0Mz1oqyJwWeXRVsU6LFYUawWM+8MRymtGZWFsouE28Cazm3wzsWL1",
        "qHRSYLTdQffzRQz+zPvFa2eI8cXwhWSpjevkeB2ACz0="
    ],
    "authentication-only-token" : "5dad271931eec99e721034af764e02bfc23650afc1cc3bd457a6ca5a63355b4a",
    "authentication-with-associated" : "47f5a23a87b18e4020944777ab0c66b6a9ad3c801c1d9238701db07340885559",
    "envelope-checksum" : "4a312a44a39df7947889187f81e59c2e268e37d44e2917f914d2a5e53a2195e3"
}
~~~~




## Algorithms




### Definitions

* `password` -- a human provided password;
  (should provide enough entropy, as it's the weakest link in the whole scheme;)

* `json` -- the JSON serialization as exemplified above;

* `scrypt_n`, `scrypt_r`, and `scrypt_p` -- the `scrypt` algorithm parameters;
  * `scrypt_n_log2 := json.parameters.n`;  (according to `scryptenc.c`, it must be between 1 and 63 inclusive, but we limit it at 28 due to the memory requirements;)
  * `scrypt_n := 1 << scrypt_n_log2`;
  * `scrypt_r := json.parameters.r`;  (according to `scryptenc.c`, it should be at least 1, but also `scrypt_r * scrypt_p < 0x40000000`;)
  * `scrypt_p := json.parameters.p`;  (according to `scryptenc.c`, it should be at least 1, but we limit it at 16;)
  * `scrypt_mem := 128 * scrypt_n * scrypt_r`;  (we limit it at 4 GiB;)  (not actually used, but it hints at the memory requirements given the previous parameters;)
  * `scrypt_salt := hex_decode (json.parameters.s)`;  (it must be 512 bits long;)

* `token_identifier := hex_decode (json.identifier)`;  (it must be 128 bits long;)
* `token_description := utf8_encode (strings_concatenate (strings_join (json.description, "\n"), "\n"))`
  (each `json.description` item must only contain unicode characters in the following general categories: `Letter`, `Number`, `Punctuation`, `Symbol`, or a space (i.e. ASCII 0x20);)
  (n.b. the resulting blob always ends with a "\n", just like a properly formatted file;)
* `token_ciphertext := base64url_decode (strings_join (json.token, ""))`;
  (each `json.token` item must not be empty;)
  (each `json.token` item should be exactly 128 characters, except the last that should be at most 128 characters;)
* `token_authentication := hex_decode (json.authentication_only_token)`;  (it must be 256 bits long;)
* `overall_authentication := hex_decode (json.authentication_with_associated)`;  (it must be 256 bits long;)
* `envelope_checksum := hex_decode (json.envelope_checksum)`;  (it must be 256 bits long;)

* `token_plaintext` -- the secured token;  (any bytes are accepted;  an empty token is accepted;)
* `token_plaintext_length` -- the secured token length in bytes;  (we limit it at 1 MiB;)




### Encryption

Inputs:
* `password`;
* `scrypt_n`, `scrypt_r`, `scrypt_p`, `scrypt_s`;
* `token_identifier`, `token_description`;
* `token_plaintext`, `token_plaintext_length`;

Outputs:
* `token_ciphertext`;
* `token_authentication`;
* `overall_authentication`;
* `envelope_checksum`;

~~~~
// NOTE:  Although `scrypt_s` is an input, it should be generated as follows.
scrypt_s := bytes_random (64)    // 512 bits / 64 bytes

// NOTE:  We make sure the password is a proper UTF8 string.
password_bytes := utf8_encode (password)

key_material_length := 32 + 12 + 32 + 32
key_material := scrypt (password_bytes, scrypt_s, scrypt_n, scrypt_r, scrypt_p, key_material_length)

chacha20_key       := bytes_slice (key_material,  0,  32)    // 256 bits / 32 bytes
chacha20_nonce     := bytes_slice (key_material, 32,  44)    //  96 bits / 12 bytes
blake3_token_key   := bytes_slice (key_material, 44,  76)    // 256 bits / 32 bytes
blake3_overall_key := bytes_slice (key_material, 76, 108)    // 256 bits / 32 bytes


chacha20_plaintext := bytes_join ([
        u32_to_bytes (token_plaintext_length),
        token_plaintext,
        zero_padding (512, 4 + token_plaintext_length),
    ])
    // NOTE:  The message is padded to 512 bytes with zeroes,
    //        thus the encrypted token (including the length)
    //        is always made of 512 bytes chunks.
    // NOTE:  An empty token still has 512 bytes when encrypted.

chacha20_ciphertext := chacha20 (chacha20_key, chacha20_nonce, chacha20_plaintext)
chacha20_ciphertext_length := bytes_length (chacha20_ciphertext)


blake3_token_message := bytes_join ([
        hex_decode ("bcb1c8046960c27009d6da3948ae9db8c8ea963c1f88a612b14525a4a8fd0261876cea2cbe38ea278a803b0ba0ff7bf3a9bae40380e9f666a6608c36aede33f3"),   // NOTE:  change in future versions
        //
        chacha20_ciphertext,
        zero_padding (16, chacha20_ciphertext_length),   // NOTE:  0 due to 512 padding of plaintext
        //
        u32_to_bytes (chacha20_ciphertext_length),
    ])

blake3_token_hash := blake3_keyed_hash (blake3_token_key, blake3_token_message)


blake3_overall_message := bytes_join ([
        hex_decode ("4fced4c26b5cc4047b309ab9cbf1378796f70db8f341c596ca614b73125b71bb091fd2669157b0b0979cec2e140a2156dae9731f56453fbfc29f06b1409c9da5"),   // NOTE:  change in future versions
        //
        chacha20_ciphertext,
        zero_padding (16, chacha20_ciphertext_length),   // NOTE:  0 due to 512 padding of plaintext
        //
        token_identifier,
        zero_padding (16, bytes_length (token_identifier)),
        //
        token_description,
        zero_padding (16, bytes_length (token_description)),
        //
        u32_to_bytes (chacha20_ciphertext_length),
        u32_to_bytes (bytes_length (token_identifier)),
        u32_to_bytes (bytes_length (token_description)),
    ])

blake3_overall_hash := blake3_keyed_hash (blake3_overall_key, blake3_overall_message)


blake3_envelope_message := bytes_join ([
        hex_decode ("e7c2f948611eea1f2cb3543ab799e9d3ce1372a638847d484fd9d02852517e8a24889351b2b88bd3ea1ce24f17394cf6416438868406e36bdcc2efb87b04f8c7"),   // NOTE:  change in future versions
        //
        u32_to_bytes (scrypt_n_log),
        u32_to_bytes (scrypt_r),
        u32_to_bytes (scrypt_p),
        u32_to_bytes (bytes_length (scrypt_s)),
        scrypt_s,
        zero_padding (16, bytes_length (scrypt_s)),
        //
        u32_to_bytes (bytes_length (token_identifier)),
        token_identifier,
        //
        u32_to_bytes (bytes_length (token_description)),
        token_description,
        //
        u32_to_bytes (chacha20_ciphertext_length),
        chacha20_ciphertext,
        //
        blake3_token_hash,
        blake3_overall_hash,
    ])

blake3_envelope_hash := blake3_hash (blake3_envelope_message)

token_ciphertext = chacha20_ciphertext
token_authentication = blake3_token_hash
overall_authentication = blake3_overall_hash
envelope_checksum = blake3_envelope_hash
~~~~




### Functions

* `scrypt (password_bytes_string, salt_bytes_string, n, r, p, output_bytes_length) -> (output_bytes_string)` -- applies scrypt as described by RFC 7914;

* `chacha20 (key_bytes_string, nonce_bytes_string, plaintext_bytes_string) -> (ciphertext_bytes_string)` -- applies ChaCha20 as described by RFC 8439;

* `blake3_hash (message_bytes_string) -> (hash_bytes_string)` -- applies BLAKE3 as implemented in Rust by `blake3::hash`;
* `blake3_keyed_hash (key_bytes_string, message_bytes_string) -> (hash_bytes_string)` -- applies BLAKE3 as implemented in Rust by `blake3::keyed_hash`;

* `utf8_encode (utf8_string) -> (bytes_string)` -- accepts an ASCII or Unicode string, and returns its UTF8 representation as bytes;
* `utf8_decode (bytes_string) -> (utf8_string)` -- accepts only properly encoded UTF8 strings, fails otherwise;

* `hex_decode (utf8_string) -> (bytes_string)`;  (accepts only lower case;)
* `hex_encode (bytes_string) -> (utf8_string)`;  (returns only lower case;)

* `base64url_decode (utf8_string) -> (bytes_string)`;  (according to RFC 4648;)
* `base64url_encode (bytes_string) -> (utf8_string)`;  (according to RFC 4648;)

* `bytes_random (bytes_length) -> (bytes_string)` -- generates cryptographically secure random bytes;
* `bytes_length (bytes_string) -> (bytes_length)`;  (expects only bytes, thus UTF8 or other strings should be first converted;)
* `bytes_slice (large_bytes_string, offset_start, offset_end) -> (slice_bytes_string)` -- just like Python's `"abc"[1:2] == "b"`;

* `strings_join (list_of_utf8_strings, separator_utf8_string) -> (joined_utf8_string)` -- just like Python's `"S".join(["a","b"]) == "aSb"`;
* `strings_concatenate (left_utf8_string, right_utf8_string) -> (concatenated_utf8_string)` -- just like Python's `"a"+"b" == "ab"`;

* `bytes_join (list_of_bytes_strings, separator_bytes_string) -> (joined_bytes_string)`;
* `bytes_concatenate (left_bytes_string, right_bytes_string) -> (concatenaded_bytes_string)`;




## Threath model

* weak password -- **unmitigated**

  The user is responsible for providing a "strong enough" password.

* password reuse -- mitigated

  The user will be tempted to reuse the same password for different tokens.
  However given we are using `scrypt` with a random salt, this should not be a problem.
  An attacker can't use multiple tokens to deduce either the original password,
  nor even if the same password was reused.

* password guessing -- mitigated
  (provided a strong password is used, and provided it is not hinted-to in the meta-data)

  Given we are using `scrypt` (and provided the user hasn't lowered the default parameters),
  an attacker could try to guess or brute force if a password was used with a given token,
  however each try requires one invocation of `scrypt`,
  that at the moment is around 2 seconds on a moderate laptop.
  (Also see the previous point about weak passwords.)

* token plaintext guessing -- mitigated
  (provided it is not hinted-to in the meta-data)

  By looking at an encrypted token an attacker can only deduce it's size modulo 512 bytes,
  which should be large enough to hide the length of small passwords.
  Also, given a potential token plaintext, an attacker can't determine if it is actually stored in the token.

* altering the meta-data -- mitigated

  An attacker could try to replace the encrypted payload from an often used token (say a web app login password),
  with the encrypted payload from a high-value less-often used token (say an AWS root login password),
  in the hope he could leak it by compromising the often used web application (either compromising the local browser, local network, or even the server).
  However given that we authenticate the meta-data during the decryption (and if any tampering is detected, the decryption is aborted and token plaintext is outputed),
  such an attack is not feasible.  (Provided the user has not reused the same meta-data.)

  (Moreover this attack requires the attacker to have read-write access to the tokens storage,
  at which point he most likely can just compromise the decryption tool, the local browser or application.)

* replacing a token with a previous version -- **unmitigated**

  Say inside the token's plaintext (or even the unencrypted description) one also stores the login URL of the bank;
  say at one point the bank has changed its domain, and the user edits the token by updating the URL, but keeping the same meta-data (especially the identifier);
  say that after a while the bank let's the old domain expire.
  An attacker could buy the old domain (or try to MITM or spoof it),
  and also replace the old token version (that contains the same password given the user hasn't changed it).
  If the user uses the domain from the token's plaintext (or unencrypted description),
  he would leak the password to the attacker.

  (Like in the previous case, such an attack requires read-write access to the tokens storage,
  thus it might be easier to just compromise the local tools and applications.)

* weak random generator -- **unmitigated?**

  A weak (or compromised) random generator impacts only two elements:
  * the identifier of the token, which usually (if there are no collisions, or if collisions are easily detected) shouldn't present a problem;
  * the `scrypt` salt, which should at least be unique, and (although neither the RFC nor the paper states) should be (?) cryptographically secure random (?);

* swap leaks of the password and other cryptographic key material -- **unmitigated**
  (but can be easily mitigated by using encrypted swap, or not using swap at all)

  Because we use `scrypt` that requires large amounts of RAM (for the default parameters ~1 GiB),
  and because the OS (at least Linux) by default limits the amount of memory a process is allowed to pin to RAM (on Linux 64 KiB),
  it is impossible (by default) to pin that amount of memory to RAM.

  One could pin the password in RAM, and try to zero it after `scrypt` was called,
  because it is read from the console, a pipe, or other IPC mechanisms,
  most likely it remains in other areas of the memory that can't be pined in RAM or zeroed by this tool.

  However the resulting cryptographic key material (the actual keys and nonces for ChaCha20 or BLAKE3) can be pined in RAM,
  and given one implements this tool in a non-moving GC (or no GC at all) language (like Rust or C),
  and given one also pins in RAM the ChaCha20 and BLAKE3 state,
  one could consider these safe from swap leaks.

* swap leaks of the token plaintext -- **unmitigated**
  (just as in the previous case, use encrypted swap, or no swap at all)

  As with the case of the password,
  because the token plaintext is read / written to the console, a pipe, or other IPC mechanisms,
  most likely it remains in other areas of the memory that can't be pined in RAM or zeroed by this tool.

* downgrade attacks -- mitigated

  In future versions, the format or encoding might change, but the used password might remain the same.
  An attacker could try to copy-paste cryptographic outputs from / to an older / newer version,
  in the hope the older / newer implementation has some weakeness.
  However, given each authenticator or checksum includes a 512 bit token specific for that version,
  such a downgrade attack would not be possible, unless there is a bug in the tool itself.




## Links

* scrypt -- password key derivation:
  * [scrypt -- web site](<https://www.tarsnap.com/scrypt.html>);
  * [scrypt -- source code](<https://github.com/Tarsnap/scrypt>);
    * [scryptenc.c](<https://github.com/Tarsnap/scrypt/blob/master/lib/scryptenc/scryptenc.c>);
  * [scrypt -- Wikipedia](<https://en.wikipedia.org/wiki/Scrypt>);
  * [RFC 7914 -- The scrypt Password-Based Key Derivation Function](<https://datatracker.ietf.org/doc/html/rfc7914>);
  * [scrypt -- Rust crate](<https://crates.io/crates/scrypt>);

* ChaCha20 -- symmetric stream cipher:
  * [Salsa20 -- web site](<https://cr.yp.to/snuffle.html>);
  * [ChaCha20 -- web site](<https://cr.yp.to/chacha.html>);
  * [Salsa20 / ChaCha20 -- Wikipedia](<https://en.wikipedia.org/wiki/Salsa20>);
  * [RFC 8439 -- ChaCha20 and Poly1305 for IETF Protocols](<https://datatracker.ietf.org/doc/html/rfc8439>);
  * [RFC pending -- XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305](<https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha>);
  * [chacha20 -- Rust crate](<https://crates.io/crates/chacha20>);

* BLAKE3 -- cryptographic hash:
  * [BLAKE -- Wikipedia](<https://en.wikipedia.org/wiki/BLAKE_(hash_function)>);
  * [BLAKE3 -- source code](<https://github.com/BLAKE3-team/BLAKE3>);
  * [blake3 -- Rust crate](<https://crates.io/crates/blake3>);

* AEAD -- Authenticated Encryption with Associated Data:
  * [RFC 5116 -- An Interface and Algorithms for Authenticated Encryption](<https://datatracker.ietf.org/doc/html/rfc5116>);

* Base64:
  * [Base64 -- Wikipedia](<https://en.wikipedia.org/wiki/Base64>);
  * [RFC 4648 -- The Base16, Base32, and Base64 Data Encodings](<https://datatracker.ietf.org/doc/html/rfc4648>);

* age -- encryption tool:
  * [age -- source code](<https://github.com/FiloSottile/age>);
  * [age -- design and specification](<https://age-encryption.org/v1>);

* restic -- encrypted backup tool:
  * [restic -- source code](<https://github.com/restic/restic>);
  * [restic -- design and specification](<https://restic.readthedocs.io/en/latest/100_references.html>);

* articles:
  * [blog.filippo.io -- The scrypt parameters](<https://blog.filippo.io/the-scrypt-parameters/>);
  * [blog.filippo.io -- restic cryptography](<https://blog.filippo.io/restic-cryptography/>);
  * [soatok.blog -- Comparison of Symmetric Encryption Methods](<https://soatok.blog/2020/07/12/comparison-of-symmetric-encryption-methods/>);
  * [soatok.blog -- Designing New Cryptography for Non-Standard Threat Models](<https://soatok.blog/2020/09/09/designing-new-cryptography-for-non-standard-threat-models/>)
    (XChaCha20 + Blake3 AEAD construct);

