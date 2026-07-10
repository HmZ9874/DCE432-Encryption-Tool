# DCE-432 v0.1

A Windows desktop application for an experimental high-dimensional encrypted file container.

## Download

[Download DCE432-Encryption-Tool.exe](https://github.com/HmZ9874/DCE432-Encryption-Tool/releases/download/v0.1.0/DCE432-Encryption-Tool.exe)

SHA-256: `5A52976EAA7FD9424A0EF9B07D0EAE6D05C20A0A584BD32ED6F0F1F6CFAC82F9`

The security boundary uses Argon2id password derivation and AES-256-GCM authenticated encryption. The internal pipeline performs independently keyed 3D coordinate permutation, 3D-to-4D projection, 12/16/20 rounds of reversible four-axis ARX diffusion, 4D-to-3D folding, and 3D-to-2D folding. Time, environment, performance level, and all dimension parameters are stored inside the authenticated package. Decryption never remeasures the current computer.

- Portable mode: requires only the password and can be decrypted on another device.
- Device-bound mode: requires the password and a random local device key. Save the recovery key shown by the application.
- File extension: `.dce432`
- v0.1 file size limit: 256 MB because the current transforms run in memory.

The high-dimensional transforms are experimental and have not received public cryptanalysis. They must not be claimed to be stronger than AES or ChaCha20. Confidentiality and tamper protection are provided by the standard outer authenticated encryption layer.
