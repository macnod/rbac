### Single-Threaded Design
RBAC operations span multiple transactions for maximum flexibility. Thus, this library will **not work well** with multi-threaded clients unless RBAC calls are serialized.

**Status**: Transaction wrappers planned for future release.

### Password Hashing
Username **salting** prevents casual DB lookups, but doesn't provide optimal security.

**Status**: Argon2/PBKDF2 with iterations planned for future release.
