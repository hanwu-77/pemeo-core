# Known limitations / 已知限制

This experimental source preview is intended for evaluation
with synthetic, disposable content. Do not store the only copy of personal
history or treat this as a certified security product.

- Human observations used one registered credential. Basic login, cancellation
  and approval were reported by the user and checked read-only by the developer.
  They are not independent auditor execution or legal identity verification.
- Credential addition and revocation have automated coverage but have not been
  manually accepted with additional real authenticators. Full I2 human
  acceptance is incomplete.
- Losing every usable credential prevents further human confirmation writes.
  There is no Web recovery bypass and no implemented recovery procedure.
  Credential loss itself does not delete canonical records. This does NOT prove
  that all undiscovered credential-management bugs would only cause lockout;
  authentication/authorization risks still require assessment.
- A passkey may be synchronized. This round did not verify cross-device sync,
  device exclusivity or every browser/authenticator combination.
- A confirmation binds an authenticated action to candidate content; the
  content's independent truth verification remains unverified.
- Database administrators and the service process/credentials remain trusted.
  Append-only protections are not a cryptographic ledger against administrators.
- The demo binds to HTTPS localhost only. Generated certificate trust must be
  handled explicitly by the user. Automated virtual-authenticator TLS exceptions
  do not validate OS/browser trust or real biometric interaction.
- Runtime dependencies are artifact-hash locked for the documented macOS arm64
  and Ubuntu x86_64 installation targets, not for every platform. Bundled
  native libraries require separate scrutiny for binaries, wheels or containers.
  This source distribution does not bundle dependency artifacts.
- General machine-service identity, real-model Assist, recovery, household
  sharing and production deployment are not implemented.
- CI configuration is supplied; its presence does not prove a run occurred.
  Platform support is limited to the separately recorded evidence for the
  exact distributed archive.

中文：本轮仅一个真实登记凭据；增补/撤销只有自动化覆盖，真人未验。
全部可用凭据丢失后不能继续人类确认写入，无 Web 恢复旁路，恢复流程未实现。
凭据丢失本身不触发删除原始记录，但不能保证未知缺陷最坏只导致锁号。
基本真人流程由用户报告及开发方核对，不是独立实名核验。只适用于合成数据
实验，不能用作不可替代个人资料的唯一保存系统。
