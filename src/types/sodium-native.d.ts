/**
 * Narrow ambient types for the sodium-native surface this project uses.
 *
 * Deliberately not a full binding. Declaring only what we call means an
 * accidental reach for an unreviewed primitive is a compile error rather than
 * an `any`, and the list below doubles as the audit surface for our crypto
 * dependency: it is the complete set of libsodium calls in this repo.
 */
declare module 'sodium-native' {
  const sodium: {
    readonly crypto_box_PUBLICKEYBYTES: number;
    readonly crypto_box_SECRETKEYBYTES: number;
    readonly crypto_box_SEALBYTES: number;

    /** Fill pk/sk with a fresh X25519 keypair. */
    crypto_box_keypair(publicKey: Buffer, secretKey: Buffer): void;

    /** Anonymous sealed box. ciphertext must be message.length + SEALBYTES. */
    crypto_box_seal(ciphertext: Buffer, message: Buffer, publicKey: Buffer): void;

    /** Returns false on authentication failure; never throws for a bad key. */
    crypto_box_seal_open(
      message: Buffer,
      ciphertext: Buffer,
      publicKey: Buffer,
      secretKey: Buffer,
    ): boolean;

    /** mlock'd, guarded allocation for secret material. */
    sodium_malloc(size: number): Buffer;
    sodium_memzero(buffer: Buffer): void;
  };
  export default sodium;
}
