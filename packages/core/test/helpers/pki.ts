/**
 * Throwaway test PKI. Keys and certificates are generated with the `openssl`
 * CLI into a fresh temp directory at test time, so no private key is ever
 * committed to the repo. Everything here is only used by servers bound to
 * 127.0.0.1.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type KeySpec = "ec" | "rsa2048" | "rsa1024";

export interface KeyPair {
  readonly key: string;
  readonly cert: string;
}

export interface LeafSpec {
  commonName: string;
  /** subjectAltName entries, e.g. ["DNS:app.test", "IP:127.0.0.1"]. */
  sans?: readonly string[];
  days?: number;
  key?: KeySpec;
  /** Sign with this CA; omit for a self-signed certificate. */
  issuer?: KeyPair;
}

const NAME = /^[A-Za-z0-9 .*-]+$/;
const SAN = /^(DNS:[A-Za-z0-9.*-]+|IP:[0-9a-fA-F:.]+)$/;

function openssl(args: readonly string[]): void {
  execFileSync("openssl", args, { stdio: ["ignore", "ignore", "pipe"] });
}

export class TestPki {
  private readonly dir = mkdtempSync(join(tmpdir(), "header-auditor-pki-"));
  private counter = 0;

  private path(name: string): string {
    return join(this.dir, name);
  }

  // Both helpers only ever see paths built by `path()` inside our own mkdtemp dir.
  private read(file: string): string {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test temp dir
    return readFileSync(file, "utf8");
  }

  private write(file: string, data: string, mode = 0o644): void {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- test temp dir
    writeFileSync(file, data, { mode });
  }

  private generateKey(spec: KeySpec, file: string): void {
    const args =
      spec === "ec"
        ? ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
        : [
            "-algorithm",
            "RSA",
            "-pkeyopt",
            `rsa_keygen_bits:${spec === "rsa1024" ? "1024" : "2048"}`,
          ];
    openssl(["genpkey", ...args, "-out", file]);
  }

  /** A self-signed root CA that tests pass to `ca` to simulate a trusted issuer. */
  createCa(commonName = "Header Auditor Test CA"): KeyPair {
    const id = String(++this.counter);
    const key = this.path(`ca-${id}.key`);
    const cert = this.path(`ca-${id}.pem`);
    this.generateKey("ec", key);
    openssl([
      "req",
      "-x509",
      "-new",
      "-key",
      key,
      "-out",
      cert,
      "-days",
      "30",
      "-subj",
      `/CN=${commonName}/O=Header Auditor Tests`,
      "-addext",
      "basicConstraints=critical,CA:TRUE",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign",
    ]);
    return { key: this.read(key), cert: this.read(cert) };
  }

  issue(spec: LeafSpec): KeyPair {
    if (!NAME.test(spec.commonName)) throw new Error("unsafe commonName");
    const sans = spec.sans ?? [];
    if (!sans.every((s) => SAN.test(s))) throw new Error("unsafe SAN");
    const id = String(++this.counter);
    const key = this.path(`leaf-${id}.key`);
    const cert = this.path(`leaf-${id}.pem`);
    const days = String(spec.days ?? 90);
    this.generateKey(spec.key ?? "ec", key);
    const extLines = ["basicConstraints=CA:FALSE"];
    if (sans.length > 0) extLines.push(`subjectAltName=${sans.join(",")}`);

    if (!spec.issuer) {
      openssl([
        "req",
        "-x509",
        "-new",
        "-key",
        key,
        "-out",
        cert,
        "-days",
        days,
        "-subj",
        `/CN=${spec.commonName}`,
        ...extLines.flatMap((line) => ["-addext", line]),
      ]);
    } else {
      const caKey = this.path(`issuer-${id}.key`);
      const caCert = this.path(`issuer-${id}.pem`);
      const csr = this.path(`leaf-${id}.csr`);
      const ext = this.path(`leaf-${id}.ext`);
      this.write(caKey, spec.issuer.key, 0o600);
      this.write(caCert, spec.issuer.cert);
      this.write(ext, `${extLines.join("\n")}\n`);
      openssl(["req", "-new", "-key", key, "-out", csr, "-subj", `/CN=${spec.commonName}`]);
      openssl([
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        caCert,
        "-CAkey",
        caKey,
        "-set_serial",
        `0x${id.padStart(8, "0")}`,
        "-days",
        days,
        "-out",
        cert,
        "-extfile",
        ext,
      ]);
    }
    return { key: this.read(key), cert: this.read(cert) };
  }

  cleanup(): void {
    rmSync(this.dir, { recursive: true, force: true });
  }
}
