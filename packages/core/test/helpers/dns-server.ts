/**
 * A tiny authoritative DNS server over UDP on 127.0.0.1, enough to exercise
 * the real c-ares resolver: answers TXT and CAA queries from a zone map, and
 * can simulate NXDOMAIN, SERVFAIL, REFUSED and timeouts (no reply).
 */
import { createSocket, type Socket } from "node:dgram";

export const TYPE_TXT = 16;
export const TYPE_CAA = 257;

export interface ServerName {
  txt?: string[][];
  caa?: { flags: number; tag: string; value: string }[];
  rcode?: "SERVFAIL" | "REFUSED";
  /** Drop queries for this name so the client times out. */
  drop?: boolean;
}

export interface DnsTestServer {
  readonly address: string;
  close(): Promise<void>;
}

const RCODES = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 } as const;

function readQuestion(msg: Buffer): { name: string; qtype: number; end: number } | undefined {
  let offset = 12;
  const labels: string[] = [];
  while (offset < msg.length) {
    const len = msg.readUInt8(offset);
    offset += 1;
    if (len === 0) break;
    if (len > 63 || offset + len > msg.length) return undefined;
    labels.push(msg.subarray(offset, offset + len).toString("latin1"));
    offset += len;
  }
  if (offset + 4 > msg.length) return undefined;
  return { name: labels.join(".").toLowerCase(), qtype: msg.readUInt16BE(offset), end: offset + 4 };
}

function txtRdata(strings: string[]): Buffer {
  return Buffer.concat(
    strings.map((s) => {
      const bytes = Buffer.from(s, "utf8");
      return Buffer.concat([Buffer.from([bytes.length]), bytes]);
    }),
  );
}

function caaRdata(r: { flags: number; tag: string; value: string }): Buffer {
  const tag = Buffer.from(r.tag, "ascii");
  return Buffer.concat([Buffer.from([r.flags, tag.length]), tag, Buffer.from(r.value, "utf8")]);
}

function answer(rtype: number, rdata: Buffer): Buffer {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(0xc00c, 0); // pointer to the question name
  head.writeUInt16BE(rtype, 2);
  head.writeUInt16BE(1, 4); // class IN
  head.writeUInt32BE(60, 6); // TTL
  head.writeUInt16BE(rdata.length, 10);
  return Buffer.concat([head, rdata]);
}

function respond(query: Buffer, zone: ReadonlyMap<string, ServerName>): Buffer | undefined {
  const q = readQuestion(query);
  if (!q) return undefined;
  const entry = zone.get(q.name);
  if (entry?.drop) return undefined;
  let rcode: number = RCODES.NOERROR;
  let answers: Buffer[] = [];
  if (!entry) rcode = RCODES.NXDOMAIN;
  else if (entry.rcode) rcode = RCODES[entry.rcode];
  else if (q.qtype === TYPE_TXT)
    answers = (entry.txt ?? []).map((t) => answer(TYPE_TXT, txtRdata(t)));
  else if (q.qtype === TYPE_CAA)
    answers = (entry.caa ?? []).map((c) => answer(TYPE_CAA, caaRdata(c)));
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2); // id
  const rd = query.readUInt8(2) & 0x01;
  header.writeUInt8(0x80 | 0x04 | rd, 2); // QR, AA, RD
  header.writeUInt8(0x80 | rcode, 3); // RA + rcode
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  return Buffer.concat([header, query.subarray(12, q.end), ...answers]);
}

export async function startDnsServer(
  zone: Readonly<Record<string, ServerName>>,
): Promise<DnsTestServer> {
  const names = new Map(Object.entries(zone).map(([k, v]) => [k.toLowerCase(), v]));
  const socket: Socket = createSocket("udp4");
  socket.on("message", (msg, rinfo) => {
    const reply = respond(msg, names);
    if (reply) socket.send(reply, rinfo.port, rinfo.address);
  });
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      resolve();
    });
  });
  const { port } = socket.address();
  return {
    address: `127.0.0.1:${String(port)}`,
    close: () =>
      new Promise<void>((resolve) => {
        socket.close(() => {
          resolve();
        });
      }),
  };
}
