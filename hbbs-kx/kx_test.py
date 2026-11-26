"""Тест TCP-обмена ключами с hbbs так, как его делает клиент RustDesk 1.5.3 (src/common.rs key_exchange).
python kx_test.py HOST PORT PUBKEY_B64 [plain]"""
import socket, sys, struct, base64, time, nacl.signing, nacl.public, nacl.secret, nacl.utils
import rendezvous_pb2 as R

def enc_len(n):
    if n <= 0x3F: return bytes([n << 2])
    if n <= 0x3FFF: return struct.pack('<H', (n << 2) | 1)
    if n <= 0x3FFFFF: v = (n << 2) | 2; return bytes([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff])
    return struct.pack('<I', (n << 2) | 3)
def send(s, b): s.sendall(enc_len(len(b)) + b)
def recv(s, timeout=10):
    s.settimeout(timeout); buf = b''
    while True:
        if buf:
            hl = (buf[0] & 3) + 1
            if len(buf) >= hl:
                n = int.from_bytes(buf[:hl], 'little') >> 2
                if len(buf) >= hl + n: return buf[hl:hl + n]
        c = s.recv(65536)
        if not c: raise EOFError('closed')
        buf += c
def nonce(seq): return seq.to_bytes(8, 'little') + b'\0' * 16

host, port, pk_b64 = sys.argv[1], int(sys.argv[2]), sys.argv[3]; plain = len(sys.argv) > 4
vk = nacl.signing.VerifyKey(base64.b64decode(pk_b64))
s = socket.create_connection((host, port), timeout=5)
q = R.RendezvousMessage(); q.test_nat_request.serial = 1
if plain:
    send(s, q.SerializeToString()); r = R.RendezvousMessage.FromString(recv(s))
    print('PLAIN OK, reply:', r.WhichOneof('union')); sys.exit(0)
t = time.time(); m = R.RendezvousMessage.FromString(recv(s, 20))
assert m.WhichOneof('union') == 'key_exchange', m
their = vk.verify(m.key_exchange.keys[0]); assert len(their) == 32
print('KeyExchange received after %.2fs, signature OK' % (time.time() - t))
ours = nacl.public.PrivateKey.generate(); sym = nacl.utils.random(32)
sealed = nacl.public.Box(ours, nacl.public.PublicKey(their)).encrypt(sym, b'\0' * 24).ciphertext
a = R.RendezvousMessage(); a.key_exchange.keys.extend([bytes(ours.public_key), sealed]); send(s, a.SerializeToString())
box = nacl.secret.SecretBox(sym)
send(s, box.encrypt(q.SerializeToString(), nonce(1)).ciphertext)
r = R.RendezvousMessage.FromString(box.decrypt(recv(s), nonce(1)))
print('ENCRYPTED OK, reply:', r.WhichOneof('union'))
