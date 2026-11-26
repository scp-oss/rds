#!/usr/bin/env python3
"""Патч hbbs (rustdesk-server 1.1.x): TCP-обмен ключами с клиентом (как в Pro) для клиентов RustDesk 1.5+,
которые, будучи в аккаунте, требуют его («Failed to secure tcp»). Версия обмена 0: один secretbox-ключ,
счётчики nonce в каждую сторону — то же, что hbb_common::tcp::Encrypt. Клиенты, которые пишут первыми
(без аккаунта / старые), обслуживаются как раньше, без шифрования.
Запуск: python3 patch_kx.py <путь к src/rendezvous_server.rs>"""
import sys
p = sys.argv[1]; s = open(p).read()
def rep(a, b):
    global s
    if a not in s: sys.exit("patch point not found: " + a[:80])
    s = s.replace(a, b, 1)

rep("use sodiumoxide::crypto::sign;",
    "use sodiumoxide::crypto::{box_, secretbox, sign};")
rep("""enum Sink {
    TcpStream(TcpStreamSink),""", """// ключ отправки (secretbox) и счётчик nonce — после обмена ключами (kx)
type TcpSendKey = Option<(secretbox::Key, u64)>;
enum Sink {
    TcpStream(TcpStreamSink, TcpSendKey),""")
rep("""                    Sink::TcpStream(s) => {
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }""", """                    Sink::TcpStream(s, enc) => {
                        let bytes = match enc.as_mut() {
                            Some((k, seq)) => {
                                *seq += 1;
                                secretbox::seal(&bytes, &kx_nonce(*seq), k)
                            }
                            None => bytes,
                        };
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }""")
rep("""            let (a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            sink = Some(Sink::TcpStream(a));
            while let Ok(Some(Ok(bytes))) = timeout(30_000, b.next()).await {
                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                    break;
                }
            }""", """            let (a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            sink = Some(Sink::TcpStream(a, None));
            // Клиент, который пишет сразу, — без обмена ключами (как раньше). Молчит — ждёт KeyExchange.
            let mut pending: Option<BytesMut> = None;
            let mut recv_key: Option<(secretbox::Key, u64)> = None;
            match timeout(KX_WAIT_MS, b.next()).await {
                Ok(Some(Ok(bytes))) => pending = Some(bytes),
                Ok(_) => return Ok(()),
                Err(_) => {
                    if let Some(sk) = self.inner.sk.clone() {
                        let (our_pk, our_sk) = box_::gen_keypair();
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_key_exchange(KeyExchange {
                            keys: vec![sign::sign(&our_pk.0, &sk).into()],
                            ..Default::default()
                        });
                        Self::send_to_sink(&mut sink, msg_out).await;
                        match timeout(30_000, b.next()).await {
                            Ok(Some(Ok(bytes))) => match kx_finish(&bytes, &our_sk) {
                                Some(k) => {
                                    log::debug!("Tcp connection from {:?} secured", addr);
                                    if let Some(Sink::TcpStream(_, enc)) = sink.as_mut() {
                                        *enc = Some((k.clone(), 0));
                                    }
                                    recv_key = Some((k, 0));
                                }
                                // не KeyExchange — клиент без шифрования, обрабатываем как обычно
                                None => pending = Some(bytes),
                            },
                            _ => return Ok(()),
                        }
                    }
                }
            }
            loop {
                let mut bytes = match pending.take() {
                    Some(b0) => b0,
                    None => match timeout(30_000, b.next()).await {
                        Ok(Some(Ok(b0))) => b0,
                        _ => break,
                    },
                };
                if let Some((k, seq)) = recv_key.as_mut() {
                    *seq += 1;
                    match secretbox::open(&bytes, &kx_nonce(*seq), k) {
                        Ok(plain) => bytes = BytesMut::from(&plain[..]),
                        Err(()) => {
                            log::warn!("Tcp connection from {:?}: decryption error", addr);
                            break;
                        }
                    }
                }
                if !self.handle_tcp(&bytes, &mut sink, addr, key, ws).await {
                    break;
                }
            }""")
s += '''

// ---- TCP key exchange (kx, версия 0), см. RustDesk src/common.rs key_exchange / create_symmetric_key_msg
const KX_WAIT_MS: u64 = 1_000;

#[inline]
fn kx_nonce(seqnum: u64) -> secretbox::Nonce {
    let mut nonce = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);
    nonce.0[..std::mem::size_of_val(&seqnum)].copy_from_slice(&seqnum.to_le_bytes());
    nonce
}

/// Ответ клиента KeyExchange{keys: [его box pk, box_::seal(симм. ключ, нулевой nonce)]} → симметричный ключ
fn kx_finish(bytes: &[u8], our_sk: &box_::SecretKey) -> Option<secretbox::Key> {
    let msg = RendezvousMessage::parse_from_bytes(bytes).ok()?;
    if let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union {
        if ex.keys.len() != 2 {
            return None;
        }
        let their_pk = box_::PublicKey::from_slice(&ex.keys[0])?;
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let key = box_::open(&ex.keys[1], &nonce, &their_pk, our_sk).ok()?;
        return secretbox::Key::from_slice(&key);
    }
    None
}
'''
open(p, 'w').write(s)
print("patched", p)
