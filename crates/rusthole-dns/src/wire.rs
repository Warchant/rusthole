//! DNS wire format helpers on top of `hickory-proto`: request checks, upstream query and
//! reply checks, cache preparation, and client replies.
//!
//! All functions here are pure. They do no I/O.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, HINFO};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rusthole_core::DomainName;
use rusthole_core::cache::{CacheKey, TtlPolicy};

use crate::filter::{BlockKind, BlockReply};

/// Length of the DNS header.
pub const HEADER_LEN: usize = 12;
/// The smallest UDP reply size (RFC 1035). A client without EDNS gets at most this.
pub const MIN_UDP_PAYLOAD: u16 = 512;
/// The EDNS UDP size that rusthole sends to upstreams and the largest UDP reply that it
/// sends to clients (DNS flag day 2020).
pub const MAX_UDP_PAYLOAD: u16 = 1232;
/// The largest DNS message over TCP (2-byte length prefix).
pub const MAX_TCP_MESSAGE: usize = 65_535;
/// The largest answer (encoded, in bytes) that goes into the cache. A larger answer goes to
/// the client but not into the cache. With this limit, the cache holds at most
/// `cache.max_entries` x 4 KiB of wire data, so a flood of big answers cannot use all the
/// memory of a small host.
pub const MAX_CACHEABLE_BYTES: usize = 4096;

/// The fields of the 12-byte header that the pipeline checks before a full parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawHeader {
    /// The message ID.
    pub id: u16,
    /// True for a response.
    pub qr: bool,
    /// The opcode (0 = QUERY).
    pub opcode: u8,
    /// Recursion desired.
    pub rd: bool,
    /// Number of questions.
    pub qdcount: u16,
}

impl RawHeader {
    /// Reads the header. Returns `None` when `bytes` is shorter than 12 bytes.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let h: &[u8; HEADER_LEN] = bytes.get(..HEADER_LEN)?.try_into().ok()?;
        let [id0, id1, f0, _f1, qd0, qd1, ..] = *h;
        Some(Self {
            id: u16::from_be_bytes([id0, id1]),
            qr: f0 & 0x80 != 0,
            opcode: (f0 >> 3) & 0x0f,
            rd: f0 & 0x01 != 0,
            qdcount: u16::from_be_bytes([qd0, qd1]),
        })
    }
}

/// A reply with a header only: QR=1, the ID, the opcode and RD of the request, RA=1, the
/// response code, and no records.
pub fn header_reply(h: &RawHeader, rcode: ResponseCode) -> Vec<u8> {
    let [id0, id1] = h.id.to_be_bytes();
    let f0 = 0x80 | ((h.opcode & 0x0f) << 3) | u8::from(h.rd);
    let f1 = 0x80 | (rcode.low() & 0x0f);
    vec![id0, id1, f0, f1, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// The EDNS data of a client query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientEdns {
    /// The UDP size that the client can receive.
    pub payload: u16,
    /// The DNSSEC OK bit.
    pub dnssec_ok: bool,
}

/// A parsed client query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The message ID.
    pub id: u16,
    /// Recursion desired.
    pub rd: bool,
    /// Checking disabled.
    pub cd: bool,
    /// Authentic data (RFC 6840: the client understands the AD bit).
    pub ad: bool,
    /// The question, as the client sent it (the name keeps its case).
    pub query: Query,
    /// The EDNS data, if the client sent an OPT record.
    pub edns: Option<ClientEdns>,
}

impl Request {
    /// The DNSSEC OK bit of the query.
    pub fn dnssec_ok(&self) -> bool {
        self.edns.is_some_and(|e| e.dnssec_ok)
    }

    /// The largest UDP reply for this client: its EDNS size in `512..=1232`, or 512 without
    /// EDNS.
    pub fn max_udp_len(&self) -> usize {
        let size = self.edns.map_or(MIN_UDP_PAYLOAD, |e| {
            e.payload.clamp(MIN_UDP_PAYLOAD, MAX_UDP_PAYLOAD)
        });
        usize::from(size)
    }

    /// The cache key: the lowercase name, the type, the class and the DO bit.
    pub fn cache_key(&self) -> CacheKey {
        CacheKey::new(
            &self.query.name().to_ascii(),
            u16::from(self.query.query_type()),
            u16::from(self.query.query_class()),
            self.dnssec_ok(),
        )
    }
}

/// Why a query is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The message does not parse, or it is not a query. Answer FORMERR.
    #[error("the query is malformed")]
    Malformed,
    /// The query has not exactly one question. Answer FORMERR.
    #[error("the query has not exactly one question")]
    QuestionCount,
    /// The query type is a zone transfer or a meta type. Answer NOTIMP.
    #[error("the query type is not supported")]
    NotImplemented,
}

/// Parses a client query. The caller has checked the raw header (QR=0, opcode QUERY).
pub fn parse_request(bytes: &[u8]) -> Result<(Request, Message), RequestError> {
    let msg = Message::from_vec(bytes).map_err(|_| RequestError::Malformed)?;
    if msg.metadata.message_type != MessageType::Query || msg.metadata.op_code != OpCode::Query {
        return Err(RequestError::Malformed);
    }
    let [query] = msg.queries.as_slice() else {
        return Err(RequestError::QuestionCount);
    };
    match query.query_type() {
        RecordType::AXFR | RecordType::IXFR | RecordType::OPT => {
            return Err(RequestError::NotImplemented);
        }
        _ => {}
    }
    let edns = msg.edns.as_ref().map(|e| ClientEdns {
        payload: e.max_payload(),
        dnssec_ok: e.flags().dnssec_ok,
    });
    let req = Request {
        id: msg.metadata.id,
        rd: msg.metadata.recursion_desired,
        cd: msg.metadata.checking_disabled,
        ad: msg.metadata.authentic_data,
        query: query.clone(),
        edns,
    };
    Ok((req, msg))
}

/// The query name in lowercase escaped text form, without the trailing dot. The root name
/// is `"."`.
pub fn qname_text(name: &Name) -> String {
    let s = name.to_ascii().to_ascii_lowercase();
    match s.strip_suffix('.') {
        Some(t) if !t.is_empty() => t.to_owned(),
        _ => s,
    }
}

/// The name as a [`DomainName`], or `None` when it is not a valid host name.
pub fn domain_of(name: &Name) -> Option<DomainName> {
    DomainName::parse(&name.to_ascii()).ok()
}

/// Our EDNS record: UDP size 1232, version 0, the given DO bit, no options.
fn our_edns(dnssec_ok: bool) -> Edns {
    let mut e = Edns::new();
    e.set_max_payload(MAX_UDP_PAYLOAD);
    e.set_version(0);
    e.set_dnssec_ok(dnssec_ok);
    e
}

/// Makes the upstream query: our ID, RD=1, AD=1 (RFC 6840: ask for the AD bit), the
/// question, and our own EDNS record with the client DO bit. No client option (for example
/// ECS or a cookie) goes to the upstream.
pub fn upstream_query(id: u16, query: &Query, dnssec_ok: bool) -> Option<Vec<u8>> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.metadata.authentic_data = true;
    m.add_query(query.clone());
    m.set_edns(our_edns(dnssec_ok));
    m.to_vec().ok()
}

/// Why an upstream reply is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyReject {
    /// The reply does not parse.
    #[error("the reply is malformed")]
    Malformed,
    /// The QR bit is not set.
    #[error("the message is not a response")]
    NotResponse,
    /// The ID is not the query ID.
    #[error("the reply has a wrong ID")]
    WrongId,
    /// The opcode is not QUERY.
    #[error("the reply has a wrong opcode")]
    WrongOpcode,
    /// The question is not the query question.
    #[error("the reply has a wrong question")]
    WrongQuestion,
}

/// True when two questions are the same: the name (ASCII case does not matter), the type
/// and the class.
pub fn question_matches(a: &Query, b: &Query) -> bool {
    // `Name` equality in hickory ignores ASCII case.
    a.query_type() == b.query_type() && a.query_class() == b.query_class() && a.name() == b.name()
}

/// Checks an upstream reply against the query (amendment A5): same ID, QR=1, opcode
/// QUERY, and exactly the same question. The caller checks the source address.
pub fn check_upstream_reply(bytes: &[u8], id: u16, query: &Query) -> Result<Message, ReplyReject> {
    let raw = RawHeader::parse(bytes).ok_or(ReplyReject::Malformed)?;
    if raw.id != id {
        return Err(ReplyReject::WrongId);
    }
    if !raw.qr {
        return Err(ReplyReject::NotResponse);
    }
    let msg = Message::from_vec(bytes).map_err(|_| ReplyReject::Malformed)?;
    if msg.metadata.op_code != OpCode::Query {
        return Err(ReplyReject::WrongOpcode);
    }
    match msg.queries.as_slice() {
        [q] if question_matches(q, query) => Ok(msg),
        _ => Err(ReplyReject::WrongQuestion),
    }
}

/// True for an upstream answer that makes the query go to the next upstream.
pub fn is_server_failure(msg: &Message) -> bool {
    msg.metadata.response_code == ResponseCode::ServFail
}

/// An upstream answer ready for the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cacheable {
    /// The answer with clamped TTLs and without EDNS.
    pub message: Message,
    /// The cache TTL in seconds.
    pub ttl: u32,
}

/// Prepares an upstream answer for the cache.
///
/// - Only NOERROR and NXDOMAIN answers without the TC bit go to the cache. Other answers
///   (SERVFAIL, REFUSED, truncated) come back as `Err` with the EDNS record removed.
/// - An answer longer than [`MAX_CACHEABLE_BYTES`] (or that does not encode) also comes
///   back as `Err`. The client gets it, but the cache does not keep it.
/// - The EDNS record is removed (RFC 6891: OPT records are never cached).
/// - Positive answer: each record TTL is clamped to `[min_ttl, max_ttl]`. The cache TTL is
///   the lowest answer record TTL.
/// - Negative answer (NXDOMAIN, or NOERROR with no answer record): the cache TTL comes from
///   the SOA record ([`TtlPolicy::negative`]). No record TTL is higher than it.
///
/// The caller checked the question, so the answer always matches the cache key.
pub fn prepare_for_cache(mut msg: Message, policy: &TtlPolicy) -> Result<Cacheable, Box<Message>> {
    msg.edns = None;
    msg.signature = None;
    let rcode = msg.metadata.response_code;
    if msg.metadata.truncation
        || !(rcode == ResponseCode::NoError || rcode == ResponseCode::NXDomain)
    {
        return Err(Box::new(msg));
    }
    let negative = rcode == ResponseCode::NXDomain || msg.answers.is_empty();
    let ttl = if negative {
        let soa = msg.authorities.iter().find_map(|r| match &r.data {
            RData::SOA(soa) => Some((r.ttl, soa.minimum)),
            _ => None,
        });
        let ttl = policy.negative(soa);
        for r in all_records_mut(&mut msg) {
            r.ttl = r.ttl.min(ttl);
        }
        ttl
    } else {
        for r in all_records_mut(&mut msg) {
            r.ttl = policy.positive(r.ttl);
        }
        msg.answers.iter().map(|r| r.ttl).min().unwrap_or(0)
    };
    if !msg.to_vec().is_ok_and(|v| v.len() <= MAX_CACHEABLE_BYTES) {
        return Err(Box::new(msg));
    }
    Ok(Cacheable { message: msg, ttl })
}

fn all_records_mut(msg: &mut Message) -> impl Iterator<Item = &mut Record> {
    msg.answers
        .iter_mut()
        .chain(msg.authorities.iter_mut())
        .chain(msg.additionals.iter_mut())
}

/// The owner name of each answer record and each CNAME target, without duplicates. A name
/// that is not a valid host name is left out.
pub fn answer_names(msg: &Message) -> Vec<DomainName> {
    let mut out: Vec<DomainName> = Vec::new();
    let mut push = |name: &Name| {
        if let Some(d) = domain_of(name)
            && !out.contains(&d)
        {
            out.push(d);
        }
    };
    for r in &msg.answers {
        push(&r.name);
        if let RData::CNAME(target) = &r.data {
            push(&target.0);
        }
    }
    out
}

/// A response header for `req`: its ID, RD and CD, QR=1, RA=1, and the question as the
/// client sent it.
pub(crate) fn response_for(req: &Request, rcode: ResponseCode) -> Message {
    let mut m = Message::new(req.id, MessageType::Response, OpCode::Query);
    m.metadata.recursion_desired = req.rd;
    m.metadata.checking_disabled = req.cd;
    m.metadata.recursion_available = true;
    m.metadata.response_code = rcode;
    m.add_query(req.query.clone());
    if let Some(e) = req.edns {
        m.set_edns(our_edns(e.dnssec_ok));
    }
    m
}

/// Builds the client reply from an upstream or cached answer.
///
/// The reply is new: the client ID, question, RD and CD; RA=1; the upstream response code;
/// the AD bit of the upstream only when the client set DO or AD (RFC 6840 section 5.8);
/// each record TTL lowered by `age`; our own EDNS record only when the client sent one (no
/// upstream EDNS option). Without DO, DNSSEC records of other types are removed.
pub fn answer_response(req: &Request, upstream: &Message, age: u32) -> Message {
    let rcode = upstream.metadata.response_code;
    // An extended response code belongs to the upstream EDNS exchange, not to the client.
    let rcode = if rcode.high() > 0 {
        ResponseCode::ServFail
    } else {
        rcode
    };
    let mut m = response_for(req, rcode);
    m.metadata.authentic_data = upstream.metadata.authentic_data && (req.dnssec_ok() || req.ad);
    let aged = |r: &Record| {
        let mut r = r.clone();
        r.ttl = r.ttl.saturating_sub(age);
        r
    };
    m.answers = upstream.answers.iter().map(aged).collect();
    m.authorities = upstream.authorities.iter().map(aged).collect();
    m.additionals = upstream.additionals.iter().map(aged).collect();
    m.maybe_strip_dnssec_records(req.dnssec_ok())
}

/// Builds an error reply (for example SERVFAIL) with the question.
pub fn error_response(req: &Request, rcode: ResponseCode) -> Message {
    response_for(req, rcode)
}

/// Builds the reply for a blocked query (amendment A3).
///
/// - `Null`: `0.0.0.0` for A, `::` for AAAA, NODATA for other types.
/// - `Ip`: the given address for A or AAAA, NODATA when the address is missing or for
///   other types.
/// - `Nodata`: NOERROR with no answer.
/// - `Nxdomain`: NXDOMAIN.
/// - An ANY query that is not NXDOMAIN gets the RFC 8482 answer: one HINFO record with
///   CPU `RFC8482` and an empty OS.
pub fn block_response(req: &Request, reply: &BlockReply) -> Message {
    let name = req.query.name().clone();
    let class = req.query.query_class();
    let ttl = reply.ttl;
    let record = |data: RData| {
        let mut r = Record::from_rdata(name.clone(), ttl, data);
        r.dns_class = class;
        r
    };
    if reply.kind == BlockKind::Nxdomain {
        return response_for(req, ResponseCode::NXDomain);
    }
    let mut m = response_for(req, ResponseCode::NoError);
    let qtype = req.query.query_type();
    let data = match (qtype, reply.kind) {
        (RecordType::ANY, _) => Some(RData::HINFO(HINFO::new(
            "RFC8482".to_owned(),
            String::new(),
        ))),
        (RecordType::A, BlockKind::Null) => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
        (RecordType::AAAA, BlockKind::Null) => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
        (RecordType::A, BlockKind::Ip { v4: Some(ip), .. }) => Some(RData::A(A(ip))),
        (RecordType::AAAA, BlockKind::Ip { v6: Some(ip), .. }) => Some(RData::AAAA(AAAA(ip))),
        _ => None,
    };
    if let Some(data) = data {
        m.answers.push(record(data));
    }
    m
}

/// A header-only SERVFAIL for a message that cannot be encoded.
fn servfail_header(msg: &Message) -> Vec<u8> {
    header_reply(
        &RawHeader {
            id: msg.metadata.id,
            qr: true,
            opcode: u8::from(msg.metadata.op_code),
            rd: msg.metadata.recursion_desired,
            qdcount: 0,
        },
        ResponseCode::ServFail,
    )
}

/// Encodes a reply. When it is longer than `max_len`, the function sends a truncated reply
/// instead: the TC bit, the question, the EDNS record and no other record (RFC 1035
/// section 4.2.1, RFC 6891). The client then asks again over TCP.
pub fn encode(msg: &Message, max_len: usize) -> Vec<u8> {
    match msg.to_vec() {
        Ok(bytes) if bytes.len() <= max_len => bytes,
        Ok(_) => match msg.truncate().to_vec() {
            Ok(bytes) if bytes.len() <= max_len => bytes,
            _ => {
                let mut h = servfail_header(msg);
                // Keep the TC bit with the original response code: the client retries
                // over TCP.
                if let Some(f1) = h.get_mut(3) {
                    *f1 = 0x80 | (msg.metadata.response_code.low() & 0x0f);
                }
                if let Some(f0) = h.get_mut(2) {
                    *f0 |= 0x02;
                }
                h
            }
        },
        Err(_) => servfail_header(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::DNSClass;
    use hickory_proto::rr::rdata::{CNAME, SOA};

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn query_bytes(id: u16, qname: &str, qtype: RecordType, edns: Option<(u16, bool)>) -> Vec<u8> {
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(name(qname), qtype));
        if let Some((size, dnssec_ok)) = edns {
            let mut e = Edns::new();
            e.set_max_payload(size);
            e.set_dnssec_ok(dnssec_ok);
            m.set_edns(e);
        }
        m.to_vec().unwrap()
    }

    fn req(qname: &str, qtype: RecordType, edns: Option<(u16, bool)>) -> Request {
        parse_request(&query_bytes(7, qname, qtype, edns))
            .unwrap()
            .0
    }

    fn a(owner: &str, ttl: u32, ip: [u8; 4]) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A(Ipv4Addr::from(ip))))
    }

    fn soa(owner: &str, ttl: u32, minimum: u32) -> Record {
        Record::from_rdata(
            name(owner),
            ttl,
            RData::SOA(SOA::new(
                name("ns.example."),
                name("admin.example."),
                1,
                3600,
                600,
                86400,
                minimum,
            )),
        )
    }

    const POLICY: TtlPolicy = TtlPolicy {
        min_ttl: 10,
        max_ttl: 1000,
        negative_ttl: 300,
    };

    #[test]
    fn raw_header() {
        assert_eq!(RawHeader::parse(&[0; 11]), None);
        let h = RawHeader::parse(&[0x12, 0x34, 0x81, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            h,
            RawHeader {
                id: 0x1234,
                qr: true,
                opcode: 0,
                rd: true,
                qdcount: 1
            }
        );
        let h = RawHeader::parse(&[0, 1, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(h.opcode, 5);
        assert!(!h.qr);
    }

    #[test]
    fn header_reply_echoes_id_opcode_rd() {
        let h = RawHeader {
            id: 0xabcd,
            qr: false,
            opcode: 2,
            rd: true,
            qdcount: 1,
        };
        let r = header_reply(&h, ResponseCode::Refused);
        let m = Message::from_vec(&r).unwrap();
        assert_eq!(m.metadata.id, 0xabcd);
        assert_eq!(m.metadata.message_type, MessageType::Response);
        assert_eq!(m.metadata.op_code, OpCode::Status);
        assert!(m.metadata.recursion_desired);
        assert_eq!(m.metadata.response_code, ResponseCode::Refused);
        assert_eq!(m.queries.len(), 0);
    }

    #[test]
    fn parse_request_rules() {
        let r = req("Example.COM.", RecordType::A, Some((4096, true)));
        assert_eq!(r.id, 7);
        assert!(r.dnssec_ok());
        assert_eq!(r.max_udp_len(), 1232);
        assert_eq!(r.cache_key(), CacheKey::new("example.com.", 1, 1, true));
        let r = req("example.com.", RecordType::A, Some((100, false)));
        assert_eq!(r.max_udp_len(), 512);
        assert!(!r.dnssec_ok());
        let r = req("example.com.", RecordType::A, None);
        assert_eq!(r.max_udp_len(), 512);

        let axfr = query_bytes(1, "example.com.", RecordType::AXFR, None);
        assert_eq!(
            parse_request(&axfr).unwrap_err(),
            RequestError::NotImplemented
        );

        let mut two = Message::new(1, MessageType::Query, OpCode::Query);
        two.add_query(Query::query(name("a.example."), RecordType::A));
        two.add_query(Query::query(name("b.example."), RecordType::A));
        assert_eq!(
            parse_request(&two.to_vec().unwrap()).unwrap_err(),
            RequestError::QuestionCount
        );
        let none = Message::new(1, MessageType::Query, OpCode::Query);
        assert_eq!(
            parse_request(&none.to_vec().unwrap()).unwrap_err(),
            RequestError::QuestionCount
        );
        let mut bytes = query_bytes(1, "example.com.", RecordType::A, None);
        bytes.truncate(bytes.len() - 2);
        assert_eq!(parse_request(&bytes).unwrap_err(), RequestError::Malformed);
    }

    #[test]
    fn qname_forms() {
        assert_eq!(qname_text(&name("WWW.Example.com.")), "www.example.com");
        assert_eq!(qname_text(&Name::root()), ".");
        assert_eq!(
            domain_of(&name("WWW.Example.com.")).unwrap().as_str(),
            "www.example.com"
        );
        assert_eq!(domain_of(&Name::root()), None);
    }

    #[test]
    fn upstream_query_has_our_edns_and_ad() {
        let q = Query::query(name("example.com."), RecordType::AAAA);
        let bytes = upstream_query(99, &q, true).unwrap();
        let m = Message::from_vec(&bytes).unwrap();
        assert_eq!(m.metadata.id, 99);
        assert!(m.metadata.recursion_desired);
        assert!(m.metadata.authentic_data);
        let e = m.edns.unwrap();
        assert_eq!(e.max_payload(), 1232);
        assert!(e.flags().dnssec_ok);
        assert_eq!(e.options().as_ref().len(), 0);
    }

    fn reply_bytes(id: u16, q: Query, f: impl FnOnce(&mut Message)) -> Vec<u8> {
        let mut m = Message::new(id, MessageType::Response, OpCode::Query);
        m.add_query(q);
        f(&mut m);
        m.to_vec().unwrap()
    }

    #[test]
    fn upstream_reply_checks() {
        let q = Query::query(name("example.com."), RecordType::A);
        let ok = reply_bytes(5, q.clone(), |_| {});
        assert!(check_upstream_reply(&ok, 5, &q).is_ok());
        // The question name case does not matter.
        let upper = reply_bytes(5, Query::query(name("EXAMPLE.com."), RecordType::A), |_| {});
        assert!(check_upstream_reply(&upper, 5, &q).is_ok());
        assert_eq!(
            check_upstream_reply(&ok, 6, &q).unwrap_err(),
            ReplyReject::WrongId
        );
        let other_name = reply_bytes(5, Query::query(name("example.org."), RecordType::A), |_| {});
        assert_eq!(
            check_upstream_reply(&other_name, 5, &q).unwrap_err(),
            ReplyReject::WrongQuestion
        );
        let other_type = reply_bytes(
            5,
            Query::query(name("example.com."), RecordType::AAAA),
            |_| {},
        );
        assert_eq!(
            check_upstream_reply(&other_type, 5, &q).unwrap_err(),
            ReplyReject::WrongQuestion
        );
        let mut chaos = Query::query(name("example.com."), RecordType::A);
        chaos.set_query_class(DNSClass::CH);
        let other_class = reply_bytes(5, chaos, |_| {});
        assert_eq!(
            check_upstream_reply(&other_class, 5, &q).unwrap_err(),
            ReplyReject::WrongQuestion
        );
        let no_question = {
            let m = Message::new(5, MessageType::Response, OpCode::Query);
            m.to_vec().unwrap()
        };
        assert_eq!(
            check_upstream_reply(&no_question, 5, &q).unwrap_err(),
            ReplyReject::WrongQuestion
        );
        let query_not_reply = query_bytes(5, "example.com.", RecordType::A, None);
        assert_eq!(
            check_upstream_reply(&query_not_reply, 5, &q).unwrap_err(),
            ReplyReject::NotResponse
        );
        assert_eq!(
            check_upstream_reply(&[0, 5, 0x80], 5, &q).unwrap_err(),
            ReplyReject::Malformed
        );
    }

    #[test]
    fn cache_positive_ttl_clamp() {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name("example.com."), RecordType::A));
        m.answers.push(a("example.com.", 5, [192, 0, 2, 1]));
        m.answers.push(a("example.com.", 5000, [192, 0, 2, 2]));
        m.set_edns(Edns::new());
        let c = prepare_for_cache(m, &POLICY).unwrap();
        assert_eq!(c.ttl, 10);
        assert_eq!(c.message.answers[0].ttl, 10);
        assert_eq!(c.message.answers[1].ttl, 1000);
        assert!(c.message.edns.is_none());
    }

    #[test]
    fn cache_negative_ttl_from_soa() {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.metadata.response_code = ResponseCode::NXDomain;
        m.authorities.push(soa("example.com.", 900, 60));
        let c = prepare_for_cache(m.clone(), &POLICY).unwrap();
        assert_eq!(c.ttl, 60);
        assert_eq!(c.message.authorities[0].ttl, 60);
        // NODATA without SOA uses negative_ttl.
        let mut nodata = Message::new(1, MessageType::Response, OpCode::Query);
        nodata.metadata.response_code = ResponseCode::NoError;
        assert_eq!(prepare_for_cache(nodata, &POLICY).unwrap().ttl, 300);
        // A large SOA minimum is capped.
        let mut big = m;
        big.authorities[0] = soa("example.com.", 9000, 9000);
        assert_eq!(prepare_for_cache(big, &POLICY).unwrap().ttl, 300);
    }

    #[test]
    fn cache_refuses_servfail_and_truncated() {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.metadata.response_code = ResponseCode::ServFail;
        m.set_edns(Edns::new());
        let back = prepare_for_cache(m, &POLICY).unwrap_err();
        assert!(back.edns.is_none());
        let mut tc = Message::new(1, MessageType::Response, OpCode::Query);
        tc.metadata.truncation = true;
        tc.answers.push(a("example.com.", 50, [192, 0, 2, 1]));
        assert!(prepare_for_cache(tc, &POLICY).is_err());
        let mut refused = Message::new(1, MessageType::Response, OpCode::Query);
        refused.metadata.response_code = ResponseCode::Refused;
        assert!(prepare_for_cache(refused, &POLICY).is_err());
    }

    #[test]
    fn answer_response_is_rebuilt_for_the_client() {
        let r = req("WWW.example.com.", RecordType::A, Some((1232, false)));
        let mut up = Message::new(999, MessageType::Response, OpCode::Query);
        up.metadata.authentic_data = true;
        up.metadata.authoritative = true;
        up.add_query(Query::query(name("www.example.com."), RecordType::A));
        up.answers.push(a("www.example.com.", 100, [192, 0, 2, 1]));
        let mut e = Edns::new();
        e.set_max_payload(4096);
        up.set_edns(e);
        let m = answer_response(&r, &up, 30);
        assert_eq!(m.metadata.id, 7);
        assert!(m.metadata.recursion_available);
        assert!(!m.metadata.authoritative);
        // The client set neither DO nor AD, so no AD bit.
        assert!(!m.metadata.authentic_data);
        assert_eq!(m.queries[0].name().to_ascii(), "WWW.example.com.");
        assert_eq!(m.answers[0].ttl, 70);
        assert_eq!(m.edns.as_ref().unwrap().max_payload(), 1232);

        let r_do = req("www.example.com.", RecordType::A, Some((1232, true)));
        let m = answer_response(&r_do, &up, 500);
        assert!(m.metadata.authentic_data);
        assert_eq!(m.answers[0].ttl, 0);
        assert!(m.edns.as_ref().unwrap().flags().dnssec_ok);

        let r_plain = req("www.example.com.", RecordType::A, None);
        let m = answer_response(&r_plain, &up, 0);
        assert!(m.edns.is_none());
    }

    #[test]
    fn block_replies() {
        let b = |kind| BlockReply { kind, ttl: 2 };
        let r = req("ads.example.", RecordType::A, None);
        let m = block_response(&r, &b(BlockKind::Null));
        assert_eq!(m.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        assert_eq!(m.answers[0].ttl, 2);
        let r6 = req("ads.example.", RecordType::AAAA, None);
        let m = block_response(&r6, &b(BlockKind::Null));
        assert_eq!(m.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
        let https = req("ads.example.", RecordType::HTTPS, None);
        let m = block_response(&https, &b(BlockKind::Null));
        assert_eq!(m.answers.len(), 0);
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        let m = block_response(&r, &b(BlockKind::Nxdomain));
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        let m = block_response(&r, &b(BlockKind::Nodata));
        assert_eq!(m.answers.len(), 0);
        let ip = BlockKind::Ip {
            v4: Some(Ipv4Addr::new(192, 0, 2, 9)),
            v6: None,
        };
        let m = block_response(&r, &b(ip));
        assert_eq!(m.answers[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 9))));
        let m = block_response(&r6, &b(ip));
        assert_eq!(m.answers.len(), 0);
        let any = req("ads.example.", RecordType::ANY, None);
        let m = block_response(&any, &b(BlockKind::Null));
        assert_eq!(m.answers[0].record_type(), RecordType::HINFO);
    }

    #[test]
    fn answer_names_has_owners_and_cname_targets() {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.answers.push(Record::from_rdata(
            name("www.example.com."),
            60,
            RData::CNAME(CNAME(name("Tracker.Example.net."))),
        ));
        m.answers
            .push(a("tracker.example.net.", 60, [192, 0, 2, 1]));
        let names: Vec<String> = answer_names(&m).iter().map(ToString::to_string).collect();
        assert_eq!(names, vec!["www.example.com", "tracker.example.net"]);
    }

    #[test]
    fn encode_truncates_when_too_long() {
        let r = req("big.example.", RecordType::A, Some((512, false)));
        let mut up = Message::new(1, MessageType::Response, OpCode::Query);
        for i in 0..60u8 {
            up.answers.push(a("big.example.", 60, [192, 0, 2, i]));
        }
        let m = answer_response(&r, &up, 0);
        let full = encode(&m, MAX_TCP_MESSAGE);
        assert!(full.len() > 512);
        let short = encode(&m, r.max_udp_len());
        assert!(short.len() <= 512);
        let back = Message::from_vec(&short).unwrap();
        assert!(back.metadata.truncation);
        assert_eq!(back.answers.len(), 0);
        assert_eq!(back.queries.len(), 1);
        assert_eq!(back.metadata.id, 7);
        assert!(back.edns.is_some());
    }

    #[test]
    fn encode_tiny_limit_gives_header() {
        let r = req("example.com.", RecordType::A, None);
        let m = error_response(&r, ResponseCode::NoError);
        let b = encode(&m, 12);
        assert_eq!(b.len(), 12);
        let h = RawHeader::parse(&b).unwrap();
        assert!(h.qr);
        assert_eq!(h.id, 7);
        assert_eq!(b[2] & 0x02, 0x02);
    }
}
