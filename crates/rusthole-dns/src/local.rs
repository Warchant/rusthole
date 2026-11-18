//! Replies from local DNS data (part P3c). Pure: no I/O.
//!
//! [`rusthole_core::localdns::LocalZone`] decides; this module makes the DNS messages.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use rusthole_core::DomainName;
use rusthole_core::localdns::{LocalData, LocalRr};

use crate::wire::{Request, response_for};

/// The DNS class of local data.
pub const LOCAL_CLASS: u16 = 1;

/// An authoritative reply (AA bit) with local records. No records gives NODATA.
pub fn local_response(req: &Request, records: &[LocalRr]) -> Message {
    let mut m = response_for(req, ResponseCode::NoError);
    m.metadata.authoritative = true;
    m.answers = records.iter().filter_map(to_record).collect();
    m
}

/// NXDOMAIN for a private reverse name that no conditional forwarding rule covers.
pub fn private_reverse_response(req: &Request) -> Message {
    response_for(req, ResponseCode::NXDomain)
}

/// The DNS name of a domain name (fully qualified).
pub fn dns_name(d: &DomainName) -> Option<Name> {
    Name::from_ascii(format!("{}.", d.as_str())).ok()
}

fn to_record(r: &LocalRr) -> Option<Record> {
    let data = match &r.data {
        LocalData::A(ip) => RData::A(A(*ip)),
        LocalData::Aaaa(ip) => RData::AAAA(AAAA(*ip)),
        LocalData::Cname(t) => RData::CNAME(CNAME(dns_name(t)?)),
        LocalData::Ptr(t) => RData::PTR(PTR(dns_name(t)?)),
    };
    let mut rec = Record::from_rdata(dns_name(&r.name)?, r.ttl, data);
    rec.dns_class = DNSClass::IN;
    Some(rec)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::RecordType;

    use super::*;
    use crate::wire::parse_request;

    fn req(name: &str, t: RecordType) -> Request {
        let mut m = Message::new(9, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
        parse_request(&m.to_vec().unwrap()).unwrap().0
    }

    fn d(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    #[test]
    fn local_answers_are_authoritative() {
        let r = req("Media.LAN.", RecordType::A);
        let recs = vec![
            LocalRr {
                name: d("media.lan"),
                ttl: 60,
                data: LocalData::Cname(d("nas.lan")),
            },
            LocalRr {
                name: d("nas.lan"),
                ttl: 300,
                data: LocalData::A(Ipv4Addr::new(192, 0, 2, 10)),
            },
        ];
        let m = local_response(&r, &recs);
        assert!(m.metadata.authoritative);
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(m.metadata.id, 9);
        assert_eq!(m.answers.len(), 2);
        assert_eq!(m.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(m.answers[1].ttl, 300);
        assert_eq!(m.queries[0].name().to_ascii(), "Media.LAN.");
        let nodata = local_response(&r, &[]);
        assert!(nodata.metadata.authoritative);
        assert_eq!(nodata.answers.len(), 0);
        let ptr = local_response(
            &req("10.2.0.192.in-addr.arpa.", RecordType::PTR),
            &[LocalRr {
                name: d("10.2.0.192.in-addr.arpa"),
                ttl: 300,
                data: LocalData::Ptr(d("nas.lan")),
            }],
        );
        assert_eq!(ptr.answers[0].record_type(), RecordType::PTR);
        let nx = private_reverse_response(&req("1.0.0.10.in-addr.arpa.", RecordType::PTR));
        assert_eq!(nx.metadata.response_code, ResponseCode::NXDomain);
        assert!(!nx.metadata.authoritative);
    }
}
