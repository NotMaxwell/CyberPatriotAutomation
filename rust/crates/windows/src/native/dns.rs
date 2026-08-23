//! The DNS servers each live interface is configured with, read from the IP
//! helper API.
//!
//! Replaces parsing `netsh interface ip show dns`, whose layout and headings are
//! localised. It also removes a subtler bug the parser could only paper over:
//! the check ran over text, so an address embedded in a longer one matched, and
//! a resolver at 11.1.1.10 was reported as the public 1.1.1.1. Comparing
//! `IpAddr` values makes the match exact.

use super::from_wide;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};

/// Loopback adapters, which the C# port skips by interface type.
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

/// The DNS servers configured on every live, non-loopback interface.
///
/// Returns `None` when the adapter list could not be read.
pub fn servers() -> Option<Vec<(String, IpAddr)>> {
    // Only the DNS list is wanted, so the address lists are skipped.
    let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 0u32;

    unsafe {
        // Sizing call: expected to come back with the required buffer size.
        let status = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, None, &mut size);
        if status != ERROR_BUFFER_OVERFLOW.0 || size == 0 {
            return None;
        }

        // IP_ADAPTER_ADDRESSES_LH contains pointers, so the buffer has to be
        // aligned for it rather than being a plain byte vector.
        let count = (size as usize).div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer: Vec<IP_ADAPTER_ADDRESSES_LH> = Vec::with_capacity(count);
        let head = buffer.as_mut_ptr();
        size = (count * std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>()) as u32;

        if GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(head), &mut size) != 0 {
            return None;
        }

        let mut found = Vec::new();
        let mut adapter = head as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let entry = &*adapter;
            adapter = entry.Next;

            if entry.OperStatus != IfOperStatusUp || entry.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }

            let name = from_wide(entry.FriendlyName.0)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "(unnamed)".to_string());

            let mut server = entry.FirstDnsServerAddress;
            while !server.is_null() {
                if let Some(address) = to_ip((*server).Address.lpSockaddr) {
                    found.push((name.clone(), address));
                }
                server = (*server).Next;
            }
        }

        Some(found)
    }
}

/// Read a `SOCKADDR` as an [`IpAddr`], for the two families DNS uses.
///
/// # Safety
/// `raw` must be null or point to a `SOCKADDR` whose family field is valid.
unsafe fn to_ip(raw: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<IpAddr> {
    unsafe {
        if raw.is_null() {
            return None;
        }
        match (*raw).sa_family {
            AF_INET => {
                let v4 = &*(raw as *const SOCKADDR_IN);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    v4.sin_addr.S_un.S_addr,
                ))))
            }
            AF_INET6 => {
                let v6 = &*(raw as *const SOCKADDR_IN6);
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}
