use crate::pattern::{fill_bytes, Pattern};
use log::debug;
use std::{
    alloc::{alloc, Layout},
    ffi::{CStr, CString},
    mem::size_of,
    ptr::{addr_of, null_mut},
};
use windows_sys::{
    core::PCSTR,
    Win32::Networking::WinSock::{
        getaddrinfo, gethostbyname, ADDRINFOA, AF_INET, HOSTENT, SOCKADDR,
    },
};

const VERIFY_CERTIFICATE_PATTERN: Pattern = Pattern {
    name: "VerifyCertificate",
    start: 0x0000000140100000,
    end: 0x0000000200000000,
    mask: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
    ????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxx????xxxxxxxxxxxxxxxxxxxxxxx?????\
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxx????xxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxx\
    xxxxxxxxxxxxxxxx????xxxx????xxxxxxxxxxx?????xxxxxxxx????xxxxxx?????xxxxxxxx????xxxx????xxxx\
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?????x????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx\
    xxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxx\
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxx",
    op: &[
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x44, 0x88, 0x44, 0x24, 0x18, 0x55, 0x56, 0x57, 0x48, 0x83,
        0xEC, 0x30, 0x33, 0xED, 0x41, 0x0F, 0xB6, 0xC0, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x89,
        0x6C, 0x24, 0x68, 0x41, 0x80, 0xF8, 0x01, 0x75, 0x5C, 0x48, 0x8D, 0x8A, 0xC0, 0x01, 0x00,
        0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x47, 0x8B, 0x87, 0x10, 0x08, 0x00,
        0x00, 0x44, 0x8B, 0x8F, 0x0C, 0x06, 0x00, 0x00, 0x48, 0x8D, 0x8F, 0x14, 0x08, 0x00, 0x00,
        0x89, 0x44, 0x24, 0x28, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x8D, 0x87, 0x10, 0x06, 0x00,
        0x00, 0x48, 0x8B, 0xCE, 0x48, 0x8B, 0xD7, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F,
        0x84, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x45, 0xCE, 0x48, 0x8B, 0x5C, 0x24, 0x50, 0x48, 0x83,
        0xC4, 0x30, 0x5F, 0x5E, 0x5D, 0xC3, 0x0F, 0xB6, 0x44, 0x24, 0x60, 0x48, 0x8D, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x84, 0xC0, 0x75, 0x0D, 0x83, 0xBF,
        0x24, 0x08, 0x00, 0x00, 0x00, 0x75, 0x04, 0x33, 0xC0, 0xEB, 0x05, 0xB8, 0x01, 0x00, 0x00,
        0x00, 0x44, 0x0F, 0xB6, 0xC0, 0x48, 0x8B, 0xD7, 0x48, 0x8B, 0xCB, 0xE8, 0x00, 0x00, 0x00,
        0x00, 0x85, 0xC0, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00, 0x44, 0x8B, 0x8B, 0xC4, 0x01, 0x00,
        0x00, 0x44, 0x3B, 0x8F, 0x04, 0x04, 0x00, 0x00, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00, 0x8B,
        0x83, 0xD0, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0x83, 0xC8, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8B,
        0xD4, 0x01, 0x00, 0x00, 0x89, 0x44, 0x24, 0x28, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x8B,
        0xD7, 0x48, 0x8B, 0xCE, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x85, 0x00, 0x00,
        0x00, 0x00, 0xF6, 0x83, 0xC0, 0x01, 0x00, 0x00, 0x01, 0x74, 0x52, 0x48, 0x8D, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8D, 0x8F, 0x40, 0x03, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00,
        0x85, 0xC0, 0x74, 0x1B, 0x48, 0x8D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8F, 0x40,
        0x03, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x85, 0x00, 0x00, 0x00,
        0x00, 0x8B, 0x6C, 0x24, 0x68, 0x48, 0x85, 0xF6, 0x74, 0x17, 0x48, 0x8B, 0x86, 0x70, 0x01,
        0x00, 0x00, 0x80, 0xB8, 0x98, 0x00, 0x00, 0x00, 0x00, 0x74, 0x07, 0xC6, 0x80, 0x98, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8D, 0x8F, 0x40, 0x03, 0x00, 0x00, 0x48, 0x8D, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x09, 0xF6, 0x83, 0xC0, 0x01,
        0x00, 0x00, 0x02, 0x74, 0x58, 0x48, 0x8B, 0x93, 0xF0, 0x01, 0x00, 0x00, 0x48, 0x85, 0xD2,
        0x74, 0x75, 0x41, 0xB0, 0x01, 0x48, 0x8B, 0xCE, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xE8,
        0x89, 0x44, 0x24, 0x68, 0x85, 0xC0, 0x74, 0x49, 0x48, 0x8B, 0x93, 0xF0, 0x01, 0x00, 0x00,
        0x48, 0x8B, 0xCE, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x9B, 0xF8, 0x01, 0x00, 0x00,
        0x48, 0x85, 0xDB, 0x74, 0x54, 0x0F, 0xB6, 0x44, 0x24, 0x60, 0xE9, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0x9C, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0x5C, 0x24, 0x50, 0x48, 0x83, 0xC4, 0x30, 0x5F,
        0x5E, 0x5D, 0xC3, 0xB8, 0x9A, 0xFF, 0xFF, 0xFF, 0x48, 0x8B, 0x5C, 0x24, 0x50, 0x48, 0x83,
        0xC4, 0x30, 0x5F, 0x5E, 0x5D, 0xC3, 0x48, 0x8B, 0x8B, 0xF0, 0x01, 0x00, 0x00, 0xE8, 0x00,
        0x00, 0x00, 0x00, 0x48, 0xC7, 0x83, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8B,
        0xC5, 0x48, 0x8B, 0x5C, 0x24, 0x50, 0x48, 0x83, 0xC4, 0x30, 0x5F, 0x5E, 0x5D, 0xC3, 0x48,
        0x8B, 0xD7, 0x48, 0x8B, 0xCE, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x5C, 0x24, 0x50,
        0xB8, 0xCD, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xC4, 0x30, 0x5F, 0x5E, 0x5D, 0xC3,
    ],
};

/// TODO: ANDROMEDA USES getaddrinfo
const HOSTNAME_LOOKUP_PATTERN: Pattern = Pattern {
    name: "getaddrinfo",
    start: 0x0000000140100000,
    end: 0x0000000200000000,
    mask: "xx????xxxxxxxxxxxxxxxxx",
    op: &[
        0xFF, 0x15, 0x10, 0x09, 0xE9, 0x01, //   call   QWORD PTR [rip+0x1e90910]
        0x85, 0xC0, //  test   eax,eax
        0x75, 0x52, //  jne    0x5c
        0x48, 0x8B, 0x44, 0x24, 0x68, // mov    rax,QWORD PTR [rsp+0x68]
        0x48, 0x8D, 0x53, 0x18, //  lea    rdx,[rbx+0x18]
        0x4C, 0x8B, 0x40, 0x20, // mov    r8,QWORD PTR [rax+0x20]
    ],
};

// Zero the checks at: 0000000144C2047F

pub unsafe fn hook() {
    hook_host_lookup();
    // verify_certificate();
}

static mut LOCAL_ADDR: SOCKADDR = SOCKADDR {
    sa_family: AF_INET,
    sa_data: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
};

static ADDRESS_MAPPINGS: &[(&str, u16)] = &[
    ("winter15.gosredirector.ea.com", 0),
    ("gosca.ea.com", 0),
    ("ec2-54-84-48-229.compute-1.amazonaws.com", 0),
    ("mea-public.biowareonline.net", 0),
    ("pin-river.data.ea.com", 0),
    ("pin-em.data.ea.com", 0),
];

#[no_mangle]
pub unsafe extern "system" fn fake_getaddrinfo(
    pnodename: PCSTR,
    pservicename: PCSTR,
    phints: *const ADDRINFOA,
    ppresult: *mut *mut ADDRINFOA,
) -> i32 {
    if !pnodename.is_null() {
        // Derive the safe name from the str bytes
        let nodename = CStr::from_ptr(pnodename.cast());
        debug!("Node: {:?}", nodename);
    }
    if !pservicename.is_null() {
        // Derive the safe name from the str bytes
        let servicename = CStr::from_ptr(pservicename.cast());
        debug!(" Service: {:?}", servicename);
    }

    if !phints.is_null() {
        let hints = &*phints;
        debug!(
            "{} {} {} {}",
            hints.ai_flags, hints.ai_family, hints.ai_socktype, hints.ai_protocol
        )
    }

    // let hinits = &*phints;
    // let mem: ADDRINFOA = ADDRINFOA {
    //     ai_flags: hinits.ai_flags,
    //     ai_family: AF_INET as i32,
    //     ai_socktype: hinits.ai_socktype,
    //     ai_protocol: hinits.ai_protocol,
    //     ai_addrlen: 4,
    //     ai_canonname: null_mut(),
    //     ai_addr: &mut LOCAL_ADDR,
    //     ai_next: null_mut(),
    // };

    getaddrinfo(pnodename, pservicename, phints, ppresult)
}

unsafe fn hook_host_lookup() {
    // TODO: THIS NEEDS TO BE REPLACED WITH `fake_getaddrinfo`

    // address of actual 00 00 7F FE B6 5C 3C E0
    // E0 3C 5C B6 FE 7F 00 00

    Pattern::apply_with_transform(
        &HOSTNAME_LOOKUP_PATTERN,
        size_of::<usize>(),
        |addr| {
            // Initial -> f652b0

            debug!("Pre distance {}", addr as usize);

            // == Obtain the address from the call ????
            // call ???? (Obtain the relative call distance)
            let distance = *(addr.add(2 /* Skip call opcode */) as *const u32);

            debug!("Post distance");

            // Relative jump -> EEF240 (jump to jmp in thunk table)
            let jmp_address = addr.add(6 /* Skip call opcode + address */ + distance as usize);

            jmp_address
        },
        |addr| {
            // Replace the address with our faker function
            let ptr: *mut usize = addr as *mut usize;
            *ptr = fake_getaddrinfo as usize;
        },
    );
}

/// Finds and hooks the VerifyCertificate function replacing it with
/// something that will always return zero aka the success value
unsafe fn verify_certificate() {
    Pattern::apply(&VERIFY_CERTIFICATE_PATTERN, 16, |addr| {
        // Replacement opcodes for just returning always zero
        let new_ops: [u8; 9] = [
            0xb8, 0x0, 0x0, 0x0, 0x0,  // mov eax, 0
            0xc3, // ret
            0x90, // nop
            0x90, // nop
            0x90, // nop
        ];

        // Iterate the opcodes and write them to the ptr
        let mut op_ptr: *mut u8 = addr;
        for op in new_ops {
            *op_ptr = op;
            op_ptr = op_ptr.add(1);
        }
    });
}
