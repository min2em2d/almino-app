# -*- coding: utf-8 -*-
"""
Apple CoreADI (adid_x86_64) Native Windows Emulation Engine
===========================================================
Runs Apple's authentic `adid` daemon binary in-memory on Windows/Linux using Unicorn Engine:
- Provisions brand-new virtual Macs directly against Apple's `MidService/startMachineProvisioning`
  and `MidService/finishMachineProvisioning` (produces 646-byte `adi.pb`).
- Generates live Anisette headers (`X-Apple-I-MD-M` 60B & `X-Apple-I-MD` 28B) via `ADIOTPRequest` (`0xcfe0b46a`).
- Synchronizes machine state via `ADISynchronize` (`0xa54951ec`) & `MidService/syncMachine` when requested.
- Generates live 6-digit Apple 2FA / TOTP verification codes every 30s via `ADIGenerateOTPCode` (`0x385b2ce8`).
"""

import os
import time
import uuid
import shutil
import struct
import base64
import hashlib
import plistlib
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

import requests
import urllib3
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_FS_BASE
)

urllib3.disable_warnings()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(BASE_DIR, "bin")
LOCAL_ADID_PATH = os.path.join(BIN_DIR, "adid_x86_64")
FALLBACK_ADID_PATH = r"C:\Users\min2e\Desktop\mac_files_for_windows\adid_x86_64"

CLIENT_INFO = "<MacBookPro15,1> <Mac OS X;10.15.7;19H15> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
USER_AGENT  = "akd/1.0 CFNetwork/1128.0.1 Darwin/19.6.0"

# Gate Command IDs in adid_x86_64 (0x100078040)
CMD_PROVISIONING_START = 0x716bd86c
CMD_PROVISIONING_END   = 0x0b2b3196
CMD_SYNCHRONIZE        = 0xa54951ec
CMD_OTP_REQUEST        = 0xcfe0b46a
CMD_GENERATE_OTP_CODE  = 0x385b2ce8
CMD_PROVISION_DESTROY  = 0x55a637c0
CMD_TEARDOWN           = 0x72096fe6


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    result, shift = 0, 0
    while True:
        b = data[offset]
        offset += 1
        result |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, offset


def _read_sleb128(data: bytes, offset: int) -> Tuple[int, int]:
    result, shift = 0, 0
    while True:
        b = data[offset]
        offset += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if (b & 0x80) == 0:
            if b & 0x40:
                result |= -(1 << shift)
            break
    return result, offset


def _parse_binds(data: bytes, segs: list, bind_off: int, bind_size: int) -> list:
    end = bind_off + bind_size
    p = bind_off
    seg_idx, seg_off, sym_name, addend = 0, 0, "", 0
    binds = []
    while p < end:
        byte = data[p]
        p += 1
        opcode = byte & 0xF0
        imm = byte & 0x0F
        if opcode == 0x20:
            _, p = _read_uleb128(data, p)
        elif opcode == 0x40:
            z = data.find(b'\x00', p)
            sym_name = data[p:z].decode('utf-8', errors='replace')
            p = z + 1
        elif opcode == 0x60:
            addend, p = _read_sleb128(data, p)
        elif opcode == 0x70:
            seg_idx = imm
            seg_off, p = _read_uleb128(data, p)
        elif opcode == 0x80:
            delta, p = _read_uleb128(data, p)
            seg_off = (seg_off + delta) & 0xFFFFFFFFFFFFFFFF
        elif opcode == 0x90:
            vmaddr = segs[seg_idx][1] + seg_off
            binds.append((vmaddr, sym_name, addend))
            seg_off = (seg_off + 8) & 0xFFFFFFFFFFFFFFFF
        elif opcode == 0xA0:
            vmaddr = segs[seg_idx][1] + seg_off
            binds.append((vmaddr, sym_name, addend))
            delta, p = _read_uleb128(data, p)
            seg_off = (seg_off + 8 + delta) & 0xFFFFFFFFFFFFFFFF
        elif opcode == 0xB0:
            vmaddr = segs[seg_idx][1] + seg_off
            binds.append((vmaddr, sym_name, addend))
            seg_off = (seg_off + 8 + imm * 8) & 0xFFFFFFFFFFFFFFFF
        elif opcode == 0xC0:
            count, p = _read_uleb128(data, p)
            skip, p = _read_uleb128(data, p)
            for _ in range(count):
                vmaddr = segs[seg_idx][1] + seg_off
                binds.append((vmaddr, sym_name, addend))
                seg_off = (seg_off + 8 + skip) & 0xFFFFFFFFFFFFFFFF
    return binds


class ADIDWindowsEngine:
    STACK_BASE = 0x7FFF00000000
    STACK_SIZE = 0x200000
    HEAP_BASE  = 0x200000000
    HEAP_SIZE  = 0x4000000
    TRAMP_BASE = 0x300000000
    TRAMP_SIZE = 0x10000
    TLS_BASE   = 0x400000000
    TLS_SIZE   = 0x10000

    def __init__(self, adid_path: Optional[str] = None):
        self.lock = threading.Lock()
        if not os.path.exists(LOCAL_ADID_PATH) and os.path.exists(FALLBACK_ADID_PATH):
            os.makedirs(BIN_DIR, exist_ok=True)
            shutil.copy2(FALLBACK_ADID_PATH, LOCAL_ADID_PATH)

        self.adid_path = adid_path or (LOCAL_ADID_PATH if os.path.exists(LOCAL_ADID_PATH) else FALLBACK_ADID_PATH)
        if not os.path.exists(self.adid_path):
            raise FileNotFoundError(f"adid_x86_64 binary not found at {self.adid_path}")

        with open(self.adid_path, "rb") as f:
            self.adid_data = f.read()

        self.vfs_files: Dict[str, bytes] = {}
        self.open_fds: Dict[int, list] = {}
        self.next_fd = 10
        self.host_uuid = bytes.fromhex("564dc29eaa4e5f197841728be1ba9a99")
        self.override_timestamp: Optional[float] = None
        self.current_state_key: Optional[Tuple[bytes, bytes]] = None
        self._url_bag_cache: Optional[Dict[str, str]] = None
        self._otp_code_cache: Dict[Tuple[str, str, int], str] = {}

        self._init_vm()

    def _heap_alloc(self, size: int) -> int:
        size = (size + 0xf) & ~0xf
        if self.heap_ptr + size >= self.HEAP_BASE + self.HEAP_SIZE:
            self.heap_ptr = self.runtime_heap_base
        p = self.heap_ptr
        self.heap_ptr += size
        return p

    @staticmethod
    def _read_cstr(uc: Uc, addr: int) -> str:
        if addr == 0:
            return ""
        out = bytearray()
        while True:
            b = uc.mem_read(addr, 1)[0]
            if b == 0:
                break
            out.append(b)
            addr += 1
        return out.decode('utf-8', errors='replace')

    @staticmethod
    def _write_stat64(uc: Uc, buf_addr: int, mode: int, uid: int, gid: int, size: int):
        st = bytearray(144)
        struct.pack_into("<IHHQII", st, 0, 1, mode, 1, 100, uid, gid)
        struct.pack_into("<q", st, 96, size)
        uc.mem_write(buf_addr, bytes(st))

    def _hook_tramp(self, uc: Uc, address: int, size: int, user_data: Any):
        sym = self.tramp_to_sym.get(address)
        if not sym:
            return
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)

        if sym == "_open":
            path = self._read_cstr(uc, rdi)
            if "adi-gb.lck" in path:
                uc.reg_write(UC_X86_REG_RAX, 5)
            elif path in self.vfs_files or (rsi & 0x0200):
                if path not in self.vfs_files or (rsi & 0x0400):
                    self.vfs_files[path] = b""
                fd = self.next_fd
                self.next_fd += 1
                self.open_fds[fd] = [path, rsi, 0]
                uc.reg_write(UC_X86_REG_RAX, fd)
            else:
                uc.mem_write(self.errno_addr, struct.pack("<i", 2))
                uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
        elif sym == "_lstat$INODE64":
            path = self._read_cstr(uc, rdi)
            if path in ("/var/db/fpsd/adi", "/var/db/fpsd", "/Users/Shared/adi"):
                self._write_stat64(uc, rsi, 0o040700, 265, 265, 160)
                uc.reg_write(UC_X86_REG_RAX, 0)
            elif path in self.vfs_files:
                self._write_stat64(uc, rsi, 0o100600, 265, 265, len(self.vfs_files[path]))
                uc.reg_write(UC_X86_REG_RAX, 0)
            else:
                uc.mem_write(self.errno_addr, struct.pack("<i", 2))
                uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFFF)
        elif sym == "_fstat$INODE64":
            if rdi in self.open_fds:
                path = self.open_fds[rdi][0]
                sz = len(self.vfs_files.get(path, b""))
                self._write_stat64(uc, rsi, 0o100600, 265, 265, sz)
            else:
                self._write_stat64(uc, rsi, 0o100600, 265, 265, 0)
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "_read":
            if rdi in self.open_fds:
                path, flags, off = self.open_fds[rdi]
                content = self.vfs_files.get(path, b"")
                chunk = content[off:off+rdx]
                if chunk:
                    uc.mem_write(rsi, chunk)
                self.open_fds[rdi][2] += len(chunk)
                uc.reg_write(UC_X86_REG_RAX, len(chunk))
            else:
                uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "_write":
            if rdi in self.open_fds:
                path, flags, off = self.open_fds[rdi]
                chunk = bytes(uc.mem_read(rsi, rdx))
                cur = bytearray(self.vfs_files.get(path, b""))
                if off + len(chunk) > len(cur):
                    cur.extend(b"\x00" * (off + len(chunk) - len(cur)))
                cur[off:off+len(chunk)] = chunk
                self.vfs_files[path] = bytes(cur)
                self.open_fds[rdi][2] += len(chunk)
                uc.reg_write(UC_X86_REG_RAX, len(chunk))
            else:
                uc.reg_write(UC_X86_REG_RAX, rdx)
        elif sym == "_close":
            self.open_fds.pop(rdi, None)
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "_unlink":
            path = self._read_cstr(uc, rdi)
            self.vfs_files.pop(path, None)
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "_getuid":
            uc.reg_write(UC_X86_REG_RAX, 265)
        elif sym == "_gethostuuid":
            uc.mem_write(rdi, self.host_uuid)
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "_gettimeofday":
            now = self.override_timestamp if self.override_timestamp is not None else time.time()
            sec = int(now)
            usec = int((now - sec) * 1000000)
            if rdi:
                uc.mem_write(rdi, struct.pack("<qq", sec, usec))
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "___error":
            uc.reg_write(UC_X86_REG_RAX, self.errno_addr)
        elif sym in ("_malloc", "_CFAllocatorAllocate"):
            sz = rdi if sym == "_malloc" else rsi
            p = self._heap_alloc(max(sz, 16))
            uc.reg_write(UC_X86_REG_RAX, p)
        elif sym == "_vm_allocate":
            p = self._heap_alloc(max(rdx, 4096))
            uc.mem_write(rsi, struct.pack("<Q", p))
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "_bootstrap_check_in":
            if rdx:
                uc.mem_write(rdx, struct.pack("<I", 0x101))
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif sym == "_arc4random":
            uc.reg_write(UC_X86_REG_RAX, int.from_bytes(os.urandom(4), "little"))
        elif sym in ("_kqueue", "_CFRunLoopGetMain", "_CFRunLoopGetCurrent",
                     "_CFMachPortCreateWithPort", "_CFMachPortCreateRunLoopSource",
                     "_CFFileDescriptorCreate", "_CFFileDescriptorCreateRunLoopSource",
                     "_CFURLCreateFromFileSystemRepresentation"):
            uc.reg_write(UC_X86_REG_RAX, 0x200)
        elif sym in ("_CFURLSetResourcePropertyForKey", "_CFURLCopyResourcePropertyForKey",
                     "_CSBackupSetItemExcluded", "_CFFileSecuritySetMode"):
            uc.reg_write(UC_X86_REG_RAX, 1)
        elif sym == "_CFRunLoopRun":
            uc.emu_stop()
        else:
            uc.reg_write(UC_X86_REG_RAX, 0)

    def _init_vm(self):
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack("<IIIIIIII", self.adid_data[:32])
        offset = 32
        segs = []
        bind_off = bind_size = lazy_off = lazy_size = 0
        entryoff = 0
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack("<II", self.adid_data[offset:offset+8])
            if cmd == 0x19:
                segname = self.adid_data[offset+8:offset+24].split(b'\x00')[0].decode()
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = struct.unpack("<QQQQIIII", self.adid_data[offset+24:offset+72])
                segs.append((segname, vmaddr, vmsize, fileoff, filesize))
            elif cmd in (0x22, 0x80000022):
                rebase_off, rebase_size, bind_off, bind_size, weak_off, weak_size, lazy_off, lazy_size, export_off, export_size = struct.unpack("<IIIIIIIIII", self.adid_data[offset+8:offset+48])
            elif cmd == 0x80000028:
                entryoff, _ = struct.unpack("<QQ", self.adid_data[offset+8:offset+24])
            offset += cmdsize

        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.data_segments = []
        for segname, vmaddr, vmsize, fileoff, filesize in segs:
            if segname == "__PAGEZERO":
                continue
            aligned_size = (vmsize + 0xfff) & ~0xfff
            self.mu.mem_map(vmaddr, aligned_size, UC_PROT_ALL)
            if filesize > 0:
                self.mu.mem_write(vmaddr, self.adid_data[fileoff:fileoff+filesize])
            if segname != "__TEXT":
                self.data_segments.append((vmaddr, aligned_size))

        self.mu.mem_map(self.STACK_BASE, self.STACK_SIZE, UC_PROT_ALL)
        self.mu.mem_map(self.HEAP_BASE, self.HEAP_SIZE, UC_PROT_ALL)
        self.mu.mem_map(self.TRAMP_BASE, self.TRAMP_SIZE, UC_PROT_ALL)
        self.mu.mem_map(self.TLS_BASE, self.TLS_SIZE, UC_PROT_ALL)
        self.mu.reg_write(UC_X86_REG_FS_BASE, self.TLS_BASE)

        self.heap_ptr = self.HEAP_BASE + 0x1000
        self.runtime_heap_base = self.HEAP_BASE + 0x200000

        binds = _parse_binds(self.adid_data, segs, bind_off, bind_size) + _parse_binds(self.adid_data, segs, lazy_off, lazy_size)
        self.sym_to_tramp = {}
        self.tramp_to_sym = {}
        for idx, sym in enumerate(sorted(set(b[1] for b in binds))):
            t_addr = self.TRAMP_BASE + idx * 16
            self.sym_to_tramp[sym] = t_addr
            self.tramp_to_sym[t_addr] = sym
            self.mu.mem_write(t_addr, b'\xc3')

        for vmaddr, sym, addend in binds:
            target = (self.sym_to_tramp[sym] + addend) & 0xFFFFFFFFFFFFFFFF
            self.mu.mem_write(vmaddr, struct.pack("<Q", target))

        self.errno_addr = self._heap_alloc(8)
        self.mu.hook_add(UC_HOOK_CODE, self._hook_tramp, begin=self.TRAMP_BASE, end=self.TRAMP_BASE + self.TRAMP_SIZE)

        argv0_str = b"/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/adid\x00"
        argv0_addr = self._heap_alloc(len(argv0_str))
        self.mu.mem_write(argv0_addr, argv0_str)
        argv_arr = self._heap_alloc(16)
        self.mu.mem_write(argv_arr, struct.pack("<QQ", argv0_addr, 0))

        rsp = self.STACK_BASE + self.STACK_SIZE - 0x1000
        self.ret_addr = self.TRAMP_BASE + 0xF000
        self.mu.mem_write(self.ret_addr, b'\xf4')
        self.mu.mem_write(rsp, struct.pack("<Q", self.ret_addr))

        self.mu.reg_write(UC_X86_REG_RSP, rsp)
        self.mu.reg_write(UC_X86_REG_RDI, 1)
        self.mu.reg_write(UC_X86_REG_RSI, argv_arr)

        entry = 0x100000000 + entryoff
        self.mu.emu_start(entry, self.ret_addr, count=2000000)

        self.out_buf_ptr = self._heap_alloc(8)
        self.out_len_ptr = self._heap_alloc(8)
        self.out_flag_ptr = self._heap_alloc(8)
        self.runtime_heap_base = (self.heap_ptr + 0x10000) & ~0xfff
        self.heap_ptr = self.runtime_heap_base

        # Snapshot clean post-init __DATA and initial heap so switching accounts is instantaneous and 100% isolated
        self.clean_data_snapshots = [
            (vmaddr, bytes(self.mu.mem_read(vmaddr, sz)))
            for vmaddr, sz in self.data_segments
        ]
        self.clean_init_heap = bytes(self.mu.mem_read(self.HEAP_BASE, self.runtime_heap_base - self.HEAP_BASE))

    def _call_gate_unlocked(self, pkt: bytes) -> bytes:
        req_addr = self._heap_alloc(len(pkt) + 64)
        self.mu.mem_write(req_addr, pkt)
        rsp = self.STACK_BASE + self.STACK_SIZE - 0x2000
        self.mu.mem_write(rsp, struct.pack("<QQQQQ", self.ret_addr, 0, 0, 0, 0))
        self.mu.mem_write(self.out_buf_ptr, b"\x00" * 8)
        self.mu.mem_write(self.out_len_ptr, b"\x00" * 8)
        self.mu.reg_write(UC_X86_REG_RSP, rsp)
        self.mu.reg_write(UC_X86_REG_RDI, 0)
        self.mu.reg_write(UC_X86_REG_RSI, req_addr)
        self.mu.reg_write(UC_X86_REG_RDX, len(pkt))
        self.mu.reg_write(UC_X86_REG_RCX, self.out_buf_ptr)
        self.mu.reg_write(UC_X86_REG_R8,  self.out_len_ptr)
        self.mu.reg_write(UC_X86_REG_R9,  self.out_flag_ptr)
        self.mu.emu_start(0x100078040, self.ret_addr, count=30000000)
        out_buf = struct.unpack("<Q", self.mu.mem_read(self.out_buf_ptr, 8))[0]
        out_len = struct.unpack("<I", self.mu.mem_read(self.out_len_ptr, 4))[0]
        return bytes(self.mu.mem_read(out_buf, out_len)) if (out_buf and out_len > 0) else b""

    def _load_state_unlocked(self, pb_bytes: bytes, host_uuid_hex: str):
        clean_uuid = bytes.fromhex(host_uuid_hex.replace("-", "").strip()[:32].ljust(32, "0"))
        state_key = (pb_bytes, clean_uuid)
        if self.current_state_key != state_key:
            for vmaddr, snap in self.clean_data_snapshots:
                self.mu.mem_write(vmaddr, snap)
            self.mu.mem_write(self.HEAP_BASE, self.clean_init_heap)
            self.heap_ptr = self.runtime_heap_base
            self.open_fds.clear()
            self.vfs_files.clear()
            if pb_bytes:
                self.vfs_files["/var/db/fpsd/adi/adi.pb"] = pb_bytes
            self.host_uuid = clean_uuid
            self.current_state_key = state_key

    def _get_url_bag(self, headers: Dict[str, str]) -> Dict[str, str]:
        if self._url_bag_cache:
            return self._url_bag_cache
        r = requests.get(
            "https://gsa.apple.com/grandslam/GsService2/lookup",
            headers=headers,
            verify=False,
            timeout=15,
        )
        bag = plistlib.loads(r.content)
        self._url_bag_cache = bag.get("urls", {})
        return self._url_bag_cache

    @staticmethod
    def _build_base_headers(udid: str, local_uuid: str, serial_number: str, rinfo: str = "17106176") -> Dict[str, str]:
        now_iso = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "User-Agent": USER_AGENT,
            "X-MMe-Client-Info": CLIENT_INFO,
            "X-Apple-I-Client-Time": now_iso,
            "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": "en_US",
            "X-Apple-I-MD-RINFO": str(rinfo or "17106176"),
            "X-Apple-I-MD-LU": local_uuid,
            "X-Mme-Device-Id": udid,
            "X-Apple-I-SRL-NO": serial_number,
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
        }

    def provision_new_virtual_mac(self) -> Dict[str, Any]:
        """
        Provisions a brand-new virtual Mac directly with Apple's MidService
        and returns the 646-byte `adi.pb` (base64), `host_uuid`, `udid`, `mid`, `otp`, and initial 6-digit `code`.
        """
        host_uuid_hex = uuid.uuid4().hex
        udid = str(uuid.uuid4()).upper()
        local_uuid = hashlib.sha256(udid.encode("utf-8")).hexdigest().upper()
        serial_number = "C02" + uuid.uuid4().hex[:9].upper()

        base_headers = self._build_base_headers(udid, local_uuid, serial_number)
        urls = self._get_url_bag(base_headers)
        start_url = urls.get("midStartProvisioning", "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning")
        finish_url = urls.get("midFinishProvisioning", "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning")

        # 1. Fetch spim from Apple
        r_start = requests.post(
            start_url,
            data=plistlib.dumps({"Header": {}, "Request": {}}),
            headers=base_headers,
            verify=False,
            timeout=15,
        )
        resp_start = plistlib.loads(r_start.content)
        spim_b64 = resp_start.get("Response", {}).get("spim")
        if not spim_b64:
            raise RuntimeError(f"midStartProvisioning did not return spim: {resp_start}")
        spim_bytes = base64.b64decode(spim_b64)

        with self.lock:
            self._load_state_unlocked(b"", host_uuid_hex)

            # 2. Call ADIProvisioningStart(-2, spim)
            out1 = self._call_gate_unlocked(struct.pack(">IIIqI", 1, CMD_PROVISIONING_START, 1, -2, len(spim_bytes)) + spim_bytes)
            if len(out1) < 12:
                raise RuntimeError(f"ADIProvisioningStart short output ({len(out1)}B)")
            status1, w1, w2 = struct.unpack(">iII", out1[:12])
            if status1 != 0:
                raise RuntimeError(f"ADIProvisioningStart failed with status={status1}")

            if w1 == len(out1) - 12:
                cpim_len = w1
                cpim_bytes = out1[8:8+cpim_len]
                session_id = struct.unpack(">I", out1[8+cpim_len:12+cpim_len])[0]
            else:
                session_id = w1
                cpim_len = w2
                cpim_bytes = out1[12:12+cpim_len]

            # 3. Send cpim to Apple midFinishProvisioning
            cpim_b64 = base64.b64encode(cpim_bytes).decode("ascii")
            r_fin = requests.post(
                finish_url,
                data=plistlib.dumps({"Header": {}, "Request": {"cpim": cpim_b64}}),
                headers=base_headers,
                verify=False,
                timeout=15,
            )
            resp_fin = plistlib.loads(r_fin.content)
            fin_inner = resp_fin.get("Response", {})
            if "ptm" not in fin_inner or "tk" not in fin_inner:
                self._call_gate_unlocked(struct.pack(">IIII", 1, CMD_PROVISION_DESTROY, 1, session_id))
                raise RuntimeError(f"midFinishProvisioning failed: {resp_fin}")

            ptm_bytes = base64.b64decode(fin_inner["ptm"])
            tk_bytes = base64.b64decode(fin_inner["tk"])
            rinfo_str = str(fin_inner.get("X-Apple-I-MD-RINFO", "17106176"))

            # 4. Call ADIProvisioningEnd(session_id, ptm, tk)
            pkt_end = (
                struct.pack(">IIIII", 1, CMD_PROVISIONING_END, 1, session_id, len(ptm_bytes))
                + ptm_bytes
                + struct.pack(">I", len(tk_bytes))
                + tk_bytes
            )
            out2 = self._call_gate_unlocked(pkt_end)
            status2 = struct.unpack(">i", out2[:4])[0]
            if status2 != 0:
                raise RuntimeError(f"ADIProvisioningEnd failed with status={status2}")

            pb_bytes = self.vfs_files.get("/var/db/fpsd/adi/adi.pb", b"")
            self.current_state_key = (pb_bytes, self.host_uuid)

            # 5. Request live X-Apple-I-MD-M (60B) and X-Apple-I-MD (28B)
            out3 = self._call_gate_unlocked(struct.pack(">IIIq", 1, CMD_OTP_REQUEST, 1, -2))
            status3 = struct.unpack(">i", out3[:4])[0]
            mid_b64, otp_b64 = "", ""
            if status3 == 0 and len(out3) >= 12:
                s1_len = struct.unpack(">I", out3[4:8])[0]
                s1_bytes = out3[8:8+s1_len]
                s2_len = struct.unpack(">I", out3[8+s1_len:12+s1_len])[0]
                s2_bytes = out3[12+s1_len:12+s1_len+s2_len]
                # 60 bytes is Machine ID (X-Apple-I-MD-M), 28 bytes is OTP (X-Apple-I-MD)
                if len(s1_bytes) == 60:
                    mid_b64 = base64.b64encode(s1_bytes).decode("ascii")
                    otp_b64 = base64.b64encode(s2_bytes).decode("ascii")
                else:
                    otp_b64 = base64.b64encode(s1_bytes).decode("ascii")
                    mid_b64 = base64.b64encode(s2_bytes).decode("ascii")

            # 6. Generate initial 6-digit code
            out4 = self._call_gate_unlocked(struct.pack(">IIIq", 1, CMD_GENERATE_OTP_CODE, 1, -2))
            status4 = struct.unpack(">i", out4[:4])[0]
            code_int = struct.unpack(">I", out4[4:8])[0] if len(out4) >= 8 else 0

        return {
            "pb_b64": base64.b64encode(pb_bytes).decode("ascii"),
            "pb_len": len(pb_bytes),
            "host_uuid": host_uuid_hex,
            "udid": udid,
            "local_user_uuid": local_uuid,
            "serial_number": serial_number,
            "routing_data": rinfo_str,
            "client_info": CLIENT_INFO,
            "user_agent": USER_AGENT,
            "X-Apple-I-MD-M": mid_b64,
            "X-Apple-I-MD": otp_b64,
            "initial_code": f"{code_int:06d}",
            "code_status": status4,
        }

    def get_anisette_headers(
        self,
        pb_b64: str,
        host_uuid_hex: str,
        udid: str,
        local_uuid: str,
        serial_number: str,
        rinfo: str = "17106176",
    ) -> Dict[str, str]:
        pb_bytes = base64.b64decode(pb_b64)
        with self.lock:
            self._load_state_unlocked(pb_bytes, host_uuid_hex)
            out = self._call_gate_unlocked(struct.pack(">IIIq", 1, CMD_OTP_REQUEST, 1, -2))
            status = struct.unpack(">i", out[:4])[0]
            if status != 0 or len(out) < 12:
                raise RuntimeError(f"ADIOTPRequest failed with status={status}")
            s1_len = struct.unpack(">I", out[4:8])[0]
            s1_bytes = out[8:8+s1_len]
            s2_len = struct.unpack(">I", out[8+s1_len:12+s1_len])[0]
            s2_bytes = out[12+s1_len:12+s1_len+s2_len]
            if len(s1_bytes) == 60:
                mid_b64 = base64.b64encode(s1_bytes).decode("ascii")
                otp_b64 = base64.b64encode(s2_bytes).decode("ascii")
            else:
                otp_b64 = base64.b64encode(s1_bytes).decode("ascii")
                mid_b64 = base64.b64encode(s2_bytes).decode("ascii")

        headers = self._build_base_headers(udid, local_uuid, serial_number, rinfo)
        headers["X-Apple-I-MD-M"] = mid_b64
        headers["X-Apple-I-MD"] = otp_b64
        return headers

    def synchronize_machine(
        self,
        pb_b64: str,
        host_uuid_hex: str,
        sim_bytes: bytes,
        udid: str,
        local_uuid: str,
        serial_number: str,
        rinfo: str = "17106176",
    ) -> str:
        """
        Calls ADISynchronize(-2, sim_bytes) (`0xa54951ec`), posts SRM + MID to
        `MidService/syncMachine`, and returns the updated `pb_b64`.
        """
        pb_bytes = base64.b64decode(pb_b64)
        with self.lock:
            self._load_state_unlocked(pb_bytes, host_uuid_hex)
            pkt = struct.pack(">IIIqI", 1, CMD_SYNCHRONIZE, 1, -2, len(sim_bytes)) + sim_bytes
            out = self._call_gate_unlocked(pkt)
            status = struct.unpack(">i", out[:4])[0]
            if status != 0 or len(out) < 12:
                raise RuntimeError(f"ADISynchronize failed with status={status}")
            p1_len = struct.unpack(">I", out[4:8])[0]
            p1_bytes = out[8:8+p1_len]
            p2_len = struct.unpack(">I", out[8+p1_len:12+p1_len])[0]
            p2_bytes = out[12+p1_len:12+p1_len+p2_len]
            if len(p1_bytes) == 60:
                mid_b64 = base64.b64encode(p1_bytes).decode("ascii")
                srm_b64 = base64.b64encode(p2_bytes).decode("ascii")
            else:
                srm_b64 = base64.b64encode(p1_bytes).decode("ascii")
                mid_b64 = base64.b64encode(p2_bytes).decode("ascii")
            new_pb = self.vfs_files.get("/var/db/fpsd/adi/adi.pb", pb_bytes)
            self.current_state_key = (new_pb, self.host_uuid)

        base_headers = self._build_base_headers(udid, local_uuid, serial_number, rinfo)
        urls = self._get_url_bag(base_headers)
        sync_url = urls.get("midSyncMachine", "https://gsa.apple.com/grandslam/MidService/syncMachine")
        sync_body = {
            "Header": {},
            "Request": {
                "srm": srm_b64,
                "X-Apple-I-MD-M": mid_b64,
                "X-Apple-I-MD-RINF": int(rinfo or 17106176),
            },
        }
        requests.post(sync_url, data=plistlib.dumps(sync_body), headers=base_headers, verify=False, timeout=15)
        return base64.b64encode(new_pb).decode("ascii")

    def generate_otp_code(
        self,
        pb_b64: str,
        host_uuid_hex: str,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Generates the live 6-digit Apple verification code from the account's `adi.pb` and `host_uuid`.
        """
        now = timestamp if timestamp is not None else time.time()
        counter = int(now) // 30
        remaining = 30 - (int(now) % 30)
        cache_key = (pb_b64[-48:], host_uuid_hex, counter)
        cached_code = self._otp_code_cache.get(cache_key)
        if cached_code:
            return {
                "code": cached_code,
                "remaining_seconds": remaining,
                "period": 30,
                "status": 0,
                "algorithm": "APPLE_COREADI_PB",
            }

        pb_bytes = base64.b64decode(pb_b64)
        with self.lock:
            self.override_timestamp = timestamp
            try:
                self._load_state_unlocked(pb_bytes, host_uuid_hex)
                out = self._call_gate_unlocked(struct.pack(">IIIq", 1, CMD_GENERATE_OTP_CODE, 1, -2))
                status = struct.unpack(">i", out[:4])[0]
                code_int = struct.unpack(">I", out[4:8])[0] if len(out) >= 8 else 0
            finally:
                self.override_timestamp = None

        if status != 0:
            raise RuntimeError(f"ADIGenerateOTPCode failed with status={status}")

        code_str = f"{code_int:06d}"
        if len(self._otp_code_cache) > 500:
            self._otp_code_cache.clear()
        self._otp_code_cache[cache_key] = code_str

        return {
            "code": code_str,
            "remaining_seconds": remaining,
            "period": 30,
            "status": status,
            "algorithm": "APPLE_COREADI_PB",
        }


_ENGINE_SINGLETON: Optional[ADIDWindowsEngine] = None
_ENGINE_INIT_LOCK = threading.Lock()


def get_adi_engine() -> ADIDWindowsEngine:
    global _ENGINE_SINGLETON
    if _ENGINE_SINGLETON is None:
        with _ENGINE_INIT_LOCK:
            if _ENGINE_SINGLETON is None:
                _ENGINE_SINGLETON = ADIDWindowsEngine()
    return _ENGINE_SINGLETON


if __name__ == "__main__":
    print("[*] Initializing ADIDWindowsEngine on Windows...")
    eng = get_adi_engine()
    print("[*] Provisioning brand-new virtual Mac against Apple GSA...")
    dev = eng.provision_new_virtual_mac()
    print(f"[+] Provisioned! pb_len={dev['pb_len']}B | host_uuid={dev['host_uuid']}")
    print(f"    X-Mme-Device-Id : {dev['udid']}")
    print(f"    X-Apple-I-MD-M  : {dev['X-Apple-I-MD-M']}")
    print(f"    X-Apple-I-MD    : {dev['X-Apple-I-MD']}")
    print(f"    Initial 6-Digit : {dev['initial_code']}")

    # Verify reloading from pb_b64 + host_uuid and generating code
    res = eng.generate_otp_code(dev["pb_b64"], dev["host_uuid"])
    print(f"[+] Reloaded from pb_b64 -> Live Code: {res['code']} (rotates in {res['remaining_seconds']}s)")
