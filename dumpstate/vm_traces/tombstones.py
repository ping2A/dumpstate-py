import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER

@dataclass
class BacktraceFrame:
    """Represents a single line/frame in a native backtrace."""
    frame: int
    pc: str
    library: str
    function: str | None = None
    offset: str | None = None
    build_id: str | None = None
    raw_line: str = ""

    def __str__(self):
        """Provides a clean string representation of the frame."""
        if self.frame == -1: # For raw lines that couldn't be parsed
            return self.raw_line
            
        func_off = ""
        if self.function:
            func_off = f" ({self.function}"
            if self.offset:
                func_off += f"+{self.offset}"
            func_off += ")"
        build_id_str = f" (BuildId: {self.build_id})" if self.build_id else ""
        
        return f"#{self.frame:02d} pc {self.pc} {self.library}{func_off}{build_id_str}"

@dataclass
class Tombstone:
    """Represents a single Tombstone (native crash) entry."""

    timestamp: str = ""
    pid: int = 0
    tid: int = 0
    uid: int = 0
    process_name: str = ""
    thread_name: str = ""
    cmdline: str = ""
    build_fingerprint: str = ""
    abi: str = ""
    signal: str = ""
    code: str = ""
    fault_addr: str = ""
    abort_message: str = ""
    backtrace: list[BacktraceFrame] = field(default_factory=list)

    def __str__(self):
        """Returns a summary, including the top backtrace frame if available."""
        top_frame = ""
        if self.backtrace:
            # Find the first valid parsed frame (not a raw/unparsed line)
            for frame in self.backtrace:
                if frame.frame != -1:
                    top_frame = f", top_frame='{str(frame)}'"
                    break

        return (
            f"Tombstone(timestamp='{self.timestamp}', process='{self.process_name}' ({self.pid}), "
            f"signal='{self.signal}', fault_addr='{self.fault_addr}'{top_frame})"
        )


def parse_tombstones(dumpstate_content: RawData) -> list[Tombstone] | None:
    """Parses tombstone sections from the bug report."""
    LOGGER.info("Parsing \"Tombstones\" section...")

    tombstones: list[Tombstone] = []
    current_tombstone: Tombstone | None = None
    in_backtrace = False
    parsing_logcat_tombstone = False

    # Regex for the start of a standard tombstone (now searches, not matches from start)
    tombstone_start_pattern = re.compile(rb'\*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\* \*\*\*')
    
    # Pattern to find and strip a logcat prefix.
    # Group 1 captures the content *after* the prefix.
    logcat_prefix_pattern = re.compile(rb'^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\d+\s+\d+\s+F\s+DEBUG\s*:\s?(.*)$')

    # Regex for pid/tid/name line: pid: 10809, tid: 10886, name: thumbThread1  >>> com.package <<<
    pid_tid_pattern = re.compile(rb'pid: (\d+), tid: (\d+), name: (.+?)  >>> (.+?) <<<')
    # Regex for signal line: signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x000000cafe
    signal_pattern = re.compile(rb'signal \d+ \((.+?)\), code \d+ \((.+?)\), fault addr (0x[0-9a-fA-F]+)')

    # Regex for a backtrace line
    # Example: #00 pc 00000000001de20c  /system/lib64/XX.so (XX::YY(ZZ&, ZZ*, ZZZ*)+552) (BuildId: 11111111)
    backtrace_pattern = re.compile(
        rb'#(\d+)\s+pc\s+([0-9a-fA-F]+)\s+([^\s]+)(?:\s+\((.*?)\))?(?:\s+\(BuildId:\s+(.*?)\))?'
    )

    for line in dumpstate_content.lines:
        line_stripped = line.strip()

        logcat_match = logcat_prefix_pattern.match(line_stripped)
        if logcat_match:
            line_content = logcat_match.group(1).strip()
            is_logcat_line = True
        else:
            line_content = line_stripped
            is_logcat_line = False
        
        # Check for start of a new tombstone
        if tombstone_start_pattern.search(line_content):
            if current_tombstone:
                tombstones.append(current_tombstone)
            current_tombstone = Tombstone()
            in_backtrace = False
            parsing_logcat_tombstone = is_logcat_line
            continue

        # Check if we are inside a tombstone
        if current_tombstone is None:
            continue # Not parsing, skip line

        # If we were parsing a logcat tombstone and this line *isn't* one, stop.
        if parsing_logcat_tombstone and not is_logcat_line:
            tombstones.append(current_tombstone)
            current_tombstone = None
            in_backtrace = False
            parsing_logcat_tombstone = False
            continue # This line is not part of the tombstone
        
        line_content_str = line_content.decode('utf-8', errors='replace')

        if line_content.startswith(b'Timestamp:'):
            current_tombstone.timestamp = line_content.split(b'Timestamp:', 1)[1].strip().decode('utf-8', errors='replace')
        elif line_content.startswith(b'Build fingerprint:'):
            current_tombstone.build_fingerprint = line_content.split(b':', 1)[1].strip().decode('utf-8', errors='replace')
        elif line_content.startswith(b'ABI:'):
            current_tombstone.abi = line_content.split(b':', 1)[1].strip().decode('utf-8', errors='replace')
        elif line_content.startswith(b'Cmdline:'):
            current_tombstone.cmdline = line_content.split(b':', 1)[1].strip().decode('utf-8', errors='replace')
        elif line_content.startswith(b'uid:'):
             current_tombstone.uid = int(line_content.split(b':')[1].strip())
        elif line_content.startswith(b'Abort message:'):
             current_tombstone.abort_message = line_content.split(b':', 1)[1].strip().decode('utf-8', errors='replace')
        elif line_content.startswith(b'backtrace:'):
            in_backtrace = True
            continue

        # Handle multi-line or complex patterns
        if not in_backtrace:
            pid_match = pid_tid_pattern.match(line_content)
            if pid_match:
                current_tombstone.pid = int(pid_match.group(1))
                current_tombstone.tid = int(pid_match.group(2))
                current_tombstone.thread_name = pid_match.group(3).strip().decode('utf-8', errors='replace')
                current_tombstone.process_name = pid_match.group(4).strip().decode('utf-8', errors='replace')
                continue

            signal_match = signal_pattern.match(line_content)
            if signal_match:
                current_tombstone.signal = signal_match.group(1).decode('utf-8', errors='replace')
                current_tombstone.code = signal_match.group(2).decode('utf-8', errors='replace')
                current_tombstone.fault_addr = signal_match.group(3).decode('utf-8', errors='replace')
                continue

        if in_backtrace:
            # Try to parse the backtrace line
            match = backtrace_pattern.search(line_content)
            
            if match:
                frame = int(match.group(1))
                pc = match.group(2).decode('utf-8', errors='replace')
                library = match.group(3).decode('utf-8', errors='replace')
                function_raw = match.group(4).decode('utf-8', errors='replace') if match.group(4) else None
                build_id = match.group(5).decode('utf-8', errors='replace') if match.group(5) else None
                
                function = None
                offset = None

                if function_raw:
                    # Split function and offset (e.g., "function_name+123")
                    parts = function_raw.rsplit('+', 1)
                    function = parts[0]
                    if len(parts) == 2:
                        offset = parts[1]

                frame_obj = BacktraceFrame(
                    frame=frame,
                    pc=pc,
                    library=library,
                    function=function,
                    offset=offset,
                    build_id=build_id,
                    raw_line=line_content_str
                )
                current_tombstone.backtrace.append(frame_obj)

            elif line_content.startswith(b'stack:'):
                 # Reached stack section, stop backtrace
                 in_backtrace = False
            
            elif line_content_str.strip(): # Avoid adding empty lines
                current_tombstone.backtrace.append(
                    BacktraceFrame(frame=-1, pc="", library="", raw_line=line_content_str)
                )

    if current_tombstone:
        tombstones.append(current_tombstone)

    return tombstones if tombstones else None