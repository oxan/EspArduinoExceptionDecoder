#!/usr/bin/env python3

"""ESP Exception Decoder

github:  https://github.com/janLo/EspArduinoExceptionDecoder
license: GPL v3
author:  Jan Losinski
"""

import argparse
import re
import subprocess
from collections import namedtuple

import sys

import os

EXCEPTIONS = {
    0:  "Illegal instruction",
    1:  "SYSCALL instruction",
    2:  "InstructionFetchError: Processor internal physical address or data error during instruction fetch",
    3:  "LoadStoreError: Processor internal physical address or data error during load or store",
    4:  "Level1Interrupt: Level-1 interrupt as indicated by set level-1 bits in the INTERRUPT register",
    5:  "Alloca: MOVSP instruction, if caller's registers are not in the register file",
    6:  "IntegerDivideByZero: QUOS, QUOU, REMS, or REMU divisor operand is zero",
    8:  "Privileged: Attempt to execute a privileged operation when CRING ? 0",
    9:  "LoadStoreAlignmentCause: Load or store to an unaligned address",
    12: "InstrPIFDataError: PIF data error during instruction fetch",
    13: "LoadStorePIFDataError: Synchronous PIF data error during LoadStore access",
    14: "InstrPIFAddrError: PIF address error during instruction fetch",
    15: "LoadStorePIFAddrError: Synchronous PIF address error during LoadStore access",
    16: "InstTLBMiss: Error during Instruction TLB refill",
    17: "InstTLBMultiHit: Multiple instruction TLB entries matched",
    18: "InstFetchPrivilege: An instruction fetch referenced a virtual address at a ring level less than CRING",
    20: "InstFetchProhibited: An instruction fetch referenced a page mapped with an attribute that does not permit instruction fetch",
    24: "LoadStoreTLBMiss: Error during TLB refill for a load or store",
    25: "LoadStoreTLBMultiHit: Multiple TLB entries matched for a load or store",
    26: "LoadStorePrivilege: A load or store referenced a virtual address at a ring level less than CRING",
    28: "LoadProhibited: A load referenced a page mapped with an attribute that does not permit loads",
    29: "StoreProhibited: A store referenced a page mapped with an attribute that does not permit stores",
    32: "Coprocessor 0 instruction when cp0 disabled.",
    33: "Coprocessor 1 instruction when cp1 disabled.",
    34: "Coprocessor 2 instruction when cp2 disabled.",
    35: "Coprocessor 3 instruction when cp3 disabled.",
    36: "Coprocessor 4 instruction when cp4 disabled.",
    37: "Coprocessor 5 instruction when cp5 disabled.",
    38: "Coprocessor 6 instruction when cp6 disabled.",
    39: "Coprocessor 7 instruction when cp7 disabled.",
}

PLATFORMS = {
    "ESP8266": "lx106",
    "ESP32": "esp32"
}

EXCEPTION_REGEX = re.compile(r"^Exception \((?P<exc>[0-9]*)\):$")
COUNTER_REGEX   = re.compile(r"^epc1=(?P<epc1>0x[0-9a-f]+) epc2=(?P<epc2>0x[0-9a-f]+) epc3=(?P<epc3>0x[0-9a-f]+)"
                              " excvaddr=(?P<excvaddr>0x[0-9a-f]+) depc=(?P<depc>0x[0-9a-f]+)$")
CTX_REGEX       = re.compile(r"^ctx: (?P<ctx>.+)$")
POINTER_REGEX   = re.compile(r"^sp: (?P<sp>[0-9a-f]+) end: (?P<end>[0-9a-f]+) offset: (?P<offset>[0-9a-f]+)$")
STACK_BEGIN     = ">>>stack>>>"
STACK_END       = "<<<stack<<<"
STACK_REGEX     = re.compile(r"^(?P<off>[0-9a-f]+):\W+(?P<c1>[0-9a-f]+) (?P<c2>[0-9a-f]+) (?P<c3>[0-9a-f]+) (?P<c4>[0-9a-f]+)(\W.*)?$")

StackLine = namedtuple("StackLine", ["offset", "content"])


class ExceptionDataParser(object):
    def __init__(self):
        self.exception = None

        self.epc1 = None
        self.epc2 = None
        self.epc3 = None
        self.excvaddr = None
        self.depc = None

        self.ctx = None

        self.sp = None
        self.end = None
        self.offset = None

        self.stack = []

    def _parse_exception(self, line):
        match = EXCEPTION_REGEX.match(line)
        if match is not None:
            self.exception = int(match.group('exc'))
        return match is not None

    def _parse_counters(self, line):
        match = COUNTER_REGEX.match(line)
        if match is not None:
            self.epc1 = match.group("epc1")
            self.epc2 = match.group("epc2")
            self.epc3 = match.group("epc3")
            self.excvaddr = match.group("excvaddr")
            self.depc = match.group("depc")
        return match is not None

    def _parse_ctx(self, line):
        match = CTX_REGEX.match(line)
        if match is not None:
            self.ctx = match.group("ctx")
        return match is not None

    def _parse_pointers(self, line):
        match = POINTER_REGEX.match(line)
        if match is not None:
            self.sp = match.group("sp")
            self.end = match.group("end")
            self.offset = match.group("offset")
        return match is not None

    def _parse_stack_begin(self, line):
        return line == STACK_BEGIN

    def _parse_stack_line(self, line):
        match = STACK_REGEX.match(line)
        if match is not None:
            self.stack.append(StackLine(offset=match.group("off"),
                                        content=(match.group("c1"), match.group("c2"), match.group("c3"), match.group("c4"))))
        return match is not None

    def _parse_stack_end(self, line):
        return line == STACK_END

    def parse_file(self, file):
        state = 'default'

        for line in file:
            line = line.strip()
            if state == 'default' and self._parse_exception(line):
                state = 'exception'
            elif state == 'exception' and self._parse_counters(line):
                continue
            elif state in ('exception', 'stack') and (self._parse_ctx(line) or self._parse_pointers(line)):
                # these two used to be before the stack marker, but are after it since Arduino commit 2f4380777
                continue
            elif self._parse_stack_begin(line):
                state = 'stack'
            elif state == 'stack' and self._parse_stack_line(line):
                continue
            elif state == 'stack' and self._parse_stack_end(line):
                    return True

        return state != 'default'


class AddressResolver(object):
    def __init__(self, tool_path, elf_path):
        self._tool = tool_path
        self._elf = elf_path
        self._address_map = {}

    def _lookup(self, addresses):
        cmd = [self._tool, "-aipfC", "-e", self._elf] + [addr for addr in addresses if addr is not None]
        output = subprocess.check_output(cmd, encoding="utf-8")

        line_regex = re.compile("^(?P<addr>[0-9a-fx]+): (?P<result>.+)$")

        last = None
        for line in output.splitlines():
            line = line.strip()
            match = line_regex.match(line)

            if match is None:
                if last is not None and line.startswith("(inlined by)"):
                    line = line[12:].strip()
                    self._address_map[last] += f"\n  \-> inlined by: {line}"
                continue

            if match.group("result") == "?? ??:0":
                continue

            self._address_map[match.group("addr")] = match.group("result")
            last = match.group("addr")

    def fill(self, parser):
        addresses = [parser.epc1, parser.epc2, parser.epc3, parser.excvaddr, parser.sp, parser.end, parser.offset]
        for line in parser.stack:
            addresses.extend(line.content)

        self._lookup(addresses)

    def _sanitize_addr(self, addr):
        if addr.startswith("0x"):
            addr = addr[2:]

        return f"0x{addr:0>8}"

    def is_instruction_addr(self, addr):
        # instructions are generally mapped at 0x40XXXXXXh, see
        # https://github.com/esp8266/esp8266-wiki/wiki/Memory-Map
        return self._sanitize_addr(addr).startswith("0x40")

    def resolve_addr(self, addr):
        addr = self._sanitize_addr(addr)
        if addr in self._address_map:
            return f"{addr}: {self._address_map[addr]}"
        return addr


def print_addr(name, value, resolver):
    valfmt = resolver.resolve_addr(value) if value else '?'
    print(f"{name + ':':9} {valfmt}")


def print_stack_full(lines, resolver):
    print("stack:")
    for line in lines:
        print(f"{line.offset}:")
        for addr in line.content:
            print(f"  {resolver.resolve_addr(addr)}")


def print_stack(lines, resolver):
    print("stack:")
    for line in lines:
        for addr in line.content:
            if resolver.is_instruction_addr(addr):
                print(resolver.resolve_addr(addr))


def print_result(parser, resolver, full=True):
    if parser.exception is not None:
        exception_cause = EXCEPTIONS[parser.exception] if parser.exception in EXCEPTIONS else "unknown"
        print(f"Exception: {parser.exception} ({exception_cause})")
        print("")

        print_addr("epc1",     parser.epc1,     resolver)
        print_addr("epc2",     parser.epc2,     resolver)
        print_addr("epc3",     parser.epc3,     resolver)
        print_addr("excvaddr", parser.excvaddr, resolver)
        print_addr("depc",     parser.depc,     resolver)
        print("")

    if parser.ctx is not None:
        print(f"{'ctx:':9} {parser.ctx}")
        print("")

    if any((parser.sp, parser.end, parser.offset)):
        print_addr("sp", parser.sp, resolver)
        print_addr("end", parser.end, resolver)
        print_addr("offset", parser.offset, resolver)
        print("")

    if full:
        print_stack_full(parser.stack, resolver)
    else:
        print_stack(parser.stack, resolver)

    print("")


def main(toolchain_path, platform, elf_path, exception_input=None):
    if os.path.exists(toolchain_path) and os.path.isfile(toolchain_path):
        addr2line = toolchain_path
    else:
        addr2line = os.path.join(toolchain_path, "bin/xtensa-" + PLATFORMS[platform] + "-elf-addr2line")
        if not os.path.exists(addr2line):
            raise FileNotFoundError(f"addr2line not found at '{addr2line}'")

    if not os.path.exists(elf_path):
        raise FileNotFoundError(f"ELF file not found at '{elf_path}'")

    if exception_input:
        if not os.path.exists(exception_input):
            raise FileNotFoundError(f"Exception file not found at '{exception_input}'")
        input_handle = open(exception_input, "r")
    else:
        input_handle = sys.stdin

    resolver = AddressResolver(addr2line, elf_path)
    while True:
        parser = ExceptionDataParser()
        if not parser.parse_file(input_handle):
            break

        resolver.fill(parser)
        print_result(parser, resolver, args.full)


def parse_args():
    parser = argparse.ArgumentParser(description="Decode ESP stacktraces.")

    parser.add_argument("-p", "--platform", help="platform to decode for", choices=PLATFORMS.keys(),
                        default="ESP8266")
    parser.add_argument("-t", "--toolchain", help="path to the Xtensa toolchain",
                        default="~/.platformio/packages/toolchain-xtensa/")
    parser.add_argument("-e", "--elf", help="path to ELF file", required=True)
    parser.add_argument("-f", "--full", help="print full stack dump", action="store_true")
    parser.add_argument("file", help="file to read exception data from ('-' for stdin)", default="-")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    toolchain_path = os.path.abspath(os.path.expanduser(args.toolchain))
    elf_path = os.path.abspath(os.path.expanduser(args.elf))
    if args.file == "-":
        exception_input = None
    else:
        exception_input = os.path.abspath(os.path.expanduser(args.file))

    main(toolchain_path, args.platform, elf_path, exception_input)
