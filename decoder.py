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

    def parse_file(self, file, stack_only=False):
        state = 'default'

        for line in file:
            line = line.strip()
            if state == 'default' and self._parse_exception(line):
                state = 'exception'
            elif state == 'exception' and self._parse_counters(line):
                continue
            elif (state == 'exception' or stack_only) and self._parse_stack_begin(line):
                state = 'stack'
            elif (state == 'exception' or state == 'stack') and (self._parse_ctx(line) or self._parse_pointers(line)):
                # these two can be either before or in the stack, depending on the Arduino framework version
                continue
            elif state == 'stack' and self._parse_stack_line(line):
                continue
            elif state == 'stack' and self._parse_stack_end(line):
                state = 'default'

        if state != 'default':
            print("ERROR: Parser not complete!")
            sys.exit(1)


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

    def resolve_addr(self, addr, only_found=False, full=False):
        addr = self._sanitize_addr(addr)
        if addr in self._address_map:
            return f"{addr}: {self._address_map[addr]}"

        if full:
            return f"[DATA (0x{addr})]"

        return addr if not only_found else None


def print_addr(name, value, resolver):
    print(f"{name + ':':9} {resolver.resolve_addr(value)}")


def print_stack_full(lines, resolver):
    print("stack:")
    for line in lines:
        print(f"{line.offset}:")
        for content in line.content:
            print(f"  {resolver.resolve_addr(content, full=True)}")


def print_stack(lines, resolver):
    print("stack:")
    for line in lines:
        for content in line.content:
            out = resolver.resolve_addr(content, only_found=True)
            if out:
                print(out)


def print_result(parser, resolver, full=True, stack_only=False):
    if not stack_only:
        exception_cause = EXCEPTIONS[parser.exception] if parser.exception in EXCEPTIONS else "unknown"
        print(f"Exception: {parser.exception} ({exception_cause})")
        print("")

        print_addr("epc1",     parser.epc1,     resolver)
        print_addr("epc2",     parser.epc2,     resolver)
        print_addr("epc3",     parser.epc3,     resolver)
        print_addr("excvaddr", parser.excvaddr, resolver)
        print_addr("depc",     parser.depc,     resolver)
        print("")

        print(f"{'ctx':9} {parser.ctx}")
        print("")

        print_addr("sp", parser.sp, resolver)
        print_addr("end", parser.end, resolver)
        print_addr("offset", parser.offset, resolver)
        print("")

    if full:
        print_stack_full(parser.stack, resolver)
    else:
        print_stack(parser.stack, resolver)


def parse_args():
    parser = argparse.ArgumentParser(description="decode ESP Stacktraces.")

    parser.add_argument("-p", "--platform", help="The platform to decode from", choices=PLATFORMS.keys(),
                        default="ESP8266")
    parser.add_argument("-t", "--tool", help="Path to the xtensa toolchain",
                        default="~/.platformio/packages/toolchain-xtensa/")
    parser.add_argument("-e", "--elf", help="path to elf file", required=True)
    parser.add_argument("-f", "--full", help="Print full stack dump", action="store_true")
    parser.add_argument("-s", "--stack_only", help="Decode only a stractrace", action="store_true")
    parser.add_argument("file", help="The file to read the exception data from ('-' for STDIN)", default="-")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.file == "-":
        file = sys.stdin
    else:
        if not os.path.exists(args.file):
            print("ERROR: file " + args.file + " not found")
            sys.exit(1)
        file = open(args.file, "r")

    addr2line = os.path.join(os.path.abspath(os.path.expanduser(args.tool)),
                             "bin/xtensa-" + PLATFORMS[args.platform] + "-elf-addr2line")
    if not os.path.exists(addr2line):
        print("ERROR: addr2line not found (" + addr2line + ")")

    elf_file = os.path.abspath(os.path.expanduser(args.elf))
    if not os.path.exists(elf_file):
        print("ERROR: elf file not found (" + elf_file + ")")

    parser = ExceptionDataParser()
    resolver = AddressResolver(addr2line, elf_file)

    parser.parse_file(file, args.stack_only)
    resolver.fill(parser)

    print_result(parser, resolver, args.full, args.stack_only)
