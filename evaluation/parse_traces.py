#!/usr/bin/python

import sys

# The defense, for administration purposes.
defense = sys.argv[1]
# Contains all the addresses of functions (.map)
symbols_file = sys.argv[2]
# The disassembly of the .efi file
disassembly_file = sys.argv[3]
# The base address of VariableSmm.efi, retrieved from qemu's debug.log
base_addr = sys.argv[4]
# The base address of VariableSmm.efi, retrieved from qemu's debug.log
trace_file = sys.argv[5]
# The .csv file we log the output to
log_file = sys.argv[6]


# The QEMU log file, containing the execution traces of the SMI handlers.
#trace_file = sys.argv[4]
# File to log the evaluation to
#log_file = sys.argv[5]

smi_handler_names = [
    "VariableServiceGetVariable",
    "VariableServiceGetNextVariableName",
    "VariableServiceSetVariable",
    "VariableServiceQueryVariableInfo"
]

handler_addresses = {}

with open(symbols_file, "r") as f:
    symbols = [x for x in f.read().split("\n") if x and "(.text$" in x]

for symbol in symbols:
    # Example line:
    # 000095a2 00000157     1         lto.tmp:(.text$VariableServiceGetVariable)
    func_name = symbol.split()[3].split("$")[1][:-1]
    for handler_name in smi_handler_names:
        #print(func_name, " == ", handler_name)
        if handler_name == func_name:
            func_begin = symbol.split()[0]
            func_size = symbol.split()[1]
            func_end = hex(int(func_begin, 16) + int(func_size, 16))
            handler_addresses[handler_name] = (func_begin.lstrip("0").lower(), func_end[2:])

print("Symbols retrieved:")
# show retrieved addresses
for key in handler_addresses.keys():
    print("Key = ", key, " - Value = ", handler_addresses[key])


# Retrieve the ret instruction of the four functions above.
with open(disassembly_file, "r") as f:
    disassembly = [x for x in f.read().split("\n") if x]
    for idx, value in enumerate(disassembly):
        if "<.text>:" in value:
            start_disassembly_idx = idx
            break
    disassembly = disassembly[start_disassembly_idx:]

handler_info = {}

# loop over the disassembly lines
for key in handler_addresses.keys():
    handler_info[key] = {}
    (func_begin, func_end) = handler_addresses[key]
    func_begin_int = int(func_begin, 16)
    func_end_int = int(func_end, 16)
    begin_idx = -1
    end_idx = -1

    print("Key: ", key)
    # We have to do address comparisons, since the .map file sometimes contained
    # addresses that did not match with the disassembly output from objdump.
    for idx, inst in enumerate(disassembly):
        words = inst.split()
        addr = words[0].strip(":")
        inst_addr = int(addr, 16)

        if inst_addr >= func_begin_int:
            begin_idx = idx
            handler_info[key]["start"] = addr
            break

    print("begin_idx = ", begin_idx)

    for idx, inst in enumerate(disassembly[begin_idx:]):
        words = inst.split()
        addr = words[0].strip(":")
        inst_addr = int(addr, 16)

        if inst_addr >= func_end_int:
            end_idx = begin_idx + idx
            handler_info[key]["end"] = addr
            break

    print("end_idx   = ", end_idx)

    # Retrieve the address of the ret instruction such that we can retrieve
    # the full trace of a function call.
    for inst in disassembly[begin_idx:end_idx]:
        inst_addr = inst.split()[0].strip(":")
        inst_bytes = inst.split()[1]
        if inst_bytes == "c3":
            print("ret instruction @ ", inst_addr)
            handler_info[key]["ret"] = inst_addr

print("Base address: ", base_addr)
base_addr_int = int(base_addr, 16)

# Add the base address to each address.
for key in handler_info.keys():
    print(key)
    print("start: ", handler_info[key]["start"])
    print("end: ", handler_info[key]["end"])
    print("ret: ", handler_info[key]["ret"])
    handler_info[key]["start"] = hex(int(handler_info[key]["start"], 16) + base_addr_int)[2:]
    handler_info[key]["end"] = hex(int(handler_info[key]["end"], 16) + base_addr_int)[2:]
    handler_info[key]["ret"] = hex(int(handler_info[key]["ret"], 16) + base_addr_int)[2:]
    print("With base address:")
    print("start: ", handler_info[key]["start"])
    print("end: ", handler_info[key]["end"])
    print("ret: ", handler_info[key]["ret"])

# Go over the instruction trace and slice it into pieces.
with open(trace_file, "r") as f:
    instruction_traces = f.read().split("\n")
    instructions = []
    idx = 0
    # preprocessing of the QEMU log.
    while idx < len(instruction_traces):
        instruction = instruction_traces[idx]
        # Compensate for the double instruction in the log.
        if "Stopped execution of TB chain before" in instruction:
            idx += 2
        else:
            if len(instruction.split("/")) == 3:
                ip = instruction.split("/")[1]
                instructions.append(ip.lstrip("0").lower())
            idx += 1

print("#instructions = ", len(instructions))
print(instructions[:10])

# Loop over each VariableSmm function and log the trace based on the first
# instruction of the function and the return address. These functions are not
# recursive, so this way should provide accurate instruction traces per call.
for key in handler_info.keys():
    print("Checking instruction trace for function: ", key)
    handler_info[key]["slices"] = []
    start_addr = handler_info[key]["start"]
    ret_addr = handler_info[key]["ret"]

    inst_pair = []
    for idx,inst in enumerate(instructions):
        if inst == start_addr:
            inst_pair.append(idx)
        if inst == ret_addr:
            inst_pair.append(idx)
            handler_info[key]["slices"].append(inst_pair)
            inst_pair = []

    print(handler_info[key]["slices"])



# Go through each slice and detail information.
smi_benchmarks = []
for key in handler_info.keys():
    slice_text = [defense, key]
    for pair in handler_info[key]["slices"]:
        smi_benchmarks.append(",".join(slice_text + [str(pair[1] - pair[0])]))

for benchmark in smi_benchmarks:
    print(benchmark)
        
with open(log_file, "w") as f:
    for benchmark in smi_benchmarks:
        f.write("instruction," + benchmark + "\n")

