#!/usr/bin/python

# This file retrieves the section information from objdump -h FILE and then
# outputs it in csv format in the format "defense,section,section_size"

import sys
import re

# The defense we used during compilation
defense = sys.argv[1]
# The output of objdump -h FILE > section_file
section_file = sys.argv[2]
# The output of QEMU
qemu_file = sys.argv[3]


def computer_shadow_bytes(defense, section_name, num_bytes):
    # Check section names.
    # Sections which we skip
    if "handler" in words[1]:
        return 0
    if "jumptable" in words[1]:
        return 0
    if "init_array" in words[1]:
        return 0
    if "reloc" in words[1]:
        return 0
    if "text" in section_name:
        return 0
    # Check defense for the multiplier.
    if "asan" in defense.lower():
        # Assume 1/8 shadow memory size.
        return int(float(num_bytes) * 0.125)
    elif "msan" in defense.lower():
        return num_bytes
    else:
        return 0

def compute_overhead():
    with open("/tmp/test.txt", "r") as f:
        lines = [line for line in f.read().split("\n") if line]
    footprints = {}
    for line in lines:
        words = line.replace(" ", "").split("&")
        func = words[0]
        base = int(words[1], 16)
        overhead = [float(int(x, 16)) / base for x in words[1:]]
        footprints[func] = overhead
    for func in footprints.keys():
        text = ""
        text += func + ","
        text += ",".join([str("%.2f" % x) for x in footprints[func]])
        print(text)

#########################################################
######## PARSE OBJDUMP OUTPUT
#########################################################

with open(section_file, "r") as f:
    lines = [x for x in f.read().split("\n") if x]

section_idx = -1
for idx, line in enumerate(lines):
    words = line.split()
    if words[0] == "Idx" and words[1] == "Name":
        section_idx = idx + 1
        break

if section_idx == -1:
    print("Couldn't find start of section information.")
    exit()

csv_text = []

total_bytes = 0

for idx, line in enumerate(lines[section_idx:]):
    words = line.split()
    # Skip the line after section info, since we don't need it.
    if idx % 2:
        continue
    # Example line of objdump output:
    #   0 .text         00029adc  0000000000001000  0000000000001000  00000280  2**4
    # words[1] is the section, words[2] is the size in hex
    section_name = words[1]
    section_size = int(words[2], 16)
    total_bytes += section_size
    csv_text.append(",".join([defense, section_name, str(section_size)]))
    # Take shadow bytes into account.
    num_shadow_bytes = computer_shadow_bytes(defense, section_name, section_size)
    csv_text.append(",".join([defense, "shadow_" + section_name, str(num_shadow_bytes)]))

#########################################################
######## PARSE QEMU OUTPUT
#########################################################

pattern = r"\w{10,30},\w{15},\w{2,14},\w{14},\w{2,14},\w{14},\w{2,14}"

function_stacks = { "GetVariable" : 0,
                    "GetNextVariableVariable" : 0,
                    "QueryVariableInfo" : 0,
                    "SetVariable" : 0}
peak_heap_size = 0

with open(qemu_file, "r") as f:
  qemu_lines = [line for line in f.read().split("\n") if re.search(pattern, line)]

# Loop over the filtered output, which contains lines like:
#   GetVariable,peak_stack_size,0x400,peak_heap_size,0xA01158E3,fakestack_size,0x0
for line in qemu_lines:
    words = line.split(",")
    func = words[0]
    stack_size = int(words[2], 16) + int(words[6], 16)
    heap_size = int(words[4], 16)

    if heap_size > peak_heap_size:
        peak_heap_size = heap_size
    if stack_size > function_stacks[func]:
        function_stacks[func] = stack_size

# Print max heap size
csv_text.append(",".join([defense, "peak_heap_size", hex(peak_heap_size)]))
total_bytes += peak_heap_size
# Print heap shadow bytes
num_heap_shadow_bytes = computer_shadow_bytes(defense, "", peak_heap_size)
csv_text.append(",".join([defense, "shadow_peak_heap_size", hex(num_heap_shadow_bytes)]))
total_bytes += num_heap_shadow_bytes

max_stack_size = 0
for func in function_stacks.keys():
    # Retrieve the largest stack size of the different functions.
    if function_stacks[func] > max_stack_size:
        max_stack_size = function_stacks[func]
    csv_text.append(",".join([defense, func, "peak_stack_size", hex(function_stacks[func])]))

# Add the largest stack size we observed
total_bytes += max_stack_size
csv_text.append(",".join([defense, "total_peak_size", hex(total_bytes)]))

for csv in csv_text:
    print(csv)

