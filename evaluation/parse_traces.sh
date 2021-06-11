LOG_FILE=./benchmark.csv
TRACE_FILE=/mnt/usb2/tianocore_clean_trace_smm.txt
DEBUG_LOG=./debug.log
MAP_FILE=../Build/OvmfX64/DEBUG_CLANGPDB/X64/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm/OUTPUT/VariableSmm.map
EFI_FILE=../Build/OvmfX64/DEBUG_CLANGPDB/X64/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm/OUTPUT/VariableSmm.efi
DISASSEMBLY_FILE=./disassembly.txt

objdump -D $EFI_FILE > $DISASSEMBLY_FILE
python parse_traces.py CLEAN $MAP_FILE $DISASSEMBLY_FILE $(cat $DEBUG_LOG | grep VariableSmm.efi | awk '{print $5}') $TRACE_FILE $LOG_FILE
