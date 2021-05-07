# This script first removes all the *.sanitizer.inf files for each library path in $smm_libs and then copies all the original *.inf files and copies them to *.sanitizer.inf and then appends the BuildOptions section. Given that we also changed the relevant .dsc file, we can then overwrite all the default libraries (.inf files) with our *.sanitizer.inf files which has added build options.
smm_libs=(MdePkg/Library/DxePcdLib/DxePcdLib OvmfPkg/Library/AcpiTimerLib/DxeAcpiTimerLib OvmfPkg/Library/ResetSystemLib/DxeResetSystemLib MdePkg/Library/SmmMemoryAllocationLib/SmmMemoryAllocationLib MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib MdePkg/Library/DxeHobLib/DxeHobLib MdePkg/Library/SmmMemLib/SmmMemLib MdePkg/Library/MmServicesTableLib/MmServicesTableLib MdePkg/Library/SmmServicesTableLib/SmmServicesTableLib MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort UefiCpuPkg/Library/CpuExceptionHandlerLib/SmmCpuExceptionHandlerLib SourceLevelDebugPkg/Library/DebugAgent/SmmDebugAgentLib OvmfPkg/Library/DxePciLibI440FxQ35/DxePciLibI440FxQ35 MdePkg/Library/BaseLib/BaseLib MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr MdePkg/Library/DxePcdLib/DxePcdLib MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib MdePkg/Library/BasePrintLib/BasePrintLib MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsicSev OvmfPkg/Library/PlatformDebugLibIoPort/PlatformDebugLibIoPort MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint MdeModulePkg/Library/VarCheckUefiLib/VarCheckUefiLib MdeModulePkg/Library/VarCheckPolicyLib/VarCheckPolicyLib MdePkg/Library/BasePciExpressLib/BasePciExpressLib MdePkg/Library/BasePciCf8Lib/BasePciCf8Lib MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol MdePkg/Library/UefiLib/UefiLib MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib MdeModulePkg/Library/VarCheckLib/VarCheckLib MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib MdeModulePkg/Library/VariablePolicyLib/VariablePolicyLib MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib MdeModulePkg/Library/AuthVariableLibNull/AuthVariableLibNull)

git_patches=(SanitizerConf/BaseMemoryLibRepStr.sanitizer.inf.patch)

restore_sanitizer_inf_files () {
    # Add the standard BuildOptions.txt
    build_options='./SanitizerConf/BuildOptionsGeneric.txt'
    printf "\n\n  [ADDING *.sanitizer.inf FILES]\n\n"

    for file in $"${smm_libs[@]}"
    do
        inf=$file".inf"
        sanitizer_inf=$file".sanitizer.inf"
        echo "Removing " $sanitizer_inf
        rm $sanitizer_inf
        echo "Copying " $inf " to " $sanitizer_inf
        cp $inf $sanitizer_inf
        echo "Adding build options to " $sanitizer_inf
        cat $build_options >> $sanitizer_inf
    done
    printf "\n\n  [APPLYING PATCHES]\n\n"
    for patch in $"${git_patches[@]}"
    do
        echo "Applying patch: " $patch
        git apply $patch
    done
    printf "\n\n"
}

# Check whether we should restore the *.sanitizer.inf files.
if [[ $1 = "restore" ]]
then
    shift
    echo "Restoring *.sanitizer.inf files"
    restore_sanitizer_inf_files
fi

ASAN_CC_FLAGS='-fsanitize=address -mllvm -asan-smm-tianocore=1'
MSAN_CC_FLAGS='-fsanitize=memory -mllvm -msan-smm-tianocore=1 -mllvm -msan-keep-going=1 -mllvm -msan-smm-tianocore-replace-external-functions=1'
SFI_CC_FLAGS='-fsanitize=cfi #-fno-sanitize=cfi-icall#cfi-cast-strict,cfi-derived-cast#,cfi-mfcall,cfi-unrelated-cast,cfi-nvcall,cfi-vcall'

MSAN_BLACKLIST=-fsanitize-blacklist=/mnt/part5/edk2/MdePkg/Library/MsanLib/MsanBlacklist.txt

echo SANITIZER_CC_FLAGS=${MSAN_CC_FLAGS}
echo SANITIZER_BLACKLIST=${MSAN_BLACKLIST}
printf "\n\n"

source edksetup.sh && SANITIZER_CC_FLAGS=${MSAN_CC_FLAGS} SANITIZER_BLACKLIST=${MSAN_BLACKLIST} build -a X64 -p OvmfPkg/OvmfPkgX64.dsc -t CLANGPDB -D SMM_REQUIRE -D SANITIZE_SMM -D SANITIZE_SMM_MSAN
