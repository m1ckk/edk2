git clone https://github.com/m1ckk/edk2 edk2 && cd edk2

git submodule update --init --recursive 
make -C BaseTools

# The following writes the build files to the Conf folder
source edksetup.sh

# Go to the following line in Conf/tools_def.txt and remove the "-g" argument (due to previously observed errors with debug locations in LLVM):
# DEFINE GCC_ALL_CC_FLAGS            = -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common

# Set the CLANG_BIN  path in "edksetup.sh" to the */build/bin folder of the built https://github.com/m1ckk/llvm9-project/ project.
bash build.sh


########################
#######   MSan  ########
########################

For MSan, we have to instrument all code of an SMM driver. To do this, there is the script "add_build_options.sh", which uses the contents of "BuildOptions.txt" to add build options to the different libraries that an SMM driver uses. The drivers that are used by an SMM driver seem to be partly defined in OvmfPkg/OvmfPkgX64.dsc and partly in the corresponding .inf file of that driver. To add instrumented libraries to the SMM drivers, we create new .inf files (*.sanitizer.inf), where we append our build options that include instrumentation flags to the build options. For now, I've only done this for VariableSmm.inf (see OvmfPkg/OvmfPkgX64.dsc, which contains all the *.sanitizer.inf files). So OvmfPkg/OvmfPkgX64.dsc defines the *.sanitizer.inf files, and add_build_options.sh creates them with the appended build options.

PiSmmCore loads the SMM drivers, so PiSmmCore also calls the relevant poisoning functions, such that .rdata is not poisoned, but .data is. We also have a blacklist file called "msan_blacklist.txt". For now, it seems to be the problem that MSan-instrumented VariableSmm.efi's entrypoint is called and then some external calls take place that are not instrumented, and then MSan detects the use of uninitialized memory.

To start with MSan, use add_build_options.sh to add the relevant library files and then VariableSmm.efi should be instrumented. Then use build.sh and qemu.sh to build and run.
