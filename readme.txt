git submodule update --init --recursive 
make -C BaseTools


# Go to the following line in Conf/tools_def.txt and remove the "-g" argument (due to previously observed errors with debug locations in LLVM):
# DEFINE GCC_ALL_CC_FLAGS            = -g -Os -fshort-wchar -fno-builtin -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -include AutoGen.h -fno-common

# Set the CLANG_BIN  path in "edksetup.sh" to the */build/bin folder of the built https://github.com/m1ckk/llvm9-project/ project.
bash build.sh
