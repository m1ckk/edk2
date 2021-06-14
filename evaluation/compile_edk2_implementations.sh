echo "Building the various edk2 versions"

PROJ_DIR=/mnt/part5/edk2
BUILD_DIR=$PROJ_DIR/Build
VARIABLE_SMM_DIR=${PROJ_DIR}/Build/OvmfX64/DEBUG_CLANGPDB/X64/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableSmm
EVALUATION_DIR=${PROJ_DIR}/evaluation
VERSIONS=(CLEAN ASAN ASAN_NO_FAKESTACK MSAN)

echo "\$PROJ_DIR = $PROJ_DIR"
cd ${PROJ_DIR}

for SANITIZER in "${VERSIONS[@]}"
do
    BENCHMARK_DIR=${EVALUATION_DIR}/${SANITIZER}
    echo "\$BENCHMARK_DIR = $BENCHMARK_DIR"
    echo "\$EVALUATION_DIR = $EVALUATION_DIR"

    rm -rf ${PROJ_DIR}/Build
    echo Adding *.sanitizer.inf files
    bash build.sh RESTORE || exit 1
    echo Building edk2 for sanitizer: $SANITIZER
    [[ -e $BENCHMARK_DIR ]] || mkdir -p $BENCHMARK_DIR
    bash build.sh $SANITIZER > $BENCHMARK_DIR/build.log 2>&1 || exit 1
    cp -r $BUILD_DIR $BENCHMARK_DIR/.
done

echo "Built versions for sanitizers:"
for SANITIZER in "${VERSIONS[@]}"
do
    echo "    $SANITIZER"
done
