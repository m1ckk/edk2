qemu-system-x86_64 -vga qxl -enable-kvm -machine q35,accel=kvm -cpu host -m 2G -global ICH9-LPC.disable_s3=1 -drive if=pflash,format=raw,unit=0,file=./Build/OvmfX64/DEBUG_CLANGPDB/FV/OVMF_CODE.fd,readonly=on -drive if=pflash,format=raw,file=./Build/OvmfX64/DEBUG_CLANGPDB/FV/OVMF_VARS.fd -drive file=/mnt/part5/qemu_drives/example.qcow2,format=qcow2,if=virtio
