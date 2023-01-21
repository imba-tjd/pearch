// pearch checks an exe or dll is x86 or x64.
package pearch

import (
	"encoding/binary"
	"os"
)

const MACHINE_OFFSET = 4
const PE_POINTER_OFFSET = 60
const MACHINE_VALUE_I386 = 0x014c
const MACHINE_VALUE_X64 = 0x8664

func GetTargetMachineValue(f *os.File) (uint, error) {
	var b [4096]byte
	_, err := f.Read(b[:])
	if err != nil {
		return 0, err
	}

	PE_HEADER_ADDR := binary.LittleEndian.Uint32(b[PE_POINTER_OFFSET:])
	return uint(binary.LittleEndian.Uint16(b[PE_HEADER_ADDR+MACHINE_OFFSET:])), nil
}

func IsX86(filepath string) bool {
	f, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	v, err := GetTargetMachineValue(f)
	if err != nil {
		panic(err)
	}

	return v == MACHINE_VALUE_I386
}

func IsX64(filepath string) bool {
	f, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	v, err := GetTargetMachineValue(f)
	if err != nil {
		panic(err)
	}

	return v == MACHINE_VALUE_X64
}