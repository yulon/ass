package ass

type PE struct{
	*File
	BinLibs map[string]string
}

const(
	PE_ADDRESS_IMAGE_BASE = 4194304
	PE_ADDRESS_RVA_BASE = 4096
)

func CreatePE(path string) (*PE, error) {
	f, err := CreateFile(path)
	if err != nil {
		return nil, err
	}
	return &PE{
		File: f,
		BinLibs: map[string]string{},
	}, err
}

func (f *File) WriteRelativeVirtualAddress(mark string, bit uint8) error {
	return f.WriteRelative("BinSectionStart", mark, PE_ADDRESS_RVA_BASE, bit)
}

func (f *File) WriteMemoryAddress(mark string, bit uint8) error {
	return f.WriteRelative("BinSectionStart", mark, PE_ADDRESS_IMAGE_BASE + PE_ADDRESS_RVA_BASE, bit)
}