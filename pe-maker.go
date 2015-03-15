package ass

type PEMaker struct{
	*baseMaker
	BinLibs map[string]string
}

func NewPEMaker(path string) (*PEMaker, error) {
	f, err := NewBaseMaker(path)
	if err != nil {
		return nil, err
	}
	return &PEMaker{
		baseMaker: f,
		BinLibs: map[string]string{},
	}, err
}

func (pe *PEMaker) WriteRelativeVirtualAddress(mark string, bit uint8) error {
	return pe.WriteRelative("BinSectionStart", mark, PE_ADDRESS_RVA_BASE, bit)
}

func (pe *PEMaker) WriteMemoryAddress(mark string, bit uint8) error {
	return pe.WriteRelative("BinSectionStart", mark, PE_ADDRESS_IMAGE_BASE + PE_ADDRESS_RVA_BASE, bit)
}