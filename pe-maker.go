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

func (pe *PEMaker) WriteDOSHeader() {
	pe.WriteString("MZ") // e_magic
	pe.WriteInt16(128) // e_cblp
	pe.WriteInt16(1) // e_cp
	pe.WriteInt16(0) // e_crlc
	pe.WriteInt16(4) // e_cparhdr
	pe.WriteInt16(0) // e_minalloc
	pe.WriteInt16(65535) // e_maxalloc
	pe.WriteInt16(0) // e_ss
	pe.WriteInt16(0) // e_sp
	pe.WriteInt16(0) // e_csum
	pe.WriteInt16(0) // e_ip
	pe.WriteInt16(0) // e_cs
	pe.WriteInt16(64) // e_lfarlc
	pe.WriteInt16(0) // e_ovno

	for i := 0; i < 4; i++ {
		pe.WriteInt16(0) // e_res
	}

	pe.WriteInt16(0) // e_oemid
	pe.WriteInt16(0) // e_oeminfo

	for i := 0; i < 10; i++ {
		pe.WriteInt16(0) // e_res
	}

	pe.WriteFilePointer("IMAGE_NT_HEADERS", BIT_32) // e_lfanew
}

func (pe *PEMaker) WriteNTHeader() {
	pe.Mark("IMAGE_NT_HEADERS")
	pe.WriteString(PE_IMAGE_NT_SIGNATURE)
	pe.writeFileHeader()
	pe.writeOptionalHeader()
}

func (pe *PEMaker) writeFileHeader() {

}

func (pe *PEMaker) writeOptionalHeader() {
	
}