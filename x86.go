package ass

const MACHINE_X86 = 4

var x86 = map[string][]byte{
	"reg": []byte{184},
	"adi": []byte{139, 0},
	"spa": []byte{80},
	"cal": []byte{255, 208},
}