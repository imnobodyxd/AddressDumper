#include "eyecrawl.h"

namespace EyeCrawl {
	bool DLL_MODE;

	HANDLE proc;
	unsigned int base_address;
	unsigned int base_size;
	const long default_chunksize = (64*64*16);
	const long default_scansize	 = (64*64*64);

	// +0x40 implies we want it to be in this mode
	const int op8_mode1 = 0x40;
	const int op8_mode2 = 0x48;
	const int op8_mode3 = 0x50;
	const int op8_mode4 = 0x58;
	const int op8_mode5 = 0x60;
	const int op8_mode6 = 0x68;
	const int op8_mode7 = 0x70;
	const int op8_mode8 = 0x78;

	// for quick text-byte conversion
	const char c_ref1[16]	= {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	const int c_ref2[16]	= { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15};

	// disassembler information
	const char* _r8[8]		= {"al","cl","dl","bl","ah","ch","dh","bh"};
	const char* _r16[8]		= {"ax","bx","cx","dx","sp","bp","si","di"};
	const char* _r32[8]		= {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
	const char* _rx[8]		= {"xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7"};
	const char* _cond[16]	= {"o","no","b","nb","e","ne","na","a","s","ns","p","np","l","nl","lng","g"};

	// identification table for the majority of x86 instructions.
	// Required if we also want to WRITE x86 to the process
	// This is not completely filled out,
	// but here is a fully-functional structure for
	// a table-based disassembler.
	const instruction_ref ref_x86[] = {
		{{0x03}, 0,				"add",		r_m32,		r_m,	"", ""},
		{{0x0F,0x1F}, 0,		"nop",		r_m,		none,	"dword ptr", ""},
		{{0x0F,0x28}, 0,		"movaps",	r_mx,		r_m,	"", "qword ptr"},
		{{0x0F,0x29}, 0,		"movaps",	r_m,		r_mx,	"qword ptr", ""},
		{{0x0F,0x2E}, 0,		"ucomiss",	r_mx,		r_m,	"", "qword ptr"},
		{{0x0F,0x40}, 16,		"cmov[c]",	r_m32,		r_m,	"", ""},	
		{{0x0F,0x57}, 0,		"xorps",	r_mx,		r_m,	"", "qword ptr"},
		{{0x0F,0x80}, 16,		"j[c]",		rel32,		none,	"", ""},
		{{0x0F,0xB6}, 0,		"movzx",	r_m32,		r_m,	"", "byte ptr"},
		{{0x0F,0xBB}, 0,		"btc",		r_m,		r_m32,	"", ""},
		{{0x23}, 0,				"and",		r_m32,		r_m,	"", ""},
		{{0x24}, 0,				"and",		single,		imm8,	"al", ""},
		{{0x2B}, 0,				"sub",		r_m32,		r_m,	"", ""},
		{{0x33}, 0,				"xor",		r_m32,		r_m,	"", ""},
		{{0x38}, 0,				"cmp",		r_m,		r_m8,	"byte ptr", ""},
		{{0x39}, 0,				"cmp",		r_m,		r_m32,	"", ""},
		{{0x3B}, 0,				"cmp",		r_m32,		r_m,	"", ""},
		{{0x3D}, 0,				"cmp",		single,		imm32,	"eax", ""},
		{{0x40}, 8,				"inc",		r32,		none,	"", ""},
		{{0x48}, 8,				"dec",		r32,		none,	"", ""},
		{{0x50}, 8,				"push",		r32,		none,	"", ""},
		{{0x58}, 8,				"pop",		r32,		none,	"", ""},
		{{0x66,0x90}, 8,		"xchg",		r16,		r16,	"", ""},
		{{0x66,0xC0}, 0,		"rol",		r_m,		imm8,	"byte ptr", ""},
		{{0x66,0xC1}, 0,		"rol",		r_m,		imm16,	"word ptr", ""},
		{{0x66,0xC2}, 0,		"near ret",	imm16,		none,	"", ""},
		{{0x66,0xC3}, 0,		"near retn",none,		none,	"", ""},
		{{0x66,0xC4}, 0,		"les",		r_m16,		r_m,	"", "word ptr"},
		{{0x66,0xC5}, 0,		"lds",		r_m16,		r_m,	"", "word ptr"},
		{{0x66,0xC6}, 0,		"mov",		r_m,		imm8,	"byte ptr", ""},
		{{0x66,0xC7}, 0,		"mov",		r_m,		imm16,	"word ptr", ""},
		{{0x68}, 0,				"push",		imm32,		none,	"", ""},
		{{0x6A}, 0,				"push",		imm8,		none,	"", ""},
		{{0x70}, 16,			"j[c]",		rel8,		none,	"short", ""},
		{{0x80}, op8_mode1,		"add",		r_m,		imm8,	"byte ptr", ""},
		{{0x80}, op8_mode2,		"or",		r_m,		imm8,	"byte ptr", ""},
		{{0x80}, op8_mode3,		"adc",		r_m,		imm8,	"byte ptr", ""},
		{{0x80}, op8_mode4,		"sbb",		r_m,		imm8,	"byte ptr", ""},
		{{0x80}, op8_mode5,		"and",		r_m,		imm8,	"byte ptr", ""},
		{{0x80}, op8_mode6,		"sub",		r_m,		imm8,	"byte ptr", ""},
		{{0x80}, op8_mode7,		"xor",		r_m,		imm8,	"byte ptr", ""},
		{{0x80}, op8_mode8,		"cmp",		r_m,		imm8,	"byte ptr", ""},
		{{0x81}, op8_mode1,		"add",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode2,		"or",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode3,		"adc",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode4,		"sbb",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode5,		"and",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode6,		"sub",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode7,		"xor",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode8,		"cmp",		r_m,		imm32,	"dword ptr", ""},
		{{0x81}, op8_mode1,		"add",		r_m,		imm8,	"byte ptr", ""},
		{{0x81}, op8_mode2,		"or",		r_m,		imm8,	"byte ptr", ""},
		{{0x81}, op8_mode3,		"adc",		r_m,		imm8,	"byte ptr", ""},
		{{0x82}, op8_mode4,		"sbb",		r_m,		imm8,	"byte ptr", ""},
		{{0x82}, op8_mode5,		"and",		r_m,		imm8,	"byte ptr", ""},
		{{0x82}, op8_mode6,		"sub",		r_m,		imm8,	"byte ptr", ""},
		{{0x82}, op8_mode7,		"xor",		r_m,		imm8,	"byte ptr", ""},
		{{0x82}, op8_mode8,		"cmp",		r_m,		imm8,	"byte ptr", ""},
		{{0x83}, op8_mode1,		"add",		r_m,		imm8,	"dword ptr", ""},
		{{0x83}, op8_mode2,		"or",		r_m,		imm8,	"dword ptr", ""},
		{{0x83}, op8_mode3,		"adc",		r_m,		imm8,	"dword ptr", ""},
		{{0x83}, op8_mode4,		"sbb",		r_m,		imm8,	"dword ptr", ""},
		{{0x83}, op8_mode5,		"and",		r_m,		imm8,	"dword ptr", ""},
		{{0x83}, op8_mode6,		"sub",		r_m,		imm8,	"dword ptr", ""},
		{{0x83}, op8_mode7,		"xor",		r_m,		imm8,	"dword ptr", ""},
		{{0x83}, op8_mode8,		"cmp",		r_m,		imm8,	"dword ptr", ""},
		{{0x85}, 0,				"test",		r_m,		r_m32,	"", ""},
		{{0x88}, 0,				"mov",		r_m,		r8,		"byte ptr", ""},
		{{0x89}, 0,				"mov",		r_m,		r_m32,	"", ""},
		{{0x8A}, 0,				"mov",		r_m8,		r_m,	"", "byte ptr"},
		{{0x8B}, 0,				"mov",		r_m32,		r_m,	"", ""},
		{{0x8D}, 0,				"lea",		r_m32,		r_m,	"", ""},
		{{0xA1}, 0,				"mov",		single,		imm32,	"eax", "dword"},
		{{0xA2}, 0,				"mov",		imm32,		single,	"byte", "al"},
		{{0xA3}, 0,				"mov",		imm32,		single,	"dword", "eax"},
		{{0xB8}, 8,				"mov",		r32,		imm32,	"", ""},
		{{0xC0}, op8_mode1,		"rol",		r_m,		imm8,	"byte ptr", ""},
		{{0xC0}, op8_mode2,		"ror",		r_m,		imm8,	"byte ptr", ""},
		{{0xC0}, op8_mode3,		"rcl",		r_m,		imm8,	"byte ptr", ""},
		{{0xC0}, op8_mode4,		"rcr",		r_m,		imm8,	"byte ptr", ""},
		{{0xC0}, op8_mode5,		"shl",		r_m,		imm8,	"byte ptr", ""},
		{{0xC0}, op8_mode6,		"shr",		r_m,		imm8,	"byte ptr", ""},
		{{0xC0}, op8_mode7,		"???",		r_m,		imm8,	"byte ptr", ""},
		{{0xC0}, op8_mode8,		"sar",		r_m,		imm8,	"byte ptr", ""},
		{{0xC1}, op8_mode1,		"rol",		r_m,		imm8,	"", ""},
		{{0xC1}, op8_mode2,		"ror",		r_m,		imm8,	"", ""},
		{{0xC1}, op8_mode3,		"rcl",		r_m,		imm8,	"", ""},
		{{0xC1}, op8_mode4,		"rcr",		r_m,		imm8,	"", ""},
		{{0xC1}, op8_mode5,		"shl",		r_m,		imm8,	"", ""},
		{{0xC1}, op8_mode6,		"shr",		r_m,		imm8,	"", ""},
		{{0xC1}, op8_mode7,		"???",		r_m,		imm8,	"", ""},
		{{0xC1}, op8_mode8,		"sar",		r_m,		imm8,	"", ""},
		{{0xC2}, 0,				"ret",		imm16,		none,	"", ""},
		{{0xC3}, 0,				"retn",		none,		none,	"", ""},
		{{0xC6}, 0,				"mov",		r_m,		imm8,	"byte ptr", ""},
		{{0xC7}, 0,				"mov",		r_m,		imm32,	"dword ptr", ""},
		{{0xCC}, 0,				"align",	none,		none,	"", ""},
		{{0xD9,0xE0}, 0,		"fchs",		none,		none,	"", ""}, // change sign
		{{0xD9,0xE1}, 0,		"fabs",		none,		none,	"", ""}, // absolute value
		{{0xD9,0xE4}, 0,		"ftst",		none,		none,	"", ""}, // test
		{{0xD9,0xE5}, 0,		"fxam",		none,		none,	"", ""}, // examine
		{{0xD9,0xE8}, 0,		"fld1",		none,		none,	"", ""}, // Push +1.0 onto FPU stack
		{{0xD9,0xE9}, 0,		"fldl2t",	none,		none,	"", ""}, // Push log2(10) onto FPU stack
		{{0xD9,0xEA}, 0,		"fldl2e",	none,		none,	"", ""}, // Push log2(e) onto FPU stack
		{{0xD9,0xEB}, 0,		"fldpi",	none,		none,	"", ""}, // Push pi constant onto FPU stack
		{{0xD9,0xEC}, 0,		"fldlg2",	none,		none,	"", ""}, // Push log10(2) onto FPU stack
		{{0xD9,0xED}, 0,		"fldln2",	none,		none,	"", ""}, // Push log e(2) onto FPU stack
		{{0xD9,0xEE}, 0,		"fldz",		none,		none,	"", ""}, // Push +0.0 onto FPU stack
		{{0xDD}, 0,				"fld",		r_m,		none,	"qword ptr", ""},
		{{0xE8}, 0,				"call",		rel32,		none,	"", ""},
		{{0xE9}, 0,				"jmp",		rel32,		none,	"", ""},
		{{0xEB}, 0,				"jmp",		rel8,		none,	"short", ""},
		{{0xF0,0xFF}, 0,		"lock inc",	r_m,		none,	"dword", ""},
		{{0xF2,0x0F,0x10}, 0,	"movsd",	rxmm,		r_m,	"", "qword ptr"},
		{{0xF2,0x0F,0x11}, 0,	"movsd",	r_m,		rxmm,	"qword ptr", ""},
		{{0xF7}, op8_mode1,		"test",		r_m,		imm16,	"dword ptr", ""},
		{{0xF7}, op8_mode2,		"???",		r_m,		none,	"", ""},
		{{0xF7}, op8_mode3,		"not",		r_m,		none,	"", ""},
		{{0xF7}, op8_mode4,		"neg",		r_m,		none,	"", ""},
		{{0xF7}, op8_mode5,		"mul",		r_m,		none,	"", ""},
		{{0xF7}, op8_mode6,		"imul",		r_m,		none,	"", ""},
		{{0xF7}, op8_mode7,		"div",		r_m,		none,	"", ""},
		{{0xF7}, op8_mode8,		"idiv",		r_m,		none,	"", ""},
		{{0xFF}, op8_mode1,		"inc",		r_m,		none,	"dword ptr", ""},
		{{0xFF}, op8_mode2,		"dec",		r_m,		none,	"dword ptr", ""},
		{{0xFF}, op8_mode3,		"call",		r_m,		none,	"dword ptr", ""},
		{{0xFF}, op8_mode4,		"call",		r_m,		none,	"dword ptr", ""},
		{{0xFF}, op8_mode5,		"jmp",		r_m,		none,	"dword ptr", ""},
		{{0xFF}, op8_mode6,		"jmp far",	r_m,		none,	"dword ptr", ""},
		{{0xFF}, op8_mode7,		"push",		r_m,		none,	"dword ptr", ""},
		{{0xFF}, op8_mode8,		"???",		r_m,		none,	"dword ptr", ""},
	};
};

HANDLE EyeCrawl::get()						{ return proc; }
unsigned int EyeCrawl::base_start()				{ return base_address; }
unsigned int EyeCrawl::base_end()				{ return base_address + base_size; }
unsigned int EyeCrawl::aslr(unsigned int addr)		{ return (addr - 0x400000 + base_address); }
unsigned int EyeCrawl::non_aslr(unsigned int addr)	{ return (addr + 0x400000 - base_address); }

EyeCrawl::cbyte EyeCrawl::readb(unsigned int addr, int count) {
	cbyte x = cbyte();
	for (int i=0; i<count; i++){
		x.add(readb(addr+i));
	}
	return x;
}

unsigned char EyeCrawl::readb(unsigned int addr) {
	if (DLL_MODE) return *(unsigned char*)addr;
	unsigned char buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,1,0);
	return buffer;
}

char EyeCrawl::readc(unsigned int addr) {
	if (DLL_MODE) return *(char*)addr;
	char buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,1,0);
	return buffer;
}

unsigned short EyeCrawl::readus(unsigned int addr) {
	if (DLL_MODE) return *(unsigned short*)addr;
	unsigned short buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,2,0);
	return buffer;
}

short EyeCrawl::reads(unsigned int addr) {
	if (DLL_MODE) return *(short*)addr;
	short buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,2,0);
	return buffer;
}

unsigned int EyeCrawl::readui(unsigned int addr) {
	if (DLL_MODE) return *(unsigned int*)addr;
	unsigned int buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,4,0);
	return buffer;
}

int EyeCrawl::readi(unsigned int addr) {
	if (DLL_MODE) return *(int*)addr;
	int buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,4,0);
	return buffer;
}

float EyeCrawl::readf(unsigned int addr) {
	if (DLL_MODE) return *(float*)addr;
	float buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,4,0);
	return buffer;
}

double EyeCrawl::readd(unsigned int addr) {
	if (DLL_MODE) return *(double*)addr;
	double buffer = 0;
	ReadProcessMemory(proc,reinterpret_cast<void*>(addr),&buffer,8,0);
	return buffer;
}

std::string EyeCrawl::sreads(unsigned int address) {
	std::string read="";
	if (DLL_MODE) {
		char* str = *(char**)(address);
		read += str;
	} else {
		unsigned int reader = address;
		// Check for a pointer to a string
		if (readui(address)>base_start() && readui(address)<0x3FFFFFFF && readui(address)%4==0)
			reader = readui(address);
		// Try to read string
		while (reader - address < STR_READ_MAX) {
			char c = readc(reader++);
			if (c >= 0x20 && c <= 0x7E) read += c; else break;
		}
	}
	return read;
}

// Returns an AOB string of the bytes at
// the given address.
// Warning: this function does not, and in
// general, dont, include spaces in the AOB string.
//
std::string EyeCrawl::sreadb(unsigned int addr, int count) {
	std::string str = "";
	if (count==0) return str; else {
		for (int i=0; i<count; i++){
			str += to_str(readb(addr+i));
			//if (i!=count-1) str+=" ";
		}
	}
	return str;
}

std::vector<unsigned char> EyeCrawl::preadb(unsigned int addr, int count) {
	std::vector<unsigned char>x = std::vector<unsigned char>();
	if (count != 0){
		for (int i=0; i<count; i++){
			x.push_back(readb(addr+i));
		}
	}
	return x;
}

bool EyeCrawl::write(unsigned int addr, EyeCrawl::cbyte x){
	return EyeCrawl::write(addr, x.bytes);
}

bool EyeCrawl::write(unsigned int addr, unsigned char v){
	if (DLL_MODE) *(unsigned char*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,1,0);
}

bool EyeCrawl::write(unsigned int addr, char v){
	if (DLL_MODE) *(char*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,1,0);
}

bool EyeCrawl::write(unsigned int addr, unsigned short v){
	if (DLL_MODE) *(unsigned short*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,2,0);
}

bool EyeCrawl::write(unsigned int addr, short v){
	if (DLL_MODE) *(short*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,2,0);
}

bool EyeCrawl::write(unsigned int addr, unsigned int v){
	if (DLL_MODE) *(unsigned int*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,4,0);
}

bool EyeCrawl::write(unsigned int addr, int v){
	if (DLL_MODE) *(int*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,4,0);
}

bool EyeCrawl::write(unsigned int addr, float v){
	if (DLL_MODE) *(float*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,4,0);
}

bool EyeCrawl::write(unsigned int addr, double v){
	if (DLL_MODE) *(double*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),&v,8,0);
}

bool EyeCrawl::write(unsigned int addr, std::string v){
	if (DLL_MODE) *(std::string*)(addr) = v;
	return WriteProcessMemory(proc,reinterpret_cast<void*>(addr),v.c_str(),v.length(),0);
}

bool EyeCrawl::write(unsigned int addr, std::vector<unsigned char>x){
	bool result = false;
	for (int i=0; i<x.size(); i++){
		result = EyeCrawl::write(addr+i, x[i]);
	}
	return result;
}

void EyeCrawl::open(HANDLE h) {
	if (h == INVALID_HANDLE_VALUE || h == NULL){
		DLL_MODE		= true;
		proc			= GetCurrentProcess();
		base_address	= reinterpret_cast<unsigned int>(GetModuleHandleW(0));
		base_size		= GetFileSize(h, reinterpret_cast<LPDWORD>(0xFFFFFFF));
		//printf("SWITCHING TO DLL MODE\n");
	} else {
		DLL_MODE		= false;
		proc			= h;
		HMODULE hMods[1024];
		unsigned long cbNeeded, mCurrent = 0;
		if (EnumProcessModulesEx(proc,hMods,1024,&cbNeeded,LIST_MODULES_ALL)){
			for (int i=0; i<(cbNeeded/sizeof(HMODULE)); i++){
				MODULEINFO info;
				char szModPath[MAX_PATH];
				if (GetModuleFileNameExA(proc,hMods[i],szModPath,sizeof(szModPath)) && K32GetModuleInformation(proc,hMods[i],&info,cbNeeded)){
					if (mCurrent++ == 0){
						base_address= reinterpret_cast<unsigned int>(info.lpBaseOfDll);
						base_size	= static_cast<unsigned int>(info.SizeOfImage);
					}
				}
			}
		}
	}
	if (base_address == 0 || base_size == 0){
		printf("FAILED TO RESOLVE BASE MODULE\n");
	}
}

// Replaces one occurence in the string
void strrepl(char* dest,const char* find,const char* rep){
	char str[255];
	int at=0,f;
	while (at < lstrlenA(dest)){
		f = true;
		for (int j=0; j<lstrlenA(find); j++)
			if (dest[at+j] != find[j])
				f = false;
		if (f) break; else
			str[at] = dest[at++];
	}
	if (f) {
		for (int j=0; j<lstrlenA(rep); j++)
			str[at++] = rep[j];
		str[at] = '\0';
		strcpy(dest, str);
	}
}

// Replaces all cases found of a mask-based expression
std::string replaceex(std::string str, const char* replace, const char* mask, const char* newstr) {
	std::string x;
	int size=lstrlenA(mask);
	for (int i=0; i<str.length(); i++){
		bool matched=(i<(str.length()-size));
		if (matched) // dont check past the string size
			for (int j=0; j<size; j++)
				if (mask[j]=='.' && str[i+j]!=replace[j])
					matched=false;
		if (matched){
			i += (size-1);
			x += newstr;
		} else {
			x += str[i];
		}
	}
	return x;
}

// Returns true if B is found in A
bool strfind(const char* A, const char* B) {
	unsigned char found = 1;
	for (int i=0; i < (lstrlenA(A) - lstrlenA(B)); i++){
		found = 1;
		for (int j=0; j < lstrlenA(B); j++)
			if (A[i+j] != B[j])
				found = 0;
		if (found) return found;
	}
	return false;
}

EyeCrawl::pinstruction EyeCrawl::disassemble(unsigned int addr) {
	instruction* x = new instruction();
	x->address = addr;
	x->size = 1; // atleast fill in the blank

	// Search up the instruction signature
	unsigned char matched,last,div,op8mode;
	int _lookup=0,_size,_i;
	for (_lookup; _lookup<sizeof(ref_x86)/sizeof(instruction_ref); _lookup++){
		matched = 1;
		_i		= 0;
		_size	= ref_x86[_lookup].size;
		last	= ref_x86[_lookup].bytes[_size-1];
		div		= ref_x86[_lookup].div;
		op8mode = 0;

		if (div == 0){
			for (_i=0; _i<_size; _i++)
				if (readb(addr+_i) != ref_x86[_lookup].bytes[_i])
					matched = 0;
		} else {
			if (div < 0x40){
				for (_i=0; _i<_size-1; _i++)
					if (readb(addr+_i) != ref_x86[_lookup].bytes[_i])
						matched = 0;
				if (matched){
					matched = 0;
					if ((readb(addr+_i)-last >= 0 &&
						 readb(addr+_i)-last < div)){
						matched = 1;
					} else continue;
				}
			} else {
				for (_i=0; _i<_size; _i++)
					if (readb(addr+_i) != ref_x86[_lookup].bytes[_i])
						matched = 0;
				if (matched){
					matched = 0;
					op8mode = 1;
					unsigned char b = readb(addr+_i) % 0x40;
					if (b >= (div-0x40) && b<(div-0x40)+8){
						matched = 1;
					} else continue;
				}
			}
		}

		// Now check, break upon finding correct signature
		if (matched) break;
	}
	
	// If we have this instruction signature
	// recognized, let's disassemble it
	if (matched){
		x->dest = ref_x86[_lookup].dest;
		x->src = ref_x86[_lookup].src;
		strcpy_s(x->opcode, ref_x86[_lookup].opcode);
		strrepl(x->opcode,"[c]",_cond[readb(addr+(ref_x86[_lookup].size-1))%16]);
		strcpy_s(x->data, x->opcode);
		strcpy_s(x->mark1, ref_x86[_lookup].mark1);
		strcpy_s(x->mark2, ref_x86[_lookup].mark2);
		
		if (x->dest != cnd8 &&
			x->dest != cnd16 &&
			x->dest != cnd32)
			strcat_s(x->data, " ");
		if (x->dest == single)
			strcat_s(x->data, x->mark1);
		
		
		unsigned char c,mode20,mode40,i,j,oldj=0,oldi=0,skip=0;
		char cnv[16]; // for necessary translating
		char second_op[8];

		// update data for current byte
		auto update = [&c,&addr,&x,&mode20,&mode40,&i,&j]() {
			c=readb(addr+x->size);
			mode20=c/32;
			mode40=c/64;
			i=c%8;
			j=c%64/8;
		};

		// update and then extend size
		auto extend = [&c,&addr,&x,update]() {
			update();
			x->size++;
		};

		auto w_offset8 = [&x,&cnv,&addr]() {
			unsigned char v=readb(addr+x->size);
			x->offset = v;
			if (v <= 0x7F){
				sprintf_s(cnv,"%02X",v);
				strcat_s(x->data, "+");
				strcat_s(x->data, cnv);
			} else {
				sprintf_s(cnv,"%02X",(UCHAR_MAX-v+1));
				strcat_s(x->data, "-");
				strcat_s(x->data, cnv);
			}
			x->size += 1;
		};

		auto w_offset16 = [&x,&cnv,&addr]() {
			unsigned short v=readus(addr+x->size);
			x->offset = v;
			if (v <= 0x7FFF){
				sprintf_s(cnv,"%04X",v);
				strcat_s(x->data, "+");
				strcat_s(x->data, cnv);
			} else {
				sprintf_s(cnv,"%04X",(USHRT_MAX-v+1));
				strcat_s(x->data, "-");
				strcat_s(x->data, cnv);
			}
			x->size += sizeof(unsigned short);
		};

		auto w_offset32 = [&x,&cnv,&addr]() {
			unsigned int v=readui(addr+x->size);
			x->offset = v;
			if (v <= 0x7FFFFFFF){
				sprintf_s(cnv,"%08X",v);
				strcat_s(x->data, "+");
				strcat_s(x->data, cnv);
			} else {
				sprintf_s(cnv,"%08X",(UINT32_MAX-v+1));
				strcat_s(x->data, "-");
				strcat_s(x->data, cnv);
			}
			x->size += sizeof(unsigned int);
		};

		auto w_mult32 = [&x,&mode40]() {
			if (mode40 != 0) {
				int mul=(mode40==1)?2:(mode40==2)?4:(mode40==3)?8:0;
				char s_mul[2];
				sprintf_s(s_mul,"%i",mul);
				strcat_s(x->data, "*");
				strcat_s(x->data, s_mul);
			}
		};

		auto check_mark = [&x]() {
			if (lstrlenA(x->mark1)>0){
				strcat_s(x->data, x->mark1);
				strcat_s(x->data, " ");
			} else if (lstrlenA(x->mark2)>0){
				strcat_s(x->data, x->mark2);
				strcat_s(x->data, " ");
			}
		};

		x->size = 0;
		if (op8mode) x->size++;
		update(); // use data from very first byte
		x->size = (ref_x86[_lookup].size-1);
		oldi = i;
		
		// FIRST OPERAND
		switch (x->dest) {
			case _m::none:
				check_mark();
				x->size = ref_x86[_lookup].size;
			break;

			case _m::single:
				extend();
			break;

			// Check 8bit value on the next byte
			case _m::imm8:
				extend();
				x->v8 = readb(addr+x->size);
				sprintf_s(cnv,"%02X",readb(addr+x->size));
				strcat_s(x->data,cnv);
				x->size += 1;
			break;
			// Check 16bit value on the next 2 bytes
			case _m::imm16:
				extend();
				x->v16 = readus(addr+x->size);
				sprintf_s(cnv,"%04X",readus(addr+x->size));
				strcat_s(x->data,cnv);
				x->size += sizeof(unsigned short);
			break;
			// Check 32bit value on the next 4 bytes
			case _m::imm32:
				extend();
				x->v32 = readui(addr+x->size);
				sprintf_s(cnv,"%08X",readui(addr+x->size));
				strcat_s(x->data,cnv);
				x->size += sizeof(unsigned int);
			break;

			case _m::rel8:
				check_mark();
				extend();
				x->v8 = readb(addr+x->size);
				sprintf_s(cnv,"%08X",(addr+x->size+1+(signed char)readb(addr+x->size)));
				strcat_s(x->data,cnv);
				x->size += 1;
			break;
			case _m::rel16:
				check_mark();
				extend();
				x->v16 = readus(addr+x->size);
				sprintf_s(cnv,"%04X",(addr+x->size+2+(signed short)readus(addr+x->size)));
				strcat_s(x->data,cnv);
				x->size += sizeof(unsigned short);
			break;
			case _m::rel32:
				check_mark();
				extend();
				x->v32 = readui(addr+x->size);
				sprintf_s(cnv,"%08X",(addr+x->size+4+(signed int)readui(addr+x->size)));
				strcat_s(x->data,cnv);
				x->size += sizeof(unsigned int);
			break;

			case _m::r8:
				extend();
				strcat_s(x->data,_r8[i]); // goes by 8ths
			break;
			case _m::r16:
				extend();
				strcat_s(x->data,_r16[i]); // have not gotten here yet
			break;
			case _m::r32:
				extend();
				strcat_s(x->data,_r32[i]);
			break;
			case _m::rxmm:
				extend();
				strcat_s(x->data,_rx[i]);
			break;

			case _m::r_m8:
				extend();
				update();
				x->r8[0] = j;
				switch (mode40){
					case 0: // 0x00 through 0x3F
						switch (i){
							case 0x4:
								strcat_s(x->data,_r8[j]);
							break;
							case 0x5:
								strcat_s(x->data,_r8[(c-0x5)/8]);
								x->size++;
								x->src = _m::imm32;
							break;
							default:
								strcat_s(x->data,_r8[j]);
							break;
						}
					break;
					default: // 0x40-0xFF
						strcat_s(x->data,_r8[j]);
					break;
				}
			break;

			case _m::r_m16:
				extend();
				update();
				x->r16[0] = j;
				switch (mode40){
					case 0: // 0x00 through 0x3F
						switch (i){
							case 0x4:
								strcat_s(x->data,_r16[j]);
							break;
							case 0x5:
								strcat_s(x->data,_r16[(c-0x5)/8]);
								x->size++;
								x->src = _m::imm32;
							break;
							default:
								strcat_s(x->data,_r16[j]);
							break;
						}
					break;
					default: // 0x40-0xFF
						strcat_s(x->data,_r16[j]);
					break;
				}
			break;

			case _m::r_m32:
				extend();
				update();
				x->r32[0] = j;
				switch (mode40){
					case 0: // 0x00 through 0x3F
						switch (i){
							case 0x4:
								strcat_s(x->data,_r32[j]);
							break;
							case 0x5:
								strcat_s(x->data,_r32[(c-0x5)/8]);
								x->size++;
								x->src = _m::imm32;
							break;
							default:
								strcat_s(x->data,_r32[j]);
							break;
						}
					break;
					default: // 0x40-0xFF
						strcat_s(x->data,_r32[j]);
					break;
				}
			break;

			case _m::r_mx:
				extend();
				update();
				x->rxmm[0] = j;
				switch (mode40){
					case 0: // 0x00 through 0x3F
						switch (i){
							case 0x4:
								strcat_s(x->data,_rx[j]);
							break;
							case 0x5:
								strcat_s(x->data,_rx[(c-0x5)/8]);
								x->size++;
								x->src = _m::imm32;
							break;
							default:
								strcat_s(x->data,_rx[j]);
							break;
						}
					break;
					default: // 0x40-0xFF
						strcat_s(x->data,_rx[j]);
					break;
				}
			break;

			case _m::r_m:{
				// This is done because a previous byte could
				// represent the second operand, which
				// we need to know, if it is a register
				unsigned char	src_r8op =	(x->src==r_m8),
						src_r16op =	(x->src==r_m16),
						src_r32op = (x->src==r_m32),
						src_rxop =	(x->src==r_mx);
				// For any case, we need to skip the second
				// operand check
				skip = (src_r8op ||
						src_r16op ||
						src_r32op ||
						src_rxop);

				extend();
				extend();
				x->r32[0] = i;
				switch (mode40) {
					case 3: // 0xC0 through 0xFF
						if (src_rxop || strcmp(x->mark1,"qword ptr")==0)
							strcat_s(x->data, _rx[i]);
						else if (src_r8op || strcmp(x->mark1,"byte ptr")==0)
							strcat_s(x->data, _r8[i]);
						else if (src_r16op || strcmp(x->mark1,"word ptr")==0)
							strcat_s(x->data, _r16[i]);
						else
							strcat_s(x->data, _r32[i]);
						oldj = j;
						skip = 0;
						break;
					case 2: // 0x80 through 0xBF
						check_mark();
						strcat_s(x->data, "[");
						oldj = j;
						switch(i){
							case 0x4:
								extend();
								x->r32[0] = i;
								strcat_s(x->data, _r32[i]);
								if (mode20%2!=1 || c%0x20>=16){ 
									strcat_s(x->data, "+");
									strcat_s(x->data, _r32[j]);
									w_mult32();
								} else if (c%0x20>=8) {
									strcat_s(x->data, "+");
									strcat_s(x->data, _r32[j]);
								}
							break;
							default:
								strcat_s(x->data, _r32[i]);
							break;
						}
						w_offset32();
						strcat_s(x->data, "]");
						break;
					case 1: // 0x40 through 0x80
						check_mark();
						strcat_s(x->data, "[");
						oldj = j;
						switch(i){
							case 0x4:
								extend();
								x->r32[0] = i;
								strcat_s(x->data, _r32[i]);
								if (mode20%2!=1 || c%0x20>=16){ 
									strcat_s(x->data, "+");
									strcat_s(x->data, _r32[j]);
									w_mult32();
								} else if (c%0x20>=8) {
									strcat_s(x->data, "+");
									strcat_s(x->data, _r32[j]);
								}
							break;
							default:
								strcat_s(x->data, _r32[i]);
							break;
						}
						w_offset8();
						strcat_s(x->data, "]");
						break;
					case 0: // 0x00 through 0x40
						check_mark();
						strcat_s(x->data, "[");
						oldj = j;
						switch(i){
							case 0x4:
								extend();
								x->r32[0] = i;
								switch(i){
									case 0x5:
										if ((mode20+1)%2==0){
											sprintf_s(cnv,"%08X",readui(addr+x->size));
											strcat_s(x->data, cnv);
											x->size += sizeof(unsigned int);
										} else {
											strcat_s(x->data, _r32[j]);
											w_mult32();
											w_offset32();
										}
									break;
									default:
										strcat_s(x->data, _r32[i]);
										if (mode20%2!=1 || c%0x20>=16){ 
											strcat_s(x->data, "+");
											strcat_s(x->data, _r32[j]);
											w_mult32();
										} else if (c%0x20>=8) {
											strcat_s(x->data, "+");
											strcat_s(x->data, _r32[j]);
											w_mult32();
										}
									break;
								}
								break;
							case 0x5:
								sprintf_s(cnv,"%08X",readui(addr+x->size));
								strcat_s(x->data, cnv);
								x->size += sizeof(unsigned int);
							break;
							default:
								strcat_s(x->data, _r32[i]);
							break;
						}
						strcat_s(x->data, "]");
						break;
					break;
				}
				if (skip){ // We are solving for the second operand
					if (src_r8op){	x->r8[1]=oldj; strcpy_s(second_op,_r8[oldj]); }
					if (src_r16op){ x->r16[1]=oldj; strcpy_s(second_op,_r16[oldj]); }
					if (src_r32op){ x->r32[1]=oldj; strcpy_s(second_op,_r32[oldj]); }
					if (src_rxop){ x->rxmm[1]=oldj; strcpy_s(second_op,_rx[oldj]); }
					strcat_s(x->data, ",");
					strcat_s(x->data, second_op);
				}
			} break;
		}


		// SECOND OPERAND
		// 
		// May already be configured in the
		// destination disassemble
		// 
		if (x->src == _m::single) {
			strcat_s(x->data,",");
			strcat_s(x->data,x->mark2);
		} else if (!skip && x->src != _m::none){
			strcat_s(x->data,",");

			switch (x->src) {
				// Check 8bit value on the next byte
				case _m::imm8:
					x->v8 = readb(addr+x->size);
					sprintf_s(cnv,"%02X",readb(addr+x->size));
					strcat_s(x->data,cnv);
					x->size += 1;
				break;
				// Check 16bit value on the next 2 bytes
				case _m::imm16:
					x->v16 = readus(addr+x->size);
					sprintf_s(cnv,"%04X",readus(addr+x->size));
					strcat_s(x->data,cnv);
					x->size += sizeof(unsigned short);
				break;
				// Check 32bit value on the next 4 bytes
				case _m::imm32:
					x->v32 = readui(addr+x->size);
					sprintf_s(cnv,"%08X",readui(addr+x->size));
					strcat_s(x->data,cnv);
					x->size += sizeof(unsigned int);
				break;

				case _m::rel8:
					x->v8 = readb(addr+x->size);
					sprintf_s(cnv,"%08X",(addr+x->size+1+(signed char)readb(addr+x->size)));
					strcat_s(x->data,cnv);
					x->size += 1;
				break;
				case _m::rel16:
					x->v16 = readus(addr+x->size);
					sprintf_s(cnv,"%04X",(addr+x->size+2+(signed short)readus(addr+x->size)));
					strcat_s(x->data,cnv);
					x->size += sizeof(unsigned short);
				break;
				case _m::rel32:
					x->v32 = readui(addr+x->size);
					sprintf_s(cnv,"%08X",(addr+x->size+4+(signed int)readui(addr+x->size)));
					strcat_s(x->data,cnv);
					x->size += sizeof(unsigned int);
				break;

				case _m::r8:
					strcat_s(x->data,_r8[oldj]);
				break;
				case _m::r16:
					strcat_s(x->data,_r16[oldj]);
				break;
				case _m::r32:
					strcat_s(x->data,_r32[oldj]);
				break;
				case _m::rxmm:
					strcat_s(x->data,_rx[oldj]);
				break;

				case _m::r_m8:
					x->size++;
					update();
					x->r32[0] = j;
					switch (mode40){
						case 0: // 0x00 through 0x3F
							switch (i){
								case 0x4:
									strcat_s(x->data,_r32[j]);
								break;
								case 0x5:
									strcat_s(x->data,_r32[(c-0x5)/8]);
									x->size++;
									x->src = _m::imm32;
								break;
								default:
									strcat_s(x->data,_r32[j]);
								break;
							}
						break;
						default: // 0x40-0xFF
							strcat_s(x->data,_r32[j]);
						break;
					}
				break;

				case _m::r_m16:
					x->size++;
					update();
					x->r32[0] = j;
					switch (mode40){
						case 0: // 0x00 through 0x3F
							switch (i){
								case 0x4:
									strcat_s(x->data,_r32[j]);
								break;
								case 0x5:
									strcat_s(x->data,_r32[(c-0x5)/8]);
									x->size++;
									x->src = _m::imm32;
								break;
								default:
									strcat_s(x->data,_r32[j]);
								break;
							}
						break;
						default: // 0x40-0xFF
							strcat_s(x->data,_r32[j]);
						break;
					}
				break;

				case _m::r_m32:
					x->r32[1] = j;
					switch (mode40){
						case 0: // 0x00 through 0x3F
							switch (i){
								case 0x4:
									strcat_s(x->data,_r32[j]);
								break;
								case 0x5:
									strcat_s(x->data,_r32[(c-0x5)/8]);
									x->src = _m::imm32;
								break;
								default:
									strcat_s(x->data,_r32[j]);
								break;
							}
						break;
						default: // 0x40-0xFF
							strcat_s(x->data,_r32[j]);
						break;
					}
				break;

				case _m::r_m:{
					// 32bit registers are used by default.
					// for example, if the first operand was xmm0,
					// the instruction could be mov xmm0,[eax+ebx+00].
					// 
					// If it is above 0xBF(0xC0+) we would use mov xmm?,xmm?
					// 
					unsigned char	dest_r8op =	(x->dest==r_m8),
							dest_r16op=	(x->dest==r_m16),
							dest_r32op= (x->dest==r_m32),
							dest_rxop =	(x->dest==r_mx);

					extend();
					x->r32[1] = i;
					switch (mode40){
						case 3: // 0xC0 through 0xFF		[op] eax,[eax]
							if (dest_rxop || strcmp(x->mark2,"qword ptr")==0)
								strcat_s(x->data, _rx[i]);
							else if (dest_r8op || strcmp(x->mark2,"byte ptr")==0)
								strcat_s(x->data, _r8[i]);
							else if (dest_r16op || strcmp(x->mark2,"word ptr")==0)
								strcat_s(x->data, _r16[i]);
							else
								strcat_s(x->data, _r32[i]);
						break;
						case 2: // 0x80 through 0xBF		[op] eax,[eax+eax*?+????????]
							check_mark();
							strcat_s(x->data, "[");
							switch(i){
								case 0x4:
									extend();
									x->r32[1] = i;
									strcat_s(x->data, _r32[i]);
									// 0x60 = [op] eax,[eax+00000000]
									// 0xA0 = [op] eax,[eax+00000000]
									// but, 0x80 = [op] eax,[eax+eax*4+00000000]
									//
									strcat_s(x->data, "+");
									strcat_s(x->data, _r32[j]);
									w_mult32();
								break;
								default:
									strcat_s(x->data, _r32[i]);
								break;
							}
							w_offset32();
							strcat_s(x->data, "]");
						break;
						case 1: // 0x40 through 0x7F		[op] eax,[eax+eax*?+??]
							check_mark();
							strcat_s(x->data, "[");
							switch(i){
								case 0x4:
									extend();
									x->r32[1] = i;
									strcat_s(x->data, _r32[i]);
									if (!(mode20%2!=0 && c%0x20<8)){
										strcat_s(x->data, "+");
										strcat_s(x->data, _r32[j]);
										w_mult32();
									}
								break;
								default:
									strcat_s(x->data, _r32[i]);
								break;
							}
							w_offset8();
							strcat_s(x->data, "]");
						break;
						case 0:
							check_mark();
							strcat_s(x->data, "[");
							switch(i){
								case 0x5:
									sprintf_s(cnv,"%08X",readui(addr+x->size));
									strcat_s(x->data, cnv);
									x->size += sizeof(unsigned int);
									break;
								case 0x4:
									extend();
									x->r32[1] = i;
									switch(i){
										case 0x5:
											if (mode20%2!=1){
												strcat_s(x->data, _r32[j]);
												w_mult32();
												w_offset32();
											} else {
												sprintf_s(cnv,"%08X",readui(addr+x->size));
												strcat_s(x->data, cnv);
												x->size += sizeof(unsigned int);
											}
										break;
										default:
											strcat_s(x->data, _r32[i]);
											if (mode20%2!=1){
												strcat_s(x->data, "+");
												strcat_s(x->data, _r32[j]);
												w_mult32();
											} else if (c%0x20>=8) {
												strcat_s(x->data, "+");
												strcat_s(x->data, _r32[j]);
												w_mult32();
											}
										break;
									}
								break;
								default:
									strcat_s(x->data, _r32[i]);
								break;
							}
							strcat_s(x->data, "]");
						break;
					}
				} break;
			}
		}
	}

	return x;
}

std::string EyeCrawl::disassemble(unsigned int start, unsigned int end, info_mode extra_info) {
	std::string str = "";
	if (proc == INVALID_HANDLE_VALUE) return str;

	//for (int n=0,s=0; n<count; n++) {
	for (int n=0,s=0; s<(end-start); n++){
		EyeCrawl::pinstruction i = EyeCrawl::disassemble(start+s);
		s += i->size;
		str += i->data;
		if (extra_info == show_offsets || extra_info == show_ioffsets){
			if (i->offset != 0) {
				char spaces[44];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces, " ");

				char c[4];
				if (extra_info == show_offsets)
					sprintf_s(c,"%02X",(unsigned char)i->offset);
				else if (extra_info == show_ioffsets)
					sprintf_s(c,"%i",(unsigned char)i->offset);
				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_int32){
			char spaces[44];
			spaces[0] = '\0';
			for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces, " ");

			char c[16];
			sprintf_s(c,"%i",i->v32);
			str += spaces;
			str += " // ";
			str += c;
		} else if (extra_info == show_args){
			if (strfind(i->data, "ebp+")){
				char spaces[44],c[8];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");

				sprintf_s(c,"arg_%i",(unsigned char)((i->offset-0x8)/0x4));
				str = replaceex(str,"ebp+??","....xx",c);
				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_vars){
			if (strfind(i->data, "ebp-")){
				char spaces[44],c[8];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");
				
				sprintf_s(c,"var_%i",(unsigned char)((UCHAR_MAX-i->offset-1)/0x4));
				str = replaceex(str,"ebp-??","....xx",c);
				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_args_and_vars){
			bool found_var = strfind(i->data, "ebp-");
			bool found_arg = strfind(i->data, "ebp+");
			if (found_var || found_arg){
				char spaces[44],c[8];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");
				
				if (found_var){
					sprintf_s(c,"var_%i",(unsigned char)((UCHAR_MAX-i->offset-1)/0x4));
					str = replaceex(str,"ebp-??","....xx",c);
				} else if (found_arg){
					sprintf_s(c,"arg_%i",(unsigned char)((i->offset-0x8)/0x4));
					str = replaceex(str,"ebp+??","....xx",c);
				}

				str += spaces;
				str += " // ";
				str += c;
			}
		} else if (extra_info == show_non_aslr){
			if (strfind(i->data, "call") ||
				strfind(i->data, "jmp")){
				char spaces[44],c[16];
				spaces[0] = '\0';
				for (int j=lstrlenA(i->data); j<44; j++) strcat_s(spaces," ");

				sprintf_s(c,"%08X",non_aslr(i->v32));
				str += spaces;
				str += " // ";
				str += c;
			}
		}
		str += "\n";
		delete i;
	}
	return str;
}



// Limited translator...
// multipliers/3-operand instructions are not currently supported
// First idea is disassembling backwards, via the x86 table already in place.
// this may have to be reconfigured to improve..
// 
int EyeCrawl::assemble(unsigned int &addr, std::string src){
	unsigned int old_addr = addr;
	std::string opcode = "";
	char c = 0;
	while (src[c] != 0x20) {
		opcode += src[c++];
	}
	c++;

	unsigned char i_lastreg = 0;
	auto nextregister = [&i_lastreg,&c,&src]() {
		for (int i=0; i<8; i++){
			if (src.substr(c,2) == std::string(_r8[i])){
				i_lastreg = i;
				return src.substr(c,2);
			}
			if (src.substr(c,2) == std::string(_r16[i])){
				i_lastreg = i;
				return src.substr(c,2);
			}
			if (src.substr(c,3) == std::string(_r32[i])){
				i_lastreg = i;
				return src.substr(c,3);
			}
		}
		return std::string("");
	};


	// Begin parsing...
	int _lookup = 0, _size, _i;
	int div = src.find(",");
	if (div != -1){
		std::string first_op	= src.substr(c, div - c);
		std::string second_op	= src.substr(div + 1, src.length() - (div + 1));
		bool o_first			= (first_op[0] == '['); // first operand uses offset?
		bool o_second			= (second_op[0] == '['); // second operand uses offset?

		// Calculate an offset of a register in the first operand...
		if (o_first) { // mov [ . . . ], eax
			c++; // skip [
			_m op1 = r_m; // fix this by checking if register used is 8bit/16bit
			_m op2 = r_m32;
			std::string r1 = nextregister();
			unsigned int v8 = 0;
			unsigned int v32 = 0;
			unsigned char i_r1 = i_lastreg, x = 0x00;

			if (r1.length() != 0){
				c += r1.length();
				
				bool do_offset = (src[c] != ']');
				if (do_offset) {
					char k = src[c++]; // k = Operator + / - / ??? (SKIPS)
					if (src[c+2] == ']'){		v8 = to_byte(src.substr(c,2).c_str()); x = 0x40; c += 2; if (k == '-') v8 = UCHAR_MAX+1-v8; }
					else if (src[c+8] == ']'){	v32= to_addr(src.substr(c,8).c_str()); x = 0x80; c += 8; if (k == '-') v32 = UINT_MAX+1-v32; }
				} else {						x = 0x00; }
				c++; // skip ]
			} else {
				// dealing with just an int value at the second operand
				c++;
				i_r1 = 0;
				x = 0x5;
				v32 = to_addr(src.substr(c, 8).c_str());
				c += 8;
			}

			c++; // skip ,
			std::string r2 = nextregister();
			unsigned char i_r2 = i_lastreg;
			
			for (_lookup; _lookup<sizeof(ref_x86)/sizeof(instruction_ref); _lookup++){
				if (opcode == std::string(ref_x86[_lookup].opcode) && ref_x86[_lookup].dest == op1 && ref_x86[_lookup].src == op2){
					unsigned char b1 = ref_x86[_lookup].bytes[0];
					unsigned char b2 = x + ((i_r2 * 8) + i_r1);
					write(addr++, b1);
					write(addr++, b2);
					if (v8)	{ write(addr, v8);  addr += sizeof(char); }
					if (v32){ write(addr, v32); addr += sizeof(int);  }
				}
			}
		// Calculate an offset of a register in the second operand
		} else if (o_second) { // mov eax, [ . . . ]
			// we will assume these are all 32-bit
			_m op1 = r_m32; // fix this by checking if register used is 8bit/16bit
			_m op2 = r_m;
			std::string r1 = nextregister();
			unsigned char i_r1 = i_lastreg, x = 0x00;
			c += r1.length() + 2; // skip , and [
			std::string s_o = "";
			std::string r2 = nextregister();
			unsigned char i_r2 = i_lastreg;

			unsigned int v8 = 0;
			unsigned int v32 = 0;

			if (r2.length() != 0){
				c += r2.length();
				
				bool do_offset = (src[c] != ']');
				if (do_offset) {
					char k = src[c++]; // k = Operator + / - / ??? (SKIPS)
					if (src[c+2] == ']'){		v8 = to_byte(src.substr(c,2).c_str()); x = 0x40; if (k == '-') v8 = UCHAR_MAX+1-v8; }
					else if (src[c+8] == ']'){	v32= to_addr(src.substr(c,8).c_str()); x = 0x80; if (k == '-') v32 = UINT_MAX+1-v32; }
				} else {						x = 0x00; }
			} else {
				// dealing with just an int value at the second operand
				i_r2 = 0;
				x = 0x5;
				v32 = to_addr(src.substr(c, 8).c_str());
			}
					
			for (_lookup; _lookup<sizeof(ref_x86)/sizeof(instruction_ref); _lookup++){
				if (opcode == std::string(ref_x86[_lookup].opcode) && ref_x86[_lookup].dest == op1 && ref_x86[_lookup].src == op2){
					unsigned char b1 = ref_x86[_lookup].bytes[0];
					unsigned char b2 = x + ((i_r1 * 8) + i_r2);
					write(addr++, b1);
					write(addr++, b2);
					if (v8)	{ write(addr, v8);  addr += sizeof(char); }
					if (v32){ write(addr, v32); addr += sizeof(int);  }
				}
			}
		} else { // mov eax, eax
			_m op1 = r_m32; // fix this by checking if register used is 8bit/16bit
			_m op2 = r_m;
			std::string r1 = nextregister();
			unsigned char i_r1 = i_lastreg;
			c += r1.length() + 1; // skip only the ,
			unsigned char x = 0xC0;
			std::string s_o = "";
			std::string r2 = nextregister();
			unsigned char i_r2 = i_lastreg;

			for (_lookup; _lookup<sizeof(ref_x86)/sizeof(instruction_ref); _lookup++){
				if (opcode == std::string(ref_x86[_lookup].opcode) && ref_x86[_lookup].dest == op1 && ref_x86[_lookup].src == op2){
					unsigned char b1 = ref_x86[_lookup].bytes[0];
					unsigned char b2 = x + ((i_r1 * 8) + i_r2);
					write(addr++, b1);
					write(addr++, b2);
				}
			}
		}
	} else { // single/none operand

		// Basically every other operand....NOT IMPLEMENTED YET
		// Will probably require separate/custom implementation,
		// apart from the x86 reference table.

		_m op1 = none;
		_m op2 = none;

		// Convert rel instructions to a single type (a single byte determines this)
		for (int i=0; i<16; i++){
			if (opcode.substr(1,opcode.length()-1) == std::string(_cond[i])){
				opcode = "j[c]";
				break;
			}
		}

		// check for r32, imm8, imm16, imm32, check for '[' first, etc.
		for (_lookup; _lookup<sizeof(ref_x86)/sizeof(instruction_ref); _lookup++){
			if (opcode == std::string(ref_x86[_lookup].opcode) && ref_x86[_lookup].dest == op1 && ref_x86[_lookup].src == op2){
				unsigned char b1 = ref_x86[_lookup].bytes[0];
				write(addr++, b1);
			}
		}
	}
	return addr - old_addr;
}




// ----------------------------------------------------------
// --------------- EyeCrawl Memory Managing -----------------
// ----------------------------------------------------------

unsigned char EyeCrawl::to_byte(const char* x) {
	if (lstrlenA(x)<2) return 0;
	if (x[0]=='?' && x[1]=='?') return 0;
	unsigned char b = 0;
	for (int i=0;i<16;i++){
		if (x[0]==c_ref1[i]) b+=c_ref2[i]*16;
		if (x[1]==c_ref1[i]) b+=i;
	}
	return b;
}

unsigned int EyeCrawl::to_addr(const char* non_hex_addr){
	unsigned int addr = 0;
	std::istringstream reader(non_hex_addr);
	reader >> std::hex >> addr;
	return addr;
}

std::string EyeCrawl::to_str(unsigned char b) {
	std::string x = "";
	x += c_ref1[b/16];
	x += c_ref1[b%16];
	return x;
}

std::string EyeCrawl::to_str(unsigned int address) {
	std::string str = "";
	char c[16];
	sprintf_s(c, "%08X", address);
	str += c;
	return str;
}

// 0xDEADBEEF --> "EF BE AD DE"
std::string EyeCrawl::to_bytes(unsigned int addr){
	std::string str = to_str(addr);
	std::string le	= "";
	le += str[6],le += str[7];
	le += str[4],le += str[5];
	le += str[2],le += str[3];
	le += str[0],le += str[1];
	return le;
}

// "Test" --> "64 3F 20 91" (those were made up, but that's the idea)
// If you're scanning a string,
// convert it to an AOB string first, using this.
// 
std::string EyeCrawl::to_bytes(const char* str){
	std::string bytes = "";
	for (int i = 0; i < lstrlenA(str); i++){
		unsigned char c = str[i];
		if (i == lstrlenA(str) - 1)
			bytes += to_str(c);
		else {
			bytes += to_str(c);
			bytes += 0x20;
		}
	}
	return bytes;
}

short EyeCrawl::to_short(unsigned char b1, unsigned char b2){
	short v = 0;
	v = b2;
	v <<= 8;
	v |= b1;
	return v;
}

int EyeCrawl::to_int(unsigned char b1, unsigned char b2, unsigned char b3, unsigned char b4){
	return int ((unsigned char)(b1) << 24 |
				(unsigned char)(b2) << 16 |
				(unsigned char)(b3) << 8  |
				(unsigned char)(b4));
}

unsigned int EyeCrawl::pbtodw(unsigned char* b){
	return		(b[0])		 |
				(b[1] << 8)	 |
				(b[2] << 16) |
				(b[3] << 24);
}

unsigned char* EyeCrawl::dwtopb(unsigned int v) {
	unsigned char* data = new unsigned char[sizeof(unsigned int)];
	memcpy(data, &v, sizeof(unsigned int));
	return data;
}

unsigned char EyeCrawl::cbyte::at(int index) {
	if (index < bytes.size() && index >= 0){
		return bytes[index];
	} else {
		throw std::exception("BAD CBYTE INDEX\n");
		return 0;
	}
}

void EyeCrawl::cbyte::add(unsigned char b) {
	bytes.push_back(b);
}

size_t EyeCrawl::cbyte::size() {
	return bytes.size();
}

std::string EyeCrawl::cbyte::to_string(){
	std::string str = "";
	for (int i=0; i<bytes.size(); i++){
		str += to_str(bytes[i]);
		if (i!=(size()-1))
			str += ", ";
		else
			str += ".";
	}
	return str;
};

EyeCrawl::cbyte::cbyte(){
	bytes = std::vector<unsigned char>();
};

EyeCrawl::cbyte::cbyte(std::string saob) {
	bytes = std::vector<unsigned char>();
	std::string newstr = "";
	for (char c : saob){
		if (c != 0x20){
			newstr += c;
		}
	}
	if (newstr.length()/2>0 && newstr.length()%2==0){
		for (int i=0; i<newstr.length(); i+=2){
			char s[3];
			s[0] = newstr[i];
			s[1] = newstr[i+1];
			s[2] = '\0';
			add(to_byte(s));
		}
	}
}

EyeCrawl::cbyte::cbyte(unsigned char* xbytes) {
	bytes = std::vector<unsigned char>();
	if (sizeof(xbytes) > 0){
		for (int i=0; i<sizeof(xbytes); i++){
			add(xbytes[i]);
		}
	}
}

// -----------------------------------------------------------
// --------------- EyeCrawl Memory Utilities -----------------
// -----------------------------------------------------------

// Allocates [size] number of bytes
// with READWRITE_EXECUTE privileges
unsigned int EyeCrawl::util::valloc(unsigned long size, unsigned long protect) {
	if (DLL_MODE)
		return reinterpret_cast<unsigned int>(VirtualAlloc(reinterpret_cast<void*>(0), size, 0x1000|0x2000, protect));
	else
		return reinterpret_cast<unsigned int>(VirtualAllocEx(proc, reinterpret_cast<void*>(0), size, 0x1000|0x2000, protect));
}

bool EyeCrawl::util::vfree(unsigned int address, unsigned long size) {
	if (DLL_MODE)
		return VirtualFree(reinterpret_cast<void*>(address), size, MEM_RELEASE);
	else
		return VirtualFreeEx(proc, reinterpret_cast<void*>(address), size, MEM_RELEASE);
}

// Strictly for external applications
HANDLE EyeCrawl::util::startthread(unsigned int func_address) {
	return CreateRemoteThread(proc,0,0,(LPTHREAD_START_ROUTINE)func_address,0,0,0);
}

// Strictly for external applications
void EyeCrawl::util::startthreadasync(unsigned int func_address,int max_wait) {
	HANDLE hThread = startthread(func_address);
	WaitForSingleObject(hThread,(unsigned int)max_wait);
	CloseHandle(hThread);
}

// Allocates a string in another processes memory.
// Remember to use freestr to free the string
// at this location when you are finished, just
// as you would use delete[] normally.
// 
unsigned int EyeCrawl::util::newstr(std::string str){
	unsigned int loc = valloc(((str.length()/4)+1)*4,PAGE_READWRITE);
	write(loc,str);
	return loc;
}

// Frees a string from another processes memory
bool EyeCrawl::util::freestr(unsigned int location){
	std::string str = sreads(location);
	return vfree(location,((str.length()/4)+1)*4);
}

RESULTS __fastcall EyeCrawl::util::scan(unsigned int begin, unsigned int end, const char* aob, const char* _mask) {
	char		   wildchar = 'x'; // otherwise '.' or anything else
	
	HANDLE			   self = GetCurrentProcess();
	int			oldpriority	= GetThreadPriority(self);
	if (!DLL_MODE) SetThreadPriority(self, THREAD_PRIORITY_HIGHEST);

	unsigned char*   buffer	= new unsigned char[default_chunksize];
	RESULTS	   results_list	= RESULTS();
	unsigned int	  start = begin,
						 at = 0;
	cbyte			   data	= cbyte(aob);
	int				   size = data.size();

	// Create mask for AOB if string is empty
	char mask[256];
	mask[0] = '\0';
	if (lstrlenA(_mask) == 0) {
		for (int i = 0; i < size; i++){
			strcat(mask, ".");
		}
	} else {
		strcpy(mask, _mask);
	}
	mask[size] = '\0';

#if !defined(_WIN64)
	while (start < end){
		bool read = true;
		if (DLL_MODE){
			memcpy(buffer, reinterpret_cast<void*>(start), default_chunksize);
		} else {
			read = PMREAD(proc,reinterpret_cast<void*>(start),buffer,default_chunksize,0);
		}
		if (read){
			__asm push edi
			__asm mov edi,0
			__asm jmp L2
		L1:	__asm inc edi
			__asm mov at,edi
			unsigned char match=1;
			for (unsigned int x=0; x<size; x++)
				if (buffer[at+x]!=data.bytes[x] && mask[x]!=wildchar)
					match=0;
			if (match) results_list.push_back(start+at);
		L2:	__asm cmp edi,default_chunksize
			__asm jb L1
			__asm pop edi
		}
		start += (default_chunksize - size) + 1;
	}
#endif
	delete[] buffer;
	
	if (!DLL_MODE) SetThreadPriority(self, oldpriority);
	return results_list;
}

RESULTS __fastcall EyeCrawl::util::scanpointer(unsigned int address){
	return util::scan(base_start(), base_end(), to_bytes(address).c_str(), "....");
}

RESULTS __fastcall EyeCrawl::util::scanxrefs(unsigned int begin, unsigned int to, unsigned int func){
	unsigned int start		= begin;
	unsigned int end		= to;
	bool found				= false;
	RESULTS xrefs			= RESULTS();
	unsigned char* buffer	= new unsigned char[default_chunksize];
	while (start < end && start < base_end()){
		bool read = true;
		if (DLL_MODE){
			memcpy(buffer, reinterpret_cast<void*>(start), default_chunksize);
		} else {
			read = PMREAD(proc,reinterpret_cast<void*>(start),buffer,default_chunksize,0);
		}
		if (read){
			for (int i=0; i<default_chunksize; i++){
				if (readb(start+i) == 0xE8){ // call instruction
					// calculate relative offset
					unsigned int o = readi(start+i+1);
					if (start+i+5+o == func){
						xrefs.push_back(start+i);
						found = true;
						break;
					}
					i += 4;
				}
			}
		}
		if (found) break;
		start += default_chunksize - 5;
	}
	delete[] buffer;
	return xrefs;
}

RESULTS __fastcall EyeCrawl::util::scanxrefs(unsigned int func, long dist) {
	unsigned int start	= (func - dist);
	unsigned int end	= (func + dist);
	if (start < base_start()) start	= base_start();
	if (end > base_end())	  end	= base_end();
	return EyeCrawl::util::scanxrefs(start, end, func);
}


// Simply identifies 3 different function
// prologues that are most commonly used.
// 
// Obviously will not work on a naked
// function
// 
bool EyeCrawl::util::isprologue(unsigned int address) {
	unsigned char	b1 = readb(address),
					b2 = readb(address+1),
					b3 = readb(address+2);

	bool check1 = (b1==0x55 && b2==0x8B && b3==0xEC);
	if (check1) return true;

	bool check2 = (b1==0x56 && b2==0x8B && b3==0xF1);
	if (check2){
		for (int i = 0; i < 0xFFFF; i++) {
			unsigned int at = (address + i);
			if (readb(at) == 0x5E && (readb(at+1) == 0xC3 || readb(at+1) == 0xC2)){
				return true;
			}
		}
	}

	//(b1==0x56 && b2==0x8B && b3==0xF1) ||
	//(b1==0x53 && b2==0x8B && b3==0xDC);
	return false;
}

// This doesnt even require disassembly
// Lol
bool EyeCrawl::util::isepilogue(unsigned int address) {
	unsigned char b1 = readb(address);
	unsigned char b2 = readb(address+1);
	return ((b1==0x5D || b1==0x5E) && // pop ebp, or pop esi,
			(b2==0xC2 || b2==0xC3));  // with a retn or ret XX
}

unsigned int EyeCrawl::util::nextprologue(unsigned int address, dir direction, bool aligned){
	unsigned int at = address, count = 0;
	// Skip this prologue if we're already at one
	if (isprologue(at)){
		if (direction == behind) at -= 16;
		if (direction == ahead)  at += 16;
	}
	while (!isprologue(at)){
		if (count++ > 0xFFFF) break;
		if (direction == ahead)  if (!aligned) at++; else at += 16;
		if (direction == behind) if (!aligned) at--; else at -= 16;
	}
	return at;
}

unsigned int EyeCrawl::util::nextepilogue(unsigned int address, dir direction){
	unsigned int at=address,count=0;
	while (!isepilogue(at)){
		if (count++ > 0xFFFF) break;
		if (direction == dir::ahead)  at++;
		if (direction == dir::behind) at--;
	}
	return at+1; // Return the functions retn address
}

unsigned int EyeCrawl::util::getprologue(unsigned int addr) {
	return nextprologue(addr, behind, false);
}

RESULTS EyeCrawl::util::getprologues(unsigned int func, dir direction, int count) {
	RESULTS result_list = RESULTS();
	unsigned int addr = func, current = 0;
	while (current < count){
		addr = nextprologue(addr, direction, true);
		result_list.push_back(addr);
		current++;
	}
	return result_list;
}

// go forward to the next function, then
// go backwards from there till we reach
// the last epilogue of the current function
unsigned int EyeCrawl::util::getepilogue(unsigned int func) {
	return nextepilogue(nextprologue(func, ahead, true), behind);
}

short EyeCrawl::util::fretn(unsigned int func) {
	for (unsigned int addr : getepilogues(func)) {
		if (readb(addr) == 0xC2) {
			pinstruction i = disassemble(addr);
			short v = i->v16;
			delete i;
			return v;
		}
	}
	return 0;
}

int EyeCrawl::util::fsize(unsigned int func) {
	unsigned int eof = nextprologue(func, ahead, true);
	//unsigned int eof = getepilogue(func);
	//if (readb(eof) == 0xC2) eof += 3;
	//if (readb(eof) == 0xC3) eof += 1;
	int funcSz = static_cast<int>(eof - func);
	if (funcSz < 0) return 0;
	return funcSz;
}

RESULTS EyeCrawl::util::getepilogues(unsigned int func) {
	RESULTS r = RESULTS();
	unsigned int start = func;
	unsigned int end = (start + fsize(func));
	while (start < end) {
		if (isepilogue(start)){
			r.push_back(start+1);
		}
		start++;
	}
	return r;
}

RESULTS EyeCrawl::util::getcalls(unsigned int func) {
	RESULTS r = RESULTS();
	unsigned int start = func;
	unsigned int end = (func + fsize(func));
	while (start < end) {
		if (readb(start) == 0xE8){
			unsigned int o = (start+readui(start+1)+5);
			if (o%16==0 && o>base_start() && o<base_end()){
				r.push_back(o);
			}
		}
		start++;
	}
	return r;
}

RESULTS EyeCrawl::util::getpointers(unsigned int func) {
	RESULTS r = RESULTS();
	unsigned int start = func;
	unsigned int end = (func + fsize(func));
	while (start < end) {
		pinstruction i = disassemble(start);
		if (readb(start) != 0xE8 && readb(start) != 0xE9){
			if (i->v32%4==0 && i->v32>base_start() && i->v32<base_end())
				r.push_back(i->v32);
			if (i->offset%4==0 && i->offset>base_start() && i->offset<base_end())
				r.push_back(i->offset);
		}
		start += i->size;
		delete i;
	}
	return r;
}

unsigned int EyeCrawl::util::nextcall(unsigned int func, dir d, bool loc){
	unsigned int start = func;
	// Skip current call if we're already at one
	if (readb(start) == 0xE8){
		if (d == ahead)  start++;
		if (d == behind) start--;
	}
	while (readb(start) != 0xE8){
		if (d == ahead)  start++;
		if (d == behind) start--;
	}
	unsigned int o = (start+readui(start+1)+5);
	if (o%16==0 && o>base_start() && o<base_end())
		if (!loc)
			return o;
		else
			return start;
	return 0;
}

EyeCrawl::util::MEM_PROTECT EyeCrawl::util::vprotect(unsigned int location, unsigned long size) {
	MEM_PROTECT mp = MEM_PROTECT();
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	VirtualQueryEx(proc,reinterpret_cast<void*>(location),&mbi,sizeof(mbi));
	VirtualProtectEx(proc,mbi.BaseAddress,size,PAGE_READWRITE,&mbi.Protect);
	mp.address = location;
	mp.size = size;
	mp.protection_data = mbi;
	return mp;
}

void EyeCrawl::util::vrestore(MEM_PROTECT protection) {
	DWORD oldProtect;
	VirtualProtectEx(proc,protection.protection_data.BaseAddress,protection.size,protection.protection_data.Protect,&oldProtect);
}

std::string EyeCrawl::util::calltype(unsigned int func) {
	std::string			convention = "unknown";
	unsigned int		at = func,
						eof = (func+fsize(func)),
						cleanup = fretn(func);
	if (cleanup==0)		convention = "cdecl";
	else if (cleanup>0)	convention = "stdcall";
	std::string			old_convention = convention;
	
	// Determine convention from within the function
	// (shouldn't've been that inaccurate tbh but it was RIP)
	/*unsigned int		cur_instr = 0;
	bool				local_stack = false,
						ecx = false, edx = false,
						ecx_abused = false,
						edx_abused = false;

	std::vector<unsigned char>vars = {}, args = {};

	while (at < eof){
		cur_instr++;
		pinstruction i = disassemble(at);
		if (strcmp(i->data,"push ecx") == 0)	ecx=true;
		if (strcmp(i->data,"push edx") == 0)	edx=true;
		if (i->r32[0] == R_ECX)					ecx=true;
		if (i->r32[0] == R_EDX)					edx=true;
		if (i->r32[0] == R_ECX && !ecx_abused)	convention = old_convention;
		if (i->r32[0] == R_EDX && !edx_abused)	return old_convention;

		if (strcmp(i->data,"pop ecx") == 0){	ecx=false,ecx_abused=false; }
		if (strcmp(i->data,"pop edx") == 0){	edx=false,edx_abused=false; }
		if (i->r32[1] == R_ECX && !ecx){		ecx_abused=true; }
		if (i->r32[1] == R_EDX && !edx){		edx_abused=true; }
		
		if (cur_instr == 3){
			if (strcmp(i->data,"mov ecx,ecx") == 0 && !ecx)
				ecx_abused=true;
			else if (strcmp(i->data,"mov edx,edx") == 0 && !edx)
				edx_abused=true;
			else {
				if (strfind(i->data,"ecx,ecx")) ecx=false,ecx_abused=false;
				if (strfind(i->data,"edx,edx")) edx=false,edx_abused=false;
			}
			if (strfind(i->data,"sub esp"))
				if (i->v8 == 0x10)
					local_stack=true;
		}

		if (cur_instr <= 10)
			if (edx_abused)
				return "fastcall";

		if (local_stack){
			if (i->r32[0] == R_EBP || i->r32[1] == R_EBP){
				unsigned char var = (unsigned char)(256-i->offset);
				if (i->offset >= 0x80 && var >= 0x8){
					bool found = false;
					for (unsigned char x : vars){
						found = (x == var);
						if (found) break;
					}
					if (!found) vars.push_back(var);
				}
			}
		}

		if (i->r32[0] == R_EBP || i->r32[1] == R_EBP){
			unsigned char arg = (unsigned char)(i->offset);
			if (arg >= 0x4 && arg <= 0x80){
				bool found = false;
				for (unsigned char x : args){
					found = (x == arg);
					if (found) break;
				}
				if (!found) args.push_back(arg);
			}
		}

		at += i->size;
		delete i;
	}

	if (ecx_abused) convention = "fastcall";
	if (edx_abused) convention = "fastcall";// old_convention;
	//if (args.size() == 2 && convention == "fastcall")
	//	convention = old_convention;*/

	// Cross reference check to
	// assure accuracy with what we determined
	// within the function
	/*const int scanbuffer	= (64*64*32);
	unsigned int start		= (func-(scanbuffer*2));
	unsigned int end		= (func+(scanbuffer*2));
	bool found				= false;
	RESULTS xrefs			= RESULTS();
	unsigned char* buffer	= new unsigned char[scanbuffer];
	while (start < end){
		if (PMREAD(proc,reinterpret_cast<void*>(start),buffer,scanbuffer,0)){
			for (int i=0; i<scanbuffer; i++){
				if (readb(start+i) == 0xE8){
					unsigned int o = readi(start+i+1);
					if (start+i+5+o == func){
						xrefs.push_back(start+i);
						found = true;
						break;
					}
					i += 4;
				}
			}
		}
		if (found) break;
		start += scanbuffer;
	}
	delete[] buffer;*/
	RESULTS xrefs = scanxrefs(func, default_scansize / 4);

	for (unsigned int location : xrefs) {
		/*pinstruction i;
		i = disassemble(location - 2);
		if (i->size == 2){
			if (strfind(i->data,"ecx,") && !strfind(i->data,"push dword ptr") && convention != "fastcall")
				convention = "fastcall";
			if (strfind(i->data,"edx,"))
				convention = "fastcall";
		}
		delete i;
		i = disassemble(location - 5);
		if (i->size == 5){
			if (strfind(i->data,"ecx,") && convention != "fastcall")
				convention = "fastcall";
			if (strfind(i->data,"edx,"))
				convention = "fastcall";
		}
		delete i;*/

		unsigned char b = readb(location - 1);
		if (b == 0x50 ||
			b == 0x51 ||
			b == 0x52 ||
			b == 0x53 ||
			b == 0x56 ||
			b == 0x57){
			convention = old_convention;
			break;
		}

		// Cross reference
		at = nextcall(location, behind, true) + 5;
		if (at < nextprologue(location, behind, false))
			at = nextprologue(location, behind, false) + 3;

		while (at < location){
			pinstruction i = disassemble(at);
			if (at < location - 16){
				at += i->size;
				delete i;
				continue;
			}
			
			if ((strfind(i->data,"mov ecx") ||
				 strfind(i->data,"or ecx")) &&
				 convention != "fastcall")
				convention = "thiscall";
			if (strfind(i->data,"mov edx") ||
				strfind(i->data,"or edx"))
				convention = "fastcall";

			if (strcmp(i->data,"push ecx") == 0 ||
				strcmp(i->data,"pop ecx") == 0 ||
				strcmp(i->data,"push edx") == 0 ||
				strcmp(i->data,"pop edx") == 0)
				convention = old_convention;
			at += i->size;
			delete i;
		}

		break;
	}

	return convention;
}


unsigned int EyeCrawl::util::debug32(unsigned int address, unsigned char r32, int offset) {
	unsigned long size=5,nop=0,isize=0,d=0;
	unsigned int value=0,at=0,mask=0xABCDEF,
			 code_loc=valloc(48,PAGE_EXECUTE_READWRITE),
			 trace_loc=valloc(4,PAGE_READWRITE);

	// Figure out how many left over bytes
	// from an instruction we might overwrite
	// 
	pinstruction i;
	i = disassemble(address);
	while (i->address<(address+size)){
		isize += i->size;
		nop = ((i->address+i->size)-(address+size));
		free(i);
		i = disassemble(address+isize);
	}
	free(i);

	// Get current bytes + bytes from
	// instruction we might overwrite
	unsigned char* old_bytes = new unsigned char[size+nop];
	if (DLL_MODE)
		*(unsigned char**)address = old_bytes;
	else
		PMREAD(proc,reinterpret_cast<void*>(address),old_bytes,size+nop,0);

	// Make up our JMP from the address
	// to our own code
	unsigned char* inject = new unsigned char[5];
	memcpy(inject,"\xE9",1);
	*(unsigned int*)(inject+1)=(code_loc-(address+5));

	if (offset == 0){
		// simply place one instruction to capture 
		// the value of the register to our readout location
		write(code_loc+at++, static_cast<unsigned char>(0x50+r32)); // push (r32)
		switch (r32) {
			case R_EAX:
				write(code_loc+at++, static_cast<unsigned char>(0xA3));
				break;
			default:
				write(code_loc+at++, static_cast<unsigned char>(0x89)); // ecx-edi (0xD,0x15,0x1D,0x25,0x2D . . .)
				write(code_loc+at++, static_cast<unsigned char>(0x5+(r32*8)));
			break;
		}
		// Trace register to our trace location
		write(code_loc+at, trace_loc);
		at += 4;
		write(code_loc+at++, static_cast<unsigned char>(0x58+r32)); // pop (r32)
	} else {
		// or, if we want an offset of a register ...
		// move the offset into EAX and show the value of EAX
		// at our readout location
		write(code_loc+at++, static_cast<unsigned char>(0x50)); // push eax
		write(code_loc+at++, static_cast<unsigned char>(0x8B));
		if (offset > UCHAR_MAX){
			if (r32 != R_ESP)
				write(code_loc+at++, static_cast<unsigned char>(0x80+r32));
			else {
				write(code_loc+at++, static_cast<unsigned char>(0x84));
				write(code_loc+at++, static_cast<unsigned char>(0x24));
			}
			write(code_loc+at++, offset);
		} else {
			if (r32 != R_ESP)
				write(code_loc+at++, static_cast<unsigned char>(0x40+r32));
			else {
				write(code_loc+at++, static_cast<unsigned char>(0x44));
				write(code_loc+at++, static_cast<unsigned char>(0x24));
			}
			write(code_loc+at++, static_cast<unsigned char>(offset));
		}
		// Trace register to our trace location
		write(code_loc+at++, static_cast<unsigned char>(0xA3));
		write(code_loc+at, trace_loc);
		at += 4;
		write(code_loc+at++, static_cast<unsigned char>(0x58)); // pop eax
	}

	// Put overwritten bytes back (full instruction(s))
	if (DLL_MODE)
		*(unsigned char**)(code_loc + at) = old_bytes;
	else
		PMWRITE(proc,reinterpret_cast<void*>(code_loc + at),old_bytes,size+nop,0);
	at += (size+nop);

	// Place our JMP back
	write(code_loc+at++, static_cast<unsigned char>(0xE9));
	write(code_loc+at,(address+5)-(code_loc+at+4));
	at += 4;

	// causes debugging to delay until it reads a value from
	// the register. (thankfully, alot of functions are used
	// rapidly, so a fast hook can work w/ memcheck)
	// 
	write(trace_loc,mask);

	// Inject the JMP to our own code
	if (DLL_MODE)
		*(unsigned char**)address = inject;
	else
		PMWRITE(proc,reinterpret_cast<void*>(address),inject,size,0);
	for (int i=0; i<nop; i++) write(address+size+i, static_cast<unsigned char>(0x90));
	delete[] inject;

	// Wait for our masked value to be modified
	// This means something wrote to our location
	bool modified = false;
	while (modified == false){
		Sleep(1);
		value = readui(trace_loc);
		if (value != mask)
			modified = true;
		if (d++ > 0xFFFF) break; // dont debug for eternity
	}

	if (DLL_MODE)
		*(unsigned char**)address = old_bytes;
	else
		PMWRITE(proc,reinterpret_cast<void*>(address),old_bytes,size+nop,0);
	
	delete[] old_bytes;

	vfree(code_loc,48);
	vfree(trace_loc,4);
	return (value==mask)?0:value;
}

RESULTS EyeCrawl::util::debug32(unsigned int address, unsigned char r32) {
	RESULTS values=RESULTS();
	unsigned long size=5,nop=0,isize=0,d=0;
	unsigned int value=0,at=0,mask=0xABCDEF,
			 code_loc=valloc(256,PAGE_EXECUTE_READWRITE),
			 trace_loc=valloc(64,PAGE_READWRITE);

	// Figure out how many left over bytes
	// from an instruction we might overwrite
	// 
	pinstruction i;
	i = disassemble(address);
	while (i->address<(address+size)){
		isize += i->size;
		nop = ((i->address+i->size)-(address+size));
		free(i);
		i = disassemble(address+isize);
	}
	free(i);

	// Get current bytes + bytes from
	// instruction we might overwrite
	unsigned char* old_bytes = new unsigned char[size+nop];
	if (DLL_MODE)
		*(unsigned char**)address = old_bytes;
	else
		PMREAD(proc,reinterpret_cast<void*>(address),old_bytes,size+nop,0);

	// Make up our JMP from the address
	// to our own code
	unsigned char* inject = new unsigned char[5];
	memcpy(inject,"\xE9",1);
	*(unsigned int*)(inject+1)=(code_loc-(address+5));

	printf("%08X.\n", code_loc);
	write(code_loc+at++, static_cast<unsigned char>(0x50)); // push eax
	for (int i=0; i<64; i+=4){
		write(code_loc+at++, static_cast<unsigned char>(0x8B));
		if (r32 != R_ESP)
			write(code_loc+at++, static_cast<unsigned char>(0x80+r32));
		else {
			write(code_loc+at++, static_cast<unsigned char>(0x84));
			write(code_loc+at++, static_cast<unsigned char>(0x24));
		}
		write(code_loc+at, i);
		at += 4;
		
		// Trace register to our trace location
		write(code_loc+at++, static_cast<unsigned char>(0xA3));
		write(code_loc+at, (int)(trace_loc+i));
		at += 4;
	}
	write(code_loc+at++, static_cast<unsigned char>(0x58)); // pop eax

	// Put overwritten bytes back (full instruction(s))
	if (DLL_MODE)
		*(unsigned char**)(code_loc + at) = old_bytes;
	else
		PMWRITE(proc,reinterpret_cast<void*>(code_loc + at),old_bytes,size+nop,0);
	at += (size+nop);

	// Place our JMP back
	write(code_loc+at++, static_cast<unsigned char>(0xE9));
	write(code_loc+at,(address+5)-(code_loc+at+4));
	at += 4;

	// causes debugging to delay until it reads a value from
	// the register. (thankfully, alot of functions are used
	// rapidly, so a fast hook can work w/ memcheck)
	// 
	write(trace_loc,mask);

	// Inject the JMP to our own code
	if (DLL_MODE)
		*(unsigned char**)address = inject;
	else
		PMWRITE(proc,reinterpret_cast<void*>(address),inject,size,0);

	for (int i=0; i<nop; i++) write(address+size+i, static_cast<unsigned char>(0x90));
	delete[] inject;

	// Wait for our masked value to be modified
	// This means something wrote to our location
	bool modified = false;
	while (modified == false){
		Sleep(1);
		value = readui(trace_loc);
		if (value != mask)
			modified = true;
		if (d++ > 0xFFFF) break; // dont debug for eternity
	}

	for (int i=0; i<64; i+=4)
		values.push_back(readui(trace_loc+i));

	if (DLL_MODE)
		*(unsigned char**)address = old_bytes;
	else
		PMWRITE(proc,reinterpret_cast<void*>(address),old_bytes,size+nop,0);
	
	delete[] old_bytes;

	vfree(code_loc,256);
	vfree(trace_loc,64);
	return values;
}

std::string EyeCrawl::util::readout32(unsigned int addr, unsigned char r32){
	std::string data;
	RESULTS reg = EyeCrawl::util::debug32(addr, r32);
	int i = 0;
	for (unsigned int x : reg){
		char info[128];
		unsigned int ptr = readui(x);
		if (ptr>base_start() && ptr<0x3FFFFFFF && ptr%4==0)
			sprintf_s(info,"EBP+%02X = %08X - \"%s\"\n",i,x,sreads(ptr).c_str());
		else if (x>base_start() && x<0x3FFFFFFF && sreads(x).length()>=4)
			sprintf_s(info,"EBP+%02X = %08X - \"%s\"\n",i,x,sreads(ptr).c_str());
		else
			sprintf_s(info,"EBP+%02X = %08X - %i\n",i,x,x);
		data += info;
		i += 4;
	}
	return data;
}
