#ifndef C_EYECRAWL_x86
#define C_EYECRAWL_x86
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <sstream>

#define RESULTS std::vector<unsigned int>
#define STR_READ_MAX 1024
#define PMREAD ReadProcessMemory
#define PMWRITE WriteProcessMemory
#define R_EAX 0
#define R_ECX 1
#define R_EDX 2
#define R_EBX 3
#define R_ESP 4
#define R_EBP 5
#define R_ESI 6
#define R_EDI 7

namespace EyeCrawl {
	// Use OpenProcess to get your handle if using on
	// a remote process.
	// Use open(NULL) if you are using a DLL!
	void open(HANDLE);
	HANDLE get();
	unsigned int base_start();
	unsigned int base_end();
	unsigned int aslr(unsigned int);
	unsigned int non_aslr(unsigned int);

	enum dir {
		ahead,
		behind
	};

	enum info_mode {
		show_none,
		show_offsets,
		show_ioffsets,
		show_int32,
		show_args,
		show_vars,
		show_args_and_vars,
		show_non_aslr
	};

	enum _m { // mnemonics
		none,
		single,
		cnd8,
		cnd16,
		cnd32,
		r_m,
		r8,
		r16,
		r32,
		r_m8,
		r_m16,
		r_m32,
		rel8,
		rel16,
		rel32,
		imm8,
		imm16,
		imm32,
		rxmm,
		r_mx,
	};

	struct instruction {
		_m dest;// first opcode
		_m src;	// second opcode (based off type)

		char opcode[16];// opcode name
		char data[128]; // full instruction text
		int r8[4]; // 8bit registers used in instruction
		int r16[4];// 16bit registers used in instruction
		int r32[4];// 32bit registers used in instruction
		int rxmm[4];// xmm/FPU registers used in instruction
		int size;
		int v8; // 8bit value moved into reg8/offset/etc.
		int v16;// 16bit value moved into reg16/offset/etc.
		int v32;// 32bit value moved into reg32/offset/etc.
		unsigned int offset;// offset value pulled from instruction if there is one
		unsigned int address;// current address of this instruction
		char mark1[16];// byte ptr/dword ptr/qword ptr for first operand
		char mark2[16];// same as above but will show for second operand

		instruction() {
			opcode[0] = '\0';
			data[0] = '\0';
			mark1[0] = '\0';
			mark2[0] = '\0';
			size = 0; // skip over
			offset = 0;
			v8 = 0;
			v16 = 0;
			v32 = 0;
			dest = none;
			src = none;
			address = 0;
		}
	};

	struct instruction_ref {
		unsigned char bytes[8];
		char opcode[16];
		int size;
		_m dest;
		_m src;
		char mark1[16];
		char mark2[16];
		int div;

		instruction_ref(std::vector<unsigned char>_bytes,int _div,const char* _opcode,_m _dest,_m _src,const char* _mark1,const char* _mark2){
			size	= _bytes.size();
			dest	= _dest;
			src		= _src;
			div		= _div;
			memcpy(bytes,_bytes.data(),size);
			strcpy_s(opcode, _opcode);
			strcpy_s(mark1, _mark1);
			strcpy_s(mark2, _mark2);
		}
	};

	struct cbyte {
		std::vector<unsigned char>bytes;
		cbyte();
		cbyte(std::string);
		cbyte(unsigned char*);
		void			add(unsigned char);
		unsigned char	at(int);
		size_t			size();
		std::string		to_string();
	};

	typedef instruction* pinstruction;
	int				assemble(unsigned int&, std::string);
	pinstruction	disassemble(unsigned int);
	std::string		disassemble(unsigned int, unsigned int, info_mode);
	std::string		to_str(unsigned int);
	std::string		to_str(unsigned char);
	std::string		to_bytes(const char*);
	std::string		to_bytes(unsigned int);
	unsigned char	to_byte(const char*);
	unsigned int	to_addr(const char*);
	short			to_short(unsigned char, unsigned char);
	int				to_int(unsigned char, unsigned char, unsigned char, unsigned char);
	unsigned int	pbtodw(unsigned char*);
	unsigned char*	dwtopb(unsigned int);

	// memory reading
	cbyte			readb(unsigned int, int);
	unsigned char	readb(unsigned int);
	char			readc(unsigned int);
	unsigned short	readus(unsigned int);
	short			reads(unsigned int);
	unsigned int	readui(unsigned int);
	int				readi(unsigned int);
	float			readf(unsigned int);
	double			readd(unsigned int);
	std::string		sreads(unsigned int); // Reads a string at the given address
	std::string		sreadb(unsigned int, int); // Returns [int] number of bytes as an AOB string
	std::vector<unsigned char>preadb(unsigned int, int);

	// memory writing
	bool write(unsigned int, cbyte);
	bool write(unsigned int, unsigned char);
	bool write(unsigned int, char);
	bool write(unsigned int, unsigned short);
	bool write(unsigned int, short);
	bool write(unsigned int, unsigned int);
	bool write(unsigned int, int);
	bool write(unsigned int, float);
	bool write(unsigned int, double);
	bool write(unsigned int, std::string);
	bool write(unsigned int, std::vector<unsigned char>);

	// Utilities for debugging/scanning/getting functions/etc.
	// WIP
	//
	namespace util {
		struct MEM_PROTECT {
			MEMORY_BASIC_INFORMATION protection_data;
			unsigned int address;
			unsigned long size;
		};

		// allocates virtual memory at a random location,
		// with the provided access
		unsigned int valloc(unsigned long, unsigned long);
		// frees allocated virtual memory
		bool vfree(unsigned int, unsigned long);

		// Grants EXECUTE_READWRITE access to a
		// location in memory
		MEM_PROTECT vprotect(unsigned int location, unsigned long size);
		// Restores page access to a location
		// in memory
		void vrestore(MEM_PROTECT protection);

		// used for identifying function marks
		bool isprologue(unsigned int);
		bool isepilogue(unsigned int);
		unsigned int getprologue(unsigned int);
		RESULTS getprologues(unsigned int, dir, int);
		unsigned int getepilogue(unsigned int);
		RESULTS getepilogues(unsigned int);
		unsigned int nextprologue(unsigned int, dir, bool);
		unsigned int nextepilogue(unsigned int, dir);

		short fretn(unsigned int);
		int fsize(unsigned int);
		RESULTS getcalls(unsigned int);

		// returns a list of all the pointers used in a function.
		// for example, in the script context function you'd see
		// mov dword ptr[ebx],sub_17xxxxx
		// and the vftable for script context is sub_17xxxxx.
		// this list would include that sub_17xxxxx, as well as
		// other pointers or offsets used in the function.
		RESULTS getpointers(unsigned int);

		// gets the next call instruction
		// and returns either the address of the call(loc=true)(starting at "E8 ?? ?? ?? ??")
		// or the function it's actually calling(loc=false)
		unsigned int nextcall(unsigned int, dir, bool loc = false);

		// Determines calling convention of a function
		std::string calltype(unsigned int);

		// Scans memory for an array of bytes (AOB)
		// Extremely efficient
		// Use base_start() and base_end()
		// for any x86-related scans
		// 
		RESULTS __fastcall scan(unsigned int, unsigned int, const char*, const char*);

		// scans for pointers to a value/string/etc.
		// returns the location(s) of whereever the string is used,
		// like in a push offset 0x[STR_ADDR] instruction,
		// in a function
		RESULTS __fastcall scanpointer(unsigned int);

		// scans for references/nearby calls made to this
		// function.
		// The second arg is the distance of how far it
		// will look for an XREF to this function.
		// For a speedy scan, (64*64*64) is recommended.
		RESULTS __fastcall scanxrefs(unsigned int, long dist = 0);
		RESULTS __fastcall scanxrefs(unsigned int from, unsigned int to, unsigned int func);

		// Reads the value of a 32bit register, or an
		// offset of the register, at the given address.
		// 
		// It does this via a hook, which gets swapped out
		// immediately afterwards
		// Instructions partially overwritten
		// are taken care of.
		// 
		unsigned int	debug32(unsigned int, unsigned char, int);
		RESULTS			debug32(unsigned int, unsigned char);
		std::string		readout32(unsigned int, unsigned char);

		// Remote-process functions
		// for assisting in external applications
		HANDLE			startthread(unsigned int);
		void			startthreadasync(unsigned int, int);
		unsigned int	newstr(std::string);
		bool			freestr(unsigned int);
	}
}

#endif 
