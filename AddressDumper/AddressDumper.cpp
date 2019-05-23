#include <Windows.h>
#include <string>
#include <iostream>

//CREDITS TO STATIC FOR THE EYECRAWL API
//IT CAN BE FOUND HERE
//OPEN SOURCE AT
//https://github.com/thedoomed/EyeCrawl/
#include "eyecrawl.h"




int main()
{
    std::cout << "Finding Roblox... ";

	HWND hWnd;
	HANDLE handle;
	unsigned long id = 0;
	hWnd = FindWindowA(NULL, "Roblox");
	GetWindowThreadProcessId(hWnd, &id);

	handle = OpenProcess(PROCESS_ALL_ACCESS, false, id);
	if (handle == INVALID_HANDLE_VALUE) {
		std::cout << "Failure!\n\n";
		std::cout << "Open Roblox!\n";
		system("PAUSE");
	}

	//else open the process as a handle
	std::cout << "Success!\n";
	//set eyecrawls target process to this handle
	EyeCrawl::open(handle);

	//begin scan

	std::cout << "Scanning...\n";

	unsigned int MTLockedScan = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("The metatable is locked").c_str(), ".......................")[0];
	//the string "The metatable is locked" one of the xrefs points too a giant cfunction which we can extract a load of addresses from easily.
	unsigned int PTR = 0;
	RESULTS MTLockedResults = EyeCrawl::util::scanpointer(MTLockedScan); //scan pointers
	for (unsigned int i : MTLockedResults) if (EyeCrawl::sreadb(i + 4, 2) == "56E8") PTR = i;
	//get all the c function calls in the area
	RESULTS MTLockedCFunctions = EyeCrawl::util::getcalls(EyeCrawl::util::getprologue(PTR));

	//because first func call is create table, it will be stored at 0
	std::cout << "[lua_createtable] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[0]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[0]) << "\n";

	//MTLockedCFunctions[1] is create table aswell, so we won't bother logging it twice!

	std::cout << "[lua_pushstring] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[2]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[2]) << "\n";
	std::cout << "[lua_setfield] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[3]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[3]) << "\n";
	std::cout << "[lua_pushlstring] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[4]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[4]) << "\n";
	std::cout << "[lua_pushvalue] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[5]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[5]) << "\n";
	std::cout << "[lua_settable] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[6]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[6]) << "\n";
	std::cout << "[lua_setmetatable] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[7]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[7]) << "\n";
	std::cout << "[lua_replace] - 0x" << EyeCrawl::non_aslr(MTLockedCFunctions[8]) << " - __" << EyeCrawl::util::calltype(MTLockedCFunctions[8]) << "\n";


	//This scan below shows an example of how to use eyecrawl in better ways to minimise time taken by doing less big scans
	unsigned int LOADEDString = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("_LOADED").c_str(), ".......")[0];
	unsigned int LOADEDResults = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(LOADEDString)[0]);

	RESULTS LOADEDCFunctions = EyeCrawl::util::getcalls(LOADEDResults);

	std::cout << "[lua_getfield] - 0x" << EyeCrawl::non_aslr(LOADEDCFunctions[1]) << " - __" << EyeCrawl::util::calltype(LOADEDCFunctions[1]) << "\n";
	std::cout << "[lua_settop] - 0x" << EyeCrawl::non_aslr(LOADEDCFunctions[2]) << " - __" << EyeCrawl::util::calltype(LOADEDCFunctions[2]) << "\n";
	std::cout << "[lua_remove] - 0x" << EyeCrawl::non_aslr(LOADEDCFunctions[6]) << " - __" << EyeCrawl::util::calltype(LOADEDCFunctions[6]) << "\n";
	std::cout << "[lua_pushcclosure] - 0x" << EyeCrawl::non_aslr(LOADEDCFunctions[9]) << " - __" << EyeCrawl::util::calltype(LOADEDCFunctions[9]) << "\n";

	//do a mini "jump" "scan" to the next location, specifying how many reults from the "jump" when we land we want to list and specifiying what direction
	RESULTS BeforeGetFieldCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[1], EyeCrawl::behind, 9);

	std::cout << "[lua_call] - 0x" << EyeCrawl::non_aslr(BeforeGetFieldCFunctions[6]) << " - __" << EyeCrawl::util::calltype(BeforeGetFieldCFunctions[6]) << "\n";

	//another mini "jump" "scan" example, this time going forward
	RESULTS AfterPushValueCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[4], EyeCrawl::ahead, 7);

	std::cout << "[lua_rawgeti] - 0x" << EyeCrawl::non_aslr(AfterPushValueCFunctions[4]) << " - __" << EyeCrawl::util::calltype(AfterPushValueCFunctions[4]) << "\n";
	std::cout << "[lua_rawseti] - 0x" << EyeCrawl::non_aslr(AfterPushValueCFunctions[6]) << " - __" << EyeCrawl::util::calltype(AfterPushValueCFunctions[6]) << "\n";

	//SCVFTable Scan
	unsigned int SCScan = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("Script Context").c_str(), "")[1];
	unsigned int SCScanResult = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(SCScan)[0]);
	printf("ScriptContextVFTable: %08X.\n", EyeCrawl::non_aslr(EyeCrawl::util::getpointers(SCScanResult)[2]));

	std::cout << "Success!\n";

	std::cout << "Credits To Static For His Beautiful EyeCrawl API!\n";
	std::cout << "https://github.com/thedoomed/EyeCrawl/ \n";

	system("PAUSE");
	return 0;


	//note: I hope this example served you well, and will help you in creating fully-fledged applications
	//such as dumpers as statics beautiful eyecrawl api can be used for A LOT more than just this
	//Keep in mind this is an example and please feel free to expand it and make it dump more offsets!
}

