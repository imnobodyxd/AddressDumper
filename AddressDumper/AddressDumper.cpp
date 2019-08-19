#include <Windows.h>
#include <string>
#include <iostream>

//CREDITS TO STATIC FOR THE EYECRAWL API
//IT CAN BE FOUND HERE
//OPEN SOURCE AT
//https://github.com/thedoomed/EyeCrawl/
#include "eyecrawl.h"


std::vector<std::string> LoggedCFunctions;

void LogCFunction(std::string FunctionName, unsigned int Function) {
	std::vector<std::string>::iterator it = std::find(LoggedCFunctions.begin(), LoggedCFunctions.end(), FunctionName);
	if (it == LoggedCFunctions.cend()) {
		std::cout << "[" << FunctionName << "] - 0x" << EyeCrawl::to_str(EyeCrawl::non_aslr(Function)) << " - __" << EyeCrawl::util::calltype(Function) << "\n";
		LoggedCFunctions.push_back(FunctionName);
	}
}





int main()
{
	SetConsoleTitleA("Address Dumper | By Ringarang | Credits To Static");
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
	
	//FIXED MTLOCKED SCAN!!!
	
	unsigned int MTLockedScan = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("The metatable is locked").c_str(), ".......................")[0];
	unsigned int MTLockedResults = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(MTLockedScan)[1]);
	RESULTS MTCFunctions = EyeCrawl::util::getcalls(MTLockedResults);

	//because first func call is create table, it will be stored at 0
	LogCFunction("lua_createtable", MTCFunctions[0]);
	//MTLockedCFunctions[1] is create table aswell, so we won't bother logging it twice!

	LogCFunction("lua_pushstring", MTCFunctions[2]);
	LogCFunction("lua_setfield", MTCFunctions[3]);
	LogCFunction("lua_pushlstring", MTCFunctions[4]);
	LogCFunction("lua_pushvalue", MTCFunctions[5]);
	LogCFunction("lua_settable", MTCFunctions[6]);
	LogCFunction("lua_setmetatable", MTCFunctions[7]);
	LogCFunction("lua_replace", MTCFunctions[8]);
	
	
	
	//This scan below shows an example of how to use eyecrawl in better ways to minimise time taken by doing less big scans
	unsigned int LOADEDString = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("_LOADED").c_str(), ".......")[0];
	unsigned int LOADEDResults = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(LOADEDString)[0]);
	RESULTS LOADEDCFunctions = EyeCrawl::util::getcalls(LOADEDResults);


	LogCFunction("lua_getfield", LOADEDCFunctions[1]);
	LogCFunction("lua_settop", LOADEDCFunctions[2]);
	LogCFunction("lua_pushvalue", LOADEDCFunctions[4]);
	LogCFunction("lua_setfield", LOADEDCFunctions[5]);
	LogCFunction("lua_remove", LOADEDCFunctions[6]);
	LogCFunction("lua_insert", LOADEDCFunctions[7]);
	LogCFunction("index2adr", LOADEDCFunctions[8]);
	LogCFunction("lua_pushcclosure", LOADEDCFunctions[9]);



	//do a mini "jump" "scan" to the next location, specifying how many reults from the "jump" when we land we want to list and specifiying what direction
	RESULTS BeforeGetFieldCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[1], EyeCrawl::behind, 9);

	LogCFunction("lua_call", BeforeGetFieldCFunctions[6]);
	LogCFunction("lua_close", BeforeGetFieldCFunctions[4]);
	LogCFunction("lua_createtable", BeforeGetFieldCFunctions[1]);


	//another mini "jump" "scan" example, this time going forward
	RESULTS AfterPushValueCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[4], EyeCrawl::ahead, 7);
	LogCFunction("lua_rawget", AfterPushValueCFunctions[2]);
	LogCFunction("lua_rawgeti", AfterPushValueCFunctions[4]);
	LogCFunction("lua_rawset", AfterPushValueCFunctions[5]);
	LogCFunction("lua_rawseti", AfterPushValueCFunctions[6]);


	//Before pushvalue 
	RESULTS BeforePushValueCFunctions = EyeCrawl::util::getprologues(LOADEDCFunctions[4], EyeCrawl::behind, 8);

	LogCFunction("lua_pushlightuserdata", BeforePushValueCFunctions[5]);
	LogCFunction("lua_pushnil", BeforePushValueCFunctions[3]);
	LogCFunction("lua_pushnumber", BeforePushValueCFunctions[2]);
	LogCFunction("lua_pushstring", BeforePushValueCFunctions[1]);
	LogCFunction("lua_pushthread", BeforePushValueCFunctions[0]);

	//before pushcclosure
	RESULTS BeforePushCClosure = EyeCrawl::util::getprologues(LOADEDCFunctions[9], EyeCrawl::behind, 8);

	LogCFunction("lua_newthread", BeforePushCClosure[5]);
	LogCFunction("lua_newuserdata", BeforePushCClosure[4]);
	LogCFunction("lua_next", BeforePushCClosure[3]);
	LogCFunction("lua_objlen", BeforePushCClosure[2]);
	LogCFunction("lua_pcall", BeforePushCClosure[1]);
	LogCFunction("lua_pushboolean", BeforePushCClosure[0]);


	RESULTS BeforeSetField = EyeCrawl::util::getprologues(LOADEDCFunctions[5], EyeCrawl::behind, 2);
	LogCFunction("lua_resume", BeforeSetField[1]);


	RESULTS AfterSetField = EyeCrawl::util::getprologues(LOADEDCFunctions[5], EyeCrawl::ahead, 4);

	LogCFunction("lua_setmetatable", AfterSetField[2]);
	LogCFunction("lua_setreadonly", AfterSetField[3]);


	//SCVFTable Scan
	unsigned int SCScan = EyeCrawl::util::scan(EyeCrawl::base_start(), EyeCrawl::base_end(), EyeCrawl::to_bytes("Script Context").c_str(), "")[1];
	unsigned int SCScanResult = EyeCrawl::util::getprologue(EyeCrawl::util::scanpointer(SCScan)[0]);
	printf("ScriptContextVFTable: 0x%08X.\n", EyeCrawl::non_aslr(EyeCrawl::util::getpointers(SCScanResult)[2]));


	std::cout << "Success!\n";

	std::cout << "Credits To Static For His Beautiful EyeCrawl API!\n";
	std::cout << "https://github.com/thedoomed/EyeCrawl/ \n";

	system("PAUSE");
	return 0;


	//note: I hope this example served you well, and will help you in creating fully-fledged applications
	//such as dumpers as statics beautiful eyecrawl api can be used for A LOT more than just this
	//Keep in mind this is an example and please feel free to expand it and make it dump more offsets!
}

