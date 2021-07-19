#include <Windows.h>
#include <tlhelp32.h>
#include <DbgHelp.h>
#pragma comment(lib,"dbghelp.lib")

#include <string>
#include <codecvt>
#include <format>
#include <thread>
#include <fstream>
#include <filesystem>



#if (_WIN32 || _WIN64) && !(defined(PLATFORM_X64) || defined(PLATFORM_X86))
#if _WIN64
#define PLATFORM_X64
#else
#define PLATFORM_X86
#endif
#endif



using namespace std::chrono_literals;
namespace fs = std::filesystem;

[[noreturn]] void FatalError(const std::string& content)
{
	MessageBoxA(
		nullptr,
		content.c_str(),
		"Telegram-Anti-Revoke Launcher",
		MB_ICONERROR
	);

	std::exit(1);
}

void VerboseMsg(const std::string& content)
{
	MessageBoxA(
		nullptr,
		content.c_str(),
		"Telegram-Anti-Revoke Launcher",
		MB_ICONINFORMATION
	);
}

std::wstring ToLower(std::wstring source)
{
	std::transform(source.begin(), source.end(), source.begin(), tolower);
	return source;
}

std::string WStringToString(std::wstring a)
{
	DWORD newsize = WideCharToMultiByte(54936, 0, a.c_str(), (int)a.length(), nullptr, 0, nullptr, nullptr);
	std::string b;
	b.resize(newsize);
	WideCharToMultiByte(54936, 0, a.c_str(), (int)a.length(), &b[0], (int)b.capacity(), nullptr, nullptr);
	return b;
}

std::wstring StringToWString(std::string a)
{
	DWORD newsize = MultiByteToWideChar(54936, 0, a.c_str(), (int)a.length(), nullptr, 0);
	std::wstring b;
	b.resize(newsize);
	MultiByteToWideChar(54936, 0, a.c_str(), (int)a.length(), &b[0], (int)b.capacity());
	return b;
}

enum class Arch : uint32_t
{
	Unknown,
	x86,
	x64,
	ia64,
};

LPCSTR ArchToStr(Arch a) {
	switch (a) {
	case Arch::Unknown:
		return "Unknown";
	case Arch::x86:
		return "x86";
	case Arch::x64:
		return "x64";
	case Arch::ia64:
		return "ia64";
	default:
		return "INVALID VALUE";
	}
}

template <>
struct std::formatter<Arch> : std::formatter<std::string> {
	auto format(Arch p, format_context& ctx) {
		LPCSTR t = ArchToStr(p);
		return formatter<string>::format(t, ctx);
	}
};

template <>
struct std::formatter<Arch, wchar_t> : std::formatter<std::wstring, wchar_t> {
	auto format(Arch p, wformat_context& ctx) {
		LPCSTR t = ArchToStr(p);
		auto tw = std::make_unique<wchar_t[]>(strlen(t) + 1);
		{
			auto p = t; auto pw = tw.get();
			for (; *p; p++, pw++) {
				*pw = *p;
			}
			*pw = 0;
		}
		return formatter<wstring, wchar_t>::format(tw.get(), ctx);
	}
};

Arch GetTargetArch(const fs::path& fullFilePath)
{
	DWORD binaryType = -1;

	if (!GetBinaryTypeW(fullFilePath.c_str(), &binaryType)) {
		return Arch::Unknown;
	}

	switch (binaryType)
	{
	case SCS_32BIT_BINARY:
		return Arch::x86;
	case SCS_64BIT_BINARY:
		return Arch::x64;
	default:
		return Arch::Unknown;
	}
}

Arch GetDllTargetArch(const fs::path& fullFilePath) {
	DWORD binaryType = -1;

	auto file = std::ifstream(fullFilePath, std::ios::binary);
	std::vector<unsigned char> buffer(0x1000);
	file.read((char*)(&buffer[0]), buffer.capacity());

	auto header = ImageNtHeader(buffer.data());
	if (header == nullptr) { return Arch::Unknown; }
	switch (header->FileHeader.Machine) {
	case IMAGE_FILE_MACHINE_I386:
		return Arch::x86;
	case IMAGE_FILE_MACHINE_AMD64:
		return Arch::x64;
	case IMAGE_FILE_MACHINE_IA64:
		return Arch::ia64;
	default:
		return Arch::Unknown;
	}
}

ptrdiff_t GetLoadLibraryOffset()
{
	auto kernel32 = (uintptr_t)LoadLibraryW(L"kernel32.dll");
	if (kernel32 == 0) {
		FatalError("LoadLibraryW() kernel32.dll failed.");
	}

	auto apiAddress = (uintptr_t)GetProcAddress((HMODULE)kernel32, "LoadLibraryW");
	if (apiAddress == 0) {
		FatalError("GetProcAddress() LoadLibraryW failed.");
	}

	if (apiAddress < kernel32) {
		FatalError(
			std::format("Invalid address. kernel32: {}, apiAddress: {}", kernel32, apiAddress)
		);
	}

	return apiAddress - kernel32;
}

uintptr_t GetProcessModuleBase(uint32_t processId, std::wstring moduleName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	moduleName = ToLower(std::move(moduleName));

	uintptr_t result = 0;
	MODULEENTRY32W entry{};
	entry.dwSize = sizeof(entry);

	if (Module32FirstW(snapshot, &entry)) {
		do {
			if (moduleName == ToLower(entry.szModule)) {
				result = (uintptr_t)entry.modBaseAddr;
				break;
			}
		} while (Module32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return result;
}

bool WriteMemory(HANDLE processHandle, void* target, const void* buffer, size_t size)
{
	SIZE_T written = 0;
	if (!WriteProcessMemory(processHandle, target, buffer, size, &written)) {
		return false;
	}
	return size == written;
}

int wWinMain(HINSTANCE instance, HINSTANCE prevInstance, PWSTR pCmdLine, int showCmd)
{
	int argc = 0, curargc = 0;
	LPWSTR empty_argv = nullptr;
	LPWSTR* argv = &empty_argv;
	if (pCmdLine[0]) {
		argv = CommandLineToArgvW(pCmdLine, &argc);
	}

	bool optIgnoreNoDll = false, optVerbose = false;
	fs::path optCustomDllDir(".");
	for (curargc = 0; curargc < argc && argv[curargc][0] == L'-'; curargc++) {
		switch (argv[curargc][1]) {
		case L'e':
			optIgnoreNoDll = true;
			break;
		case L'v':
			optVerbose = true;
			break;
		case L'd':
			if (++curargc >= argc)FatalError("-d must have a parameter, and seperated with space. e.g. \"-d ./Hooks\"");
			optCustomDllDir = fs::path(argv[curargc]);
			break;
		case L'h':
			VerboseMsg(
				"Usage:\n"
				"  Dll-Injecter.exe [-h] [-e] [-v] [-d dir] [Telegram.exe]\n\n"
				"Arguments:\n"
				"  -h       Show this help.\n"
				"  -e       Silently continue even if there's no suitable DLL to load.\n"
				"  -v       Be verbose.\n"
				"  -d dir   Find DLL in specified path, rather than current dir.\n");
			std::exit(0);
		}
	}

	std::wstring exeFileName(curargc < argc ? argv[curargc] : L"Telegram.exe");
	if (optVerbose) {
		VerboseMsg(std::format("The exe file is {}, absolute path is {}, arch is {}.", WStringToString(exeFileName), WStringToString(fs::absolute(exeFileName)), GetTargetArch(fs::absolute(exeFileName))));
	}
	if (!fs::exists(exeFileName)) {
		FatalError(
			std::format(
				"\"{}\" file not found.\n"
				"Please place this file in the \"{}\" directory.", WStringToString(exeFileName), WStringToString(optCustomDllDir))
		);
	}

	auto arch = GetTargetArch(fs::absolute(exeFileName));
	if (arch == Arch::Unknown) {
		FatalError(std::format("Invalid file \"{}\".", WStringToString(exeFileName)));
	}

	std::vector<std::wstring> dllFileNames, filteredDllFileNames;

	try {
		for (auto& dllFileName : fs::directory_iterator(optCustomDllDir)) {
			if (dllFileName.is_regular_file() && dllFileName.path().extension() == ".dll" && GetDllTargetArch(dllFileName) == arch) {
				dllFileNames.push_back(fs::absolute(dllFileName));
			}
			else if (optVerbose) {
				filteredDllFileNames.push_back(std::format(L"{}  arch={}", fs::absolute(dllFileName).native(), GetDllTargetArch(dllFileName)));
			}
		}
	}
	catch (fs::filesystem_error const& ex) {
		FatalError(WStringToString(std::format(
			L"fs::filesystem_error\n{}\npath1={}\npath2={}\ncode={}\nmsg={}\ncategory={}",
			StringToWString(ex.what()), ex.path1().native(), ex.path2().native(),
			ex.code().value(), StringToWString(ex.code().message()), StringToWString(ex.code().category().name()))));
	}

	if (optVerbose) {
		std::wstring temp, temp2;
		for (auto& dllFileName : dllFileNames) {
			temp += dllFileName;
			temp += '\n';
		}
		for (auto& filteredDllFileName : filteredDllFileNames) {
			temp2 += filteredDllFileName;
			temp2 += '\n';
		}
		VerboseMsg(std::format("The dll files to load are:\n{}\n\nFiltered out dll files:\n{}", WStringToString(temp), WStringToString(temp2)));
	}
	if (!optIgnoreNoDll && dllFileNames.empty()) {
		FatalError(
			"No dll found. Is that allowed or expected? If so, try running with -e."
		);
	}

	auto apiOffset = GetLoadLibraryOffset();

	STARTUPINFOW startupInfo{};
	startupInfo.cb = sizeof(startupInfo);

	PROCESS_INFORMATION processInfo{};

	bool isCreateSuccess = CreateProcessW(
		exeFileName.c_str(),
		nullptr,
		nullptr,
		nullptr,
		false,
		0,
		nullptr,
		nullptr,
		&startupInfo,
		&processInfo
	);
	if (!isCreateSuccess) {
		FatalError(std::format("CreateProcess() failed. Last error code: {}", ::GetLastError()));
	}

	std::this_thread::sleep_for(3s);

	if (WaitForSingleObject(processInfo.hProcess, 0) != WAIT_TIMEOUT) {
		FatalError("Target process exited immediately after CreateProcess.\nIf it's an single instance program(like Telegram), try exit the existing instance first.");
	}

	auto targetKernel32 = GetProcessModuleBase(processInfo.dwProcessId, L"kernel32.dll");
	if (targetKernel32 == 0) {
		FatalError(
			"GetProcessModuleBase() kernel32.dll failed.\n"
			"Please try again later."
		);
	}

	auto targetLoadLibrary = targetKernel32 + apiOffset;

	size_t dllFileNameNameSize = 0;
	for (auto dllFileNameName : dllFileNames) {
		dllFileNameNameSize += dllFileNameName.length() + 4;
	}

	auto targetBuffer = VirtualAllocEx(
		processInfo.hProcess,
		nullptr,
		(dllFileNameNameSize * sizeof(wchar_t) + 0xfff) & ~0xfff,
		MEM_COMMIT,
		PAGE_READWRITE
	);
	if (targetBuffer == nullptr) {
		FatalError(std::format("VirtualAllocEx() failed. Last error code: {}", ::GetLastError()));
	}

	std::vector<size_t> targetFileNameOffsets;
	std::unique_ptr<wchar_t> targetFileNameBuffer(new wchar_t[dllFileNameNameSize + 1]);
	wchar_t* p = targetFileNameBuffer.get();
	for (auto dllFileNameName : dllFileNames) {
		size_t curOffset = p - targetFileNameBuffer.get();
		targetFileNameOffsets.push_back(curOffset);
		wcscpy_s(p, dllFileNameNameSize - curOffset - 1, dllFileNameName.c_str());
		p += dllFileNameName.length();
		*(p++) = 0;
		*(p++) = 0;
	}

	if (!WriteMemory(
		processInfo.hProcess,
		targetBuffer,
		targetFileNameBuffer.get(),
		dllFileNameNameSize * sizeof(wchar_t)
	)) {
		FatalError(std::format("WriteMemory() failed. Last error code: {}", ::GetLastError()));
	}

	for (auto targetFileNameOffset : targetFileNameOffsets) {
		HANDLE remoteThread = CreateRemoteThread(
			processInfo.hProcess,
			nullptr,
			0,
			(LPTHREAD_START_ROUTINE)targetLoadLibrary,
			((wchar_t*)targetBuffer + targetFileNameOffset),
			0,
			nullptr
		);
		if (remoteThread == nullptr) {
			FatalError(
				std::format("CreateRemoteThread() failed. Last error code: {}", ::GetLastError())
			);
		}
		else {
			CloseHandle(remoteThread);
		}
	}

	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);

	return 0;
}
