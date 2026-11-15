#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <cstdint>
#include <cassert>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <vector>


#ifdef NDEBUG
#define CHECK(func) func
#else
#define CHECK(func) if (func){}else{std::printf("Debug check failure by Win32. Error: %02X\n", GetLastError());assert(false);}
#endif

static constexpr DWORD ACCESS_DENIED = 0x05;

enum class Tile : std::uint8_t
{
	flag = 0xE,
	clickable = 0xF,
	mine = 0x8F
};
[[nodiscard]] std::byte as_byte(Tile t)
{
	return static_cast<std::byte>(t);
}
bool operator==(std::byte lhs, Tile rhs)
{
	return lhs == as_byte(rhs);
}
class Process
{
public:
	Process(DWORD pid)
		: m_Pid{ pid }
		, m_Handle{ OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) }
	{
		DWORD err = GetLastError();
		if (!valid() && err != ACCESS_DENIED)
		{
			std::printf("Failed to open process. Error: %02X\n", err);
		}
	}
	~Process()
	{
		if (valid())
		{
			CloseHandle(m_Handle);
		}
	}
	Process(const Process& other) = delete;
	Process& operator=(const Process& other) = delete;
	Process(Process&& other) noexcept
		: m_Pid{}
		, m_Handle{}
	{
		std::swap(m_Pid, other.m_Pid);
		std::swap(m_Handle, other.m_Handle);
	}
	Process& operator=(Process&& other) noexcept
	{
		std::swap(m_Pid, other.m_Pid);
		std::swap(m_Handle, other.m_Handle);
	}
	[[nodiscard]] bool valid() const
	{
		return m_Handle != NULL;
	}
	[[nodiscard]] std::optional<std::string> filename() const
	{
		if (valid())
		{
			std::string name{};
			name.resize(1024);
			DWORD realSize = GetModuleBaseNameA(m_Handle, NULL, name.data(), name.size());
			if (realSize > 0)
			{
				name.resize(realSize);
				return std::make_optional<std::string>(std::move(name));
			}
		}

		return std::nullopt;
	}
	[[nodiscard]] std::uintptr_t base_address() const
	{
		if (!valid())
		{
			return 0;
		}

		std::vector<HMODULE> handles{};
		handles.resize(2048);
		DWORD realSize{};
		CHECK(EnumProcessModulesEx(m_Handle,
			handles.data(),
			handles.size() * sizeof(decltype(handles)::value_type),
			std::addressof(realSize),
			LIST_MODULES_ALL));
		handles.resize(realSize);

		// The first module is always self?
		return reinterpret_cast<std::uintptr_t>(handles.front());
	}
	[[nodiscard]] std::vector<std::byte> read_memory(std::uintptr_t address, std::size_t size) const
	{
		assert(valid());	// I dont feel like handling this atm

		std::vector<std::byte> buffer{};
		buffer.resize(size);
		SIZE_T realSize{};
		CHECK(ReadProcessMemory(m_Handle, reinterpret_cast<LPCVOID>(address), buffer.data(), size, std::addressof(realSize)));
		buffer.resize(realSize);

		return buffer;
	}
	template<typename data_t>
	[[nodiscard]] data_t read_memory(std::uintptr_t address)
	{
		std::vector<std::byte> d = read_memory(address, sizeof(data_t));
		data_t data{};
		std::memcpy(std::addressof(data), d.data(), sizeof(data));
		return data;
	}
	[[nodiscard]] std::size_t write_memory(std::span<std::byte> data, std::uintptr_t address)
	{
		assert(valid());	// I dont feel like handling this atm

		SIZE_T bytesWritten{};
		CHECK(WriteProcessMemory(m_Handle, reinterpret_cast<LPVOID>(address), data.data(), data.size(), std::addressof(bytesWritten)));
		return static_cast<std::size_t>(bytesWritten);
	}
private:
	DWORD m_Pid;
	HANDLE m_Handle;
};
[[nodiscard]] std::vector<DWORD> all_pids()
{
	std::vector<DWORD> pids{};
	pids.resize(2048);
	DWORD realSize{};
	CHECK(K32EnumProcesses(pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD), std::addressof(realSize)));
	pids.resize(realSize);

	return pids;
}
[[nodiscard]] std::optional<Process> minesweeper_process()
{
	std::vector<DWORD> pids = all_pids();
	for (auto&& pid : pids)
	{
		if (pid != 0)	// pid 0 is special in windows
		{
			Process p{ pid };
			auto name = p.filename();
			if (name)
			{
				if (*name == "winmine.exe")
				{
					return std::make_optional<Process>(std::move(p));
				}
			}
		}
	}

	return std::nullopt;
}
template<typename header_t>
[[nodiscard]] header_t pe_header(const Process& minesweeper, std::uintptr_t base)
{
	std::vector<std::byte> dosHeader = minesweeper.read_memory(base, sizeof(header_t));
	header_t header{};
	std::memcpy(std::addressof(header), dosHeader.data(), sizeof(header));
	return header;
}
[[nodiscard]] bool is_section(IMAGE_SECTION_HEADER& section, std::string_view name)
{
	std::string_view n(reinterpret_cast<char*>(std::addressof(section.Name[0])));
	return n == name;
}
int32_t main(int32_t argc, char** argv)
{
	std::optional<Process> minesweeper = minesweeper_process();
	if (!minesweeper)
	{
		std::printf("Failed to open handle to Minesweeper.\n");
		return 1;
	}

	std::uintptr_t baseAddress = minesweeper->base_address();
	auto dosHeader = minesweeper->read_memory<IMAGE_DOS_HEADER>(baseAddress);

	std::uintptr_t signatureAddress = baseAddress + dosHeader.e_lfanew;
	auto peSignature = minesweeper->read_memory<DWORD>(signatureAddress);
	if (peSignature != IMAGE_NT_SIGNATURE)
	{
		std::printf("Failed to parse PE Headers.\n");
		return 2;
	}

	std::uintptr_t fileHeaderAddress = signatureAddress + sizeof(peSignature);
	auto fileHeader = minesweeper->read_memory<IMAGE_FILE_HEADER>(fileHeaderAddress);

	std::uintptr_t sectionHeaderAddress = fileHeaderAddress + sizeof(fileHeader) + fileHeader.SizeOfOptionalHeader;
	std::uintptr_t dataSection = baseAddress;
	for (WORD i = 0; i < fileHeader.NumberOfSections; ++i)
	{
		auto sectionHeader = minesweeper->read_memory<IMAGE_SECTION_HEADER>(sectionHeaderAddress);
		if (is_section(sectionHeader, ".data"))
		{
			dataSection += sectionHeader.VirtualAddress;
			break;
		}

		sectionHeaderAddress += sizeof(IMAGE_SECTION_HEADER);
	}

	std::uintptr_t boardAddress = dataSection + 0x340;
	std::size_t boardSize = 0x370;
	std::vector<std::byte> board = minesweeper->read_memory(boardAddress, boardSize);

	for (std::byte& tile : board)
	{
		if (tile == Tile::mine)
		{
			tile = as_byte(Tile::flag);
		}
	}

	std::size_t written = minesweeper->write_memory(board, boardAddress);
	if (written != board.size())
	{
		std::printf("Wrote %llu, expected to write %llu", written, board.size());
	}

	return 0;
}