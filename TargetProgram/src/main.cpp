#include <iostream>
#include <Windows.h>
#include <vector>
#include <thread>
#include <atomic>

int secretValue = 1337;
const char patternData[] = "HELLO_PATTERN_TSET_V1";

struct TestStruct {
	int id;
	char name[16];
	double value;
};

TestStruct globalStruct = { 42, "TargetStruct", 3.14159 };

int main() {
	std::cout << "Target Program running PID: " << GetCurrentProcessId() << std::endl;
	std::cout << "secretValue address: " << &secretValue << " value: " << secretValue << std::endl;
	std::cout << "patternData address: " << static_cast<const void*>(patternData) << " data: " << patternData << std::endl;
	std::cout << "globalStruct address: " << &globalStruct << " id: " << globalStruct.id << " name: " << globalStruct.name << " value: " << globalStruct.value << std::endl;

	// Allocate a dynamic buffer with a repeat-pattern inside.
	std::vector<char> dynamicBuffer(1024, 0);
	const char repeat[] = "DYNAMIC_PATTERN_XYZ";
	for (size_t i = 0; i + sizeof(repeat) < dynamicBuffer.size(); i += sizeof(repeat)) {
		memcpy(&dynamicBuffer[i], repeat, sizeof(repeat) - 1);
	}

	std::cout << "Dynamic buffer address: " << reinterpret_cast<void*>(dynamicBuffer.data()) << std::endl;

	// pointer chain
	// p4 -> p3 -> p2 -> p1 -> secretValue
	static uintptr_t p1 = (uintptr_t)&secretValue;
	static uintptr_t p2 = (uintptr_t)&p1;
	static uintptr_t p3 = (uintptr_t)&p2;
	static uintptr_t p4 = (uintptr_t)&p3;

	std::cout << "level1 (points->secret): " << (void*)&p1 << std::endl;
	std::cout << "level2 (points->level1): " << (void*)&p2 << std::endl;
	std::cout << "level3 (points->level2): " << (void*)&p3 << std::endl;
	std::cout << "level4 (points->level3): " << (void*)&p4 << std::endl;

	std::cout << "Press F2 to increse the secretValue by 1" << std::endl;

	// keep the process alive and increase secretValue
	while (true) {
		if (GetAsyncKeyState(VK_F2) & 1) {
			secretValue += 1;
			std::cout << "secretValue value: " << secretValue << std::endl;
		}
		std::this_thread::sleep_for(std::chrono::microseconds(500));
	}

	return 0;

}