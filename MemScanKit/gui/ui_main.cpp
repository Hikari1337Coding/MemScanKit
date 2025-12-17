#include "ui_main.h"
#include "imgui_init.h"
#include "imgui/backend/imgui_impl_dx11.h"
#include "imgui/backend/imgui_impl_win32.h"
#include <string>
#include "../src/utils.h"

void run_overlay_loop(HWND hwnd, WNDCLASSEXW wc) {
	InitImGui(hwnd);

	MSG msg;
	ZeroMemory(&msg, sizeof(msg));

	bool running = true;

	while (running) {
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			if (msg.message == WM_QUIT)
				running = false;
		}

		if (!running) break;

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		ImGui::Begin("MemScanKit", nullptr, ImGuiWindowFlags_AlwaysAutoResize);

		static char procText[128] = "TargetProgram.exe";
		ImGui::InputText("Process name", procText, IM_ARRAYSIZE(procText));
		ImGui::SameLine();
		if (ImGui::Button("Find")) {

			DWORD pid = getProcIdByName(procText);
			HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			ModuleInfo modInfo = getModuleInfoById(pid);

			if (pid && handle && modInfo.base && modInfo.size) {
				target_pid = pid;
				target_handle = handle;
				target_module_info = modInfo;
			}

		}

		if (ImGui::BeginTabBar("##main_tabs")) {
			if (ImGui::BeginTabItem("Target's Info")) {
				ImGui::Text("PID: %u", target_pid);
				ImGui::Text("ModuleBaseAddress: 0x%llx", target_module_info.base);
				ImGui::Text("ModuleSize: 0x%llx", target_module_info.size);
				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Scan Value")) {
				static int valueType = 0;
				ImGui::Combo("Type", &valueType, "Int32\0Float\0String\0Pointer (Lv1)\0\0");

				static int pointerDisplayValueType = 0;
				
				static char valueInput[64] = "";

				ImGui::InputText("Value", valueInput, IM_ARRAYSIZE(valueInput));

				if (!value_scanning) {
					if (ImGui::Button("Scan")) {
						// parse value
						std::string valStr = valueInput;
						std::string proc = procText;
						if (!target_pid) { OutputDebugStringA("Failed to find process\n"); }
						else {
							if (valueType == 0) {
								int32_t needle = atoi(valStr.c_str());
								if (valueScanThread.joinable()) valueScanThread.join();

								valueScanThread = std::thread([needle]() {

									valueScan<int32_t>(needle, [](int32_t a, int32_t b) {
										return a == b;
										});
									});
							}
							else if (valueType == 1) {
								float needle = (float)atof(valStr.c_str());
								if (valueScanThread.joinable()) valueScanThread.join();
								valueScanThread = std::thread([needle]() {

									valueScan<float>(needle, [](float a, float b) {return a == b; });

									});
							}
							else if (valueType == 2) {
								std::string needleStr = valueInput;
								if (valueScanThread.joinable()) valueScanThread.join();
								valueScanThread = std::thread([needleStr]() {
									stringScan(needleStr);
									});
							}
							else if (valueType == 3) {
								uintptr_t needle = (uintptr_t)atof(valStr.c_str());
								if (valueScanThread.joinable()) valueScanThread.join();
								valueScanThread = std::thread([needle]() {
									pointerScanLevel1(needle);
									});
							}
						}
					}
				}
				else {
					if (ImGui::Button("Stop")) {
						value_scanning = false;
						if (valueScanThread.joinable())
							valueScanThread.join();
					}
				}

				if (valueType != 3) {
					ImGui::SameLine();
					if (ImGui::Button("Narrow")) {
						// Narrow current results
						std::string valStr = valueInput;
						DWORD pid = target_pid;
						std::string proc = procText;

						if (valueType == 0) {
							int32_t needle = atoi(valStr.c_str());
							if (valueScanThread.joinable()) valueScanThread.join();
							valueScanThread = std::thread([needle]() {
								valueNarrow<int32_t>(needle, [](int32_t a, int32_t b) {return a == b; });
								});
						}
						else if (valueType == 1) {
							float needle = (float)atof(valStr.c_str());
							if (valueScanThread.joinable()) valueScanThread.join();
							valueScanThread = std::thread([needle]() {
								valueNarrow<float>(needle, [](float a, float b) {return a == b; });
								});
						}
						else if (valueType == 2) {
							std::string needle = valStr;
							if (valueScanThread.joinable()) valueScanThread.join();
							valueScanThread = std::thread([needle]() {
								stringNarrow(needle);
								});

						}
					}
				}

				ImGui::Separator();
				if (valueType == 3) {
					ImGui::Combo("Pointer Display Type", &pointerDisplayValueType, "Int32\0Float\0String\0\0");
				}
				if (valueType != 3) {
					ImGui::Text("Value Matches (count: %d)", (int)value_matches.size());
				}
				else if (valueType == 3) {
					ImGui::Text("Level-1 pointers found: %d", (int)pointer_results.size());
				}
				if (ImGui::BeginChild("ValueMatchesChild", ImVec2(400, 200), true)) {
					std::lock_guard<std::mutex> lock(value_matches_mutex);
					if (valueType != 3) {
						for (size_t i = 0; i < value_matches.size(); ++i) {
							uintptr_t a = value_matches[i];
							std::string addrStr = addrToHex(a);

							if (valueType == 0) {
								int32_t v;
								if (readFromTarget<int32_t>(a, v))
									addrStr += "  =  " + std::to_string(v);
								else
									addrStr += "  =  <invalid>";
							}
							else if (valueType == 1) {
								float v;
								if (readFromTarget<float>(a, v))
									addrStr += "  =  " + std::to_string(v);
								else
									addrStr += "  =  <invalid>";
							}
							else if (valueType == 2) {
								std::string v;
								if (readStringFromProcess(a, v))
									addrStr += "  =  " + v;
								else
									addrStr += "  =  <invalid>";
							}

							if (ImGui::Selectable(addrStr.c_str())) {
								ImGui::SetClipboardText(addrStr.c_str());
							}
								
						}
					}
					else if (valueType == 3) {
						std::lock_guard<std::mutex> lock(pointer_results_mutex);
						if (pointer_results.empty()) {
							ImGui::TextDisabled("No pointer results");
						}
						else {
							for (auto& result : pointer_results) {
								uintptr_t resolved = resolveLevel1(result);

								std::string addrStr = "*(" +
									addrToHex(result.base) + ")" +
									" + " + addrToHex(result.offset);

								if (resolved) {
									addrStr += " => " + addrToHex(resolved);

									std::string valueStr;
									if (readValueAsString(resolved, (DisplayType)pointerDisplayValueType, valueStr))
										addrStr += " = " + valueStr;
									else
										addrStr += " = <invalid>";
									
								}
								else {
									addrStr += " => <invalid>";
								}

								if (ImGui::Selectable(addrStr.c_str()))
									ImGui::SetClipboardText(addrStr.c_str());
							}
						}
					}
				}
				ImGui::EndChild();
				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Watchlist")) {
				static char valueInput[64] = "0x123456";
				ImGui::InputText("Address (hex)", valueInput, IM_ARRAYSIZE(valueInput));
				if (ImGui::Button("Add")) {
					uintptr_t addr = strtoull(valueInput, nullptr, 16);
					watchlist.push_back({ addr, "", ""});

				}
				static int valueDisplayType = 0;
				ImGui::Combo("Value Display Type", &valueDisplayType, "Int32\0Float\0String\0\0");
				if (ImGui::BeginChild("WatchlistChild", ImVec2(400, 200), true)) {
					for (WatchItem& item : watchlist) {
						std::string newValue;
						if (readValueAsString(item.addr, (DisplayType)valueDisplayType, newValue)) {
							item.lastValue = item.value;
							item.value = newValue;
							bool changed = (item.value != item.lastValue);
							ImGui::Text("0x%p = %s%s", (void*)item.addr, item.value.c_str(), changed ? " *" : "");
						}
							
					}
				}	
				ImGui::EndChild();
				ImGui::EndTabItem();
			}

			ImGui::EndTabBar();
		}

		ImGui::End();
		// End UI

		// Rendering
		ImGui::Render();
		const float clear_color_with_alpha[4] = { 0.f, 0.f, 0.f, 0.f };
		d3dDeviceContext->OMSetRenderTargets(1, &mainRenderTargetView, nullptr);
		d3dDeviceContext->ClearRenderTargetView(mainRenderTargetView, clear_color_with_alpha);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		swapChain->Present(1, 0); // vsync = 1

		Sleep(1); // to avoid tight loop
	}

	// Shutdown and cleanup
	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	cleanupDeviceD3D();
	UnregisterClassW(wc.lpszClassName, wc.hInstance);

	CloseHandle(target_handle);
}