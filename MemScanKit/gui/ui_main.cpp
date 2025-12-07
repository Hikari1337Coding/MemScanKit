#include "ui_main.h"
#include "imgui_init.h"
#include "imgui/backend/imgui_impl_dx11.h"
#include "imgui/backend/imgui_impl_win32.h"

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
}