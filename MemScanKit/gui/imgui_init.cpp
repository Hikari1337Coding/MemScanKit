#include "imgui/imgui.h"
#include "imgui_init.h"
#include "imgui/backend/imgui_impl_win32.h"
#include "imgui/backend/imgui_impl_dx11.h"
#include "ui_main.h"

#pragma comment(lib, "d3d11.lib")


extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void createRenderTarget() {
	ID3D11Texture2D* backBuffer;
	swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
	d3dDevice->CreateRenderTargetView(backBuffer, NULL, &mainRenderTargetView);
	backBuffer->Release();
}

bool createDeviceD3D(HWND hwnd) {
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 0;
    sd.BufferDesc.RefreshRate.Denominator = 0;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0
    };
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &swapChain, &d3dDevice, &featureLevel, &d3dDeviceContext) != S_OK)
        return false;

    createRenderTarget();
    return true;
}

void InitImGui(HWND hwnd) {
    createDeviceD3D(hwnd);
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(d3dDevice, d3dDeviceContext);
    io.ConfigFlags &= ~ImGuiConfigFlags_NoMouseCursorChange;

    ImGui::StyleColorsDark();

    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
    io.IniFilename = NULL;

    io.Fonts->AddFontDefault();
}

void createOverlayWindow() {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    WNDCLASSEXW wc = {
        sizeof(wc),
        CS_CLASSDC, WndProc,
        0, 0, GetModuleHandle(NULL),
        NULL, NULL, NULL, NULL,
        L"MemScanKit",
        NULL
    };

    RegisterClassExW(&wc);
    
    hwnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        wc.lpszClassName,
        L"MemScanKit",
        WS_POPUP | WS_VISIBLE,
        0, 0,
        screenWidth, screenHeight,
        NULL, NULL,
        wc.hInstance,
        NULL
    );

    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);

    run_overlay_loop(hwnd, wc);
}

void cleanupDeviceD3D() {
    if (mainRenderTargetView) {
        mainRenderTargetView->Release();
        mainRenderTargetView = nullptr;
    }
    if (swapChain) {
        swapChain->Release();
        swapChain = nullptr;
    }
    if (d3dDeviceContext) {
        d3dDeviceContext->Release();
        d3dDeviceContext = nullptr;
    }
    if (d3dDevice) {
        d3dDevice->Release();
        d3dDevice = nullptr;
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (d3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            // recreate render target on resize
            if (mainRenderTargetView) {
                mainRenderTargetView->Release();
                mainRenderTargetView = nullptr;
            }
            DXGI_SWAP_CHAIN_DESC sd;
            ZeroMemory(&sd, sizeof(sd));
            if (swapChain && SUCCEEDED(swapChain->GetDesc(&sd))) {
                createRenderTarget();
            }
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_CLOSE:
        // let destroy happen normally
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}