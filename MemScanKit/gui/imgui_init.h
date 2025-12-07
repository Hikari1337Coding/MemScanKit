#pragma once
#include <wtypes.h>
#include <d3d11.h>

inline ID3D11Device* d3dDevice = NULL;
inline ID3D11DeviceContext* d3dDeviceContext = NULL;
inline IDXGISwapChain* swapChain = NULL;
inline ID3D11RenderTargetView* mainRenderTargetView = NULL;

inline HWND hwnd = NULL;

void createRenderTarget();

bool createDeviceD3D(HWND hwnd);

void InitImGui(HWND hwnd);

void createOverlayWindow();

void cleanupDeviceD3D();

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);