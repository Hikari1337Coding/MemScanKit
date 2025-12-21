#include "../gui/imgui_init.h"
#include <thread>
#include "utils.h"

int main() {

	std::thread freezeThread([] {
		while (freeze_running) {
			for (auto& item : watchlist) {
				if (item.freeze) {
					writeValueFromString(item.addr, (DisplayType)watchlistDisplayType, item.frozenValue);
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(5));

		}

		});

	freezeThread.detach();

	createOverlayWindow();

	return 0;
}