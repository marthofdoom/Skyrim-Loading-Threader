#pragma once

#include "RE/Skyrim.h"
#include "SKSE/SKSE.h"

#include <spdlog/sinks/basic_file_sink.h>

#include <intrin.h>   // __rdtsc

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// REQUIRED, not stylistic. add_commonlibsse_plugin generates
// __LoadingThreaderPlugin.cpp with "..."sv literals and force-includes this
// PCH; without this the build dies with C3688 "invalid literal suffix 'sv'" in
// a file we never wrote (native-dll-via-github-actions.md, first-build gotcha).
using namespace std::literals;
