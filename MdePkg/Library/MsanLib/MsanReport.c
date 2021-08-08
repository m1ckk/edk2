//===-- msan_report.cc ----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
// Error reporting.
//===----------------------------------------------------------------------===//
#include <Library/DebugLib.h>
#include "MsanReport.h"

void ReportUMR() {
// For now, we always report.
  // We just print to the console. Report() adds the PID of the violating process.
  // We should maybe print the UEFI driver that is doing this. TODO.
  DEBUG ((DEBUG_INFO, "WARNING: MemorySanitizer: use-of-uninitialized-value\n"));
  DEBUG ((DEBUG_INFO, "Stack trace:\n"));
  DEBUG ((DEBUG_INFO, "Return address 0 = %p\n", __builtin_return_address(0)));
  DEBUG ((DEBUG_INFO, "Return address 1 = %p\n", __builtin_return_address(1)));
  DEBUG ((DEBUG_INFO, "Return address 2 = %p\n", __builtin_return_address(2)));
  DEBUG ((DEBUG_INFO, "Return address 3 = %p\n", __builtin_return_address(3)));
}
