#ifndef __MSAN_REPORT_H__
#define __MSAN_REPORT_H__

#include "Msan.h"
#include "SanitizerStackTrace.h"
#include <Library/DebugLib.h>

void ReportUMR(BufferedStackTrace *stack, u32 origin);
void ReportStats();
void ReportAtExitStatistics();
void DescribeMemoryRange(const void *x, uptr size);
/*
void ReportExpectedUMRNotFound(StackTrace *stack);
void ReportUMRInsideAddressRange(const char *what, const void *start, uptr size,
                                 uptr offset);
*/

#endif  // MSAN_REPORT_H
