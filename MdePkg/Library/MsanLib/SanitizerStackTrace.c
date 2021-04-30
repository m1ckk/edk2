//===-- sanitizer_stacktrace.h ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between AddressSanitizer and ThreadSanitizer
// run-time libraries.
//===----------------------------------------------------------------------===//
#include "SanitizerStackTrace.h"
#include <Library/DebugLib.h>

// TODO
uptr stack_top() {
    return (uptr)0x7F7EF000UL;
}

// TODO
uptr stack_bottom() {
    return (uptr)0x7F001000UL;
}

void BufferedStackTracePrint(BufferedStackTrace *bst) {
  DEBUG ((DEBUG_INFO, "BufferedStackTracePrint(): bst = %p\n", bst));
  if (bst->trace == NULL) {
    DEBUG((DEBUG_INFO, "    <empty stack>: bst->trace == NULL\n\n"));
    return;
  }
  if (bst->size == 0) {
    DEBUG((DEBUG_INFO, "    <empty stack>: bst->size == 0\n\n"));
    return;
  }
  //uptr frame_num = 0;
  for (uptr i = 0; i < bst->size && bst->trace[i]; i++) {
    // PCs in stack traces are actually the return addresses, that is,
    // addresses of the next instructions after the call.
    uptr pc = GetPreviousInstructionPc(bst->trace[i]);
/*
    SymbolizedStack *frames = Symbolizer::GetOrInit()->SymbolizePC(pc);
    // CHECK(frames);
    for (SymbolizedStack *cur = frames; cur; cur = cur->next) {
      frame_desc.clear();
      RenderFrame(&frame_desc, common_flags()->stack_trace_format, frame_num++,
                  cur->info, common_flags()->symbolize_vs_style,
                  common_flags()->strip_path_prefix);
      Printf("%s\n", frame_desc.data());
      if (dedup_frames-- > 0) {
        if (dedup_token.length())
          dedup_token.append("--");
        if (cur->info.function != nullptr)
          dedup_token.append(cur->info.function);
      }
    }
    frames->ClearAll();
*/
    DEBUG ((DEBUG_INFO, "pc = %p, base->[%d] = %p\n", pc, i, bst->trace[i]));
  }
  // Always print a trailing empty line after stack trace.
  DEBUG ((DEBUG_INFO, "\n"));
#if 0
  if (dedup_token.length())
    Printf("DEDUP_TOKEN: %s\n", dedup_token.data());
#endif
}

void BufferedStackTraceUnwindFast(BufferedStackTrace *bst, uptr pc, uptr bp,
                uptr stack_top, uptr stack_bottom, u32 max_depth) {
  const uptr kPageSize = 4096; // GetPageSizeCached();
  bst->trace_buffer[0] = pc;
  bst->size = 1;
  if (stack_top < 4096) return;  // Sanity check for stack top.
  uhwptr *frame = GetCanonicFrame(bp, stack_top, stack_bottom);
  DEBUG ((DEBUG_INFO, "pc = %p\n", pc));
  DEBUG ((DEBUG_INFO, "bp = %p\n", bp));
  DEBUG ((DEBUG_INFO, "stack_top = 0x%x\n", stack_top));
  DEBUG ((DEBUG_INFO, "stack_bottom = 0x%x\n", stack_bottom));
  DEBUG ((DEBUG_INFO, "frame = %p\n", frame));
  // Lowest possible address that makes sense as the next frame pointer.
  // Goes up as we walk the stack.
  uptr bottom = stack_bottom;
  // Avoid infinite loop when frame == frame[0] by using frame > prev_frame.
  while (IsValidFrame((uptr)frame, stack_top, bottom) &&
         IsAligned((uptr)frame, sizeof(*frame)) &&
         bst->size < max_depth) {
    DEBUG ((DEBUG_INFO, "pc = %p\n", pc));
    DEBUG ((DEBUG_INFO, "bp = %p\n", bp));
    DEBUG ((DEBUG_INFO, "stack_top = 0x%x\n", stack_top));
    DEBUG ((DEBUG_INFO, "stack_bottom = 0x%x\n", stack_bottom));
    DEBUG ((DEBUG_INFO, "max_depth = %p\n", max_depth));

    uhwptr pc1 = frame[1];
    DEBUG ((DEBUG_INFO, "pc1 = %p\n", pc1));
    // Let's assume that any pointer in the 0th page (i.e. <0x1000 on i386 and
    // x86_64) is invalid and stop unwinding here.  If we're adding support for
    // a platform where this isn't true, we need to reconsider this check.
    if (pc1 < kPageSize)
      break;
    if (pc1 != pc) {
      bst->trace_buffer[bst->size++] = (uptr) pc1;
    }
    bottom = (uptr)frame;
    DEBUG ((DEBUG_INFO, "bottom = %p\n", bottom));
    frame = GetCanonicFrame((uptr)frame[0], stack_top, bottom);
    DEBUG ((DEBUG_INFO, "frame = %p\n", frame));
  }
}

// We always do the fast unwind, since this only gets called when we error
void BufferedStackTraceUnwind(BufferedStackTrace *bst, u32 max_depth, uptr pc,
                uptr bp, void *context, uptr stack_top, uptr stack_bottom,
                bool request_fast_unwind) {
  // Ensures all call sites get what they requested.
  bst->top_frame_bp = (max_depth > 0) ? bp : 0;
  // Avoid doing any work for small max_depth.
  if (max_depth == 0) {
    bst->size = 0;
    return;
  }
  if (max_depth == 1) {
    bst->size = 1;
    bst->trace_buffer[0] = pc;
    return;
  }
  BufferedStackTraceUnwindFast(bst, pc, bp, stack_top, stack_bottom, max_depth);
}

void BufferedStackTraceUnwindImpl(BufferedStackTrace *bst, 
    uptr pc, uptr bp, void *context, bool request_fast, u32 max_depth) {
    BufferedStackTraceUnwind(bst, max_depth, pc, bp, NULL, stack_top(), stack_bottom(), 1);
}

// Get the stack trace with the given pc and bp.
// The pc will be in the position 0 of the resulting stack trace.
// The bp may refer to the current frame or to the caller's frame.
void BufferedStackTraceUnwind1(BufferedStackTrace *bst, 
    uptr pc, uptr bp, void *context, bool request_fast, u32 max_depth) {
  bst->top_frame_bp = (max_depth > 0) ? bp : 0;
  // Small max_depth optimization
  if (max_depth <= 1) {
    if (max_depth == 1)
      bst->trace_buffer[0] = pc;
    bst->size = max_depth;
    return;
  }
  BufferedStackTraceUnwindImpl(bst, pc, bp, context, request_fast, max_depth);
}

// Get the stack trace with the given pc and bp.
// The pc will be in the position 0 of the resulting stack trace.
// The bp may refer to the current frame or to the caller's frame.
void BufferedStackTraceUnwind2(BufferedStackTrace *bst, 
    uptr pc, uptr bp, void *context, bool request_fast) {
  u32 max_depth = kStackTraceMax;
  bst->top_frame_bp = (max_depth > 0) ? bp : 0;
  // Small max_depth optimization
  if (max_depth <= 1) {
    if (max_depth == 1)
      bst->trace_buffer[0] = pc;
    bst->size = max_depth;
    return;
  }
  BufferedStackTraceUnwindImpl(bst, pc, bp, context, request_fast, max_depth);
}

void BufferedStackTraceInit(BufferedStackTrace *bst) {
  bst->top_frame_bp = 0;
  bst->size = 0;
  bst->trace = bst->trace_buffer;
  bst->tag = 0;
}

