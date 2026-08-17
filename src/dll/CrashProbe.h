#pragma once

// Vectored exception handler that logs the faulting address (and module-relative RVA) of the first
// few access violations, then defers to the client's own handler. Turns the post-a5 crash in the
// async send/cipher thread into a precise RVA we can reverse, instead of guessing.
namespace uoa::crashprobe {

void install();

} // namespace uoa::crashprobe
