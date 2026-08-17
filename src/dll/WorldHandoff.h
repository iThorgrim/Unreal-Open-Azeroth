#pragma once

// After AZRT auth completes and the realm-received handler raises the login controller's gate byte, the
// native step that would carry the client from "Success!" into the world connection is Blueprint-driven
// and has stopped ticking, so the committed realm is never acted on. We resolve the login controller from
// the MANGOS subsystem and invoke the native world-login entry once, reproducing the realm selection the
// login UMG would have made. The trigger runs from user32!PeekMessageW, which the game thread pumps every
// frame, so no game function is hooked and the call lands on the thread that owns the UObjects it rebuilds.

namespace uoa::worldhandoff {

void install();

}
