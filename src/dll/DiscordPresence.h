#pragma once

namespace uoa::discord {

// Installs the Rich Presence override once the Discord SDK module is loaded.
// Values come from Settings (loaded from discord.wtf).
void installAsync();

} // namespace uoa::discord
