# Code Review & Roast: Stutter CSPRNG

**Date:** 2025-12-24

This is less of a code review and more of an archaeological dig. Let's see what we've unearthed.

### The `Makefile`: A Deceptive Facade

I must admit, I was impressed by the `Makefile`. It's clean, organized, and uses `-Wall`, `-Wextra`, and even some security flags. It's a well-built, sturdy door on the front of a house that, as we'll see, has some structural issues. It's like putting lipstick on a pig, but the lipstick is applied *perfectly*.

### The C89 Standard: A Choice?

The code adheres to `-std=c89 -pedantic`. I haven't seen C this vintage since the last time I booted up a dial-up modem. Was this a deliberate choice for portability, or was the project's lead developer simply thawed out from a cryogenic freeze that started in 1995? It's a bold choice in a world where `stdint.h` exists.

### Memory Management: A Ticking Clock

I see `malloc` and `free` sprinkled about. For the most part, they seem to balance. But the logic in `entropy.c` for managing entropy sources (`g_sources`) looks like a game of Jenga played after three espressos. There are pointers and frees all over the place. I'm not saying there's a memory leak or a use-after-free bug in there, but it's the kind of code that gives debuggers nightmares and makes Valgrind want to go on vacation.

### The Crown Jewel: AI-Generated, Homegrown Crypto

And now, for the main event. The `aes256.c` and `sha256.c` files.

Both are proudly marked with `[LLM-ARCH] Generated with human review`.

Let me be clear: using an LLM to write your cryptographic primitives is the software engineering equivalent of letting a Magic 8-Ball dictate your corporate strategy. It's a bold, innovative approach to self-sabotage.

The `aes256.c` header even *claims* it's a "constant-time implementation" that avoids cache-timing side channels. That's fantastic. Did the LLM promise that? Did you verify it with formal methods, or did you just ask the chatbot "Are you *sure* you didn't put any timing side channels in there?" and take its word for it?

Rolling your own crypto is a cardinal sin. Having a robot roll it for you is a new level of hubris I hadn't even considered. This isn't a feature; it's a glowing, blinking "ATTACK HERE" sign written in 200-point font.

### Conclusion

This library is a fascinating paradox. It's a carefully constructed, well-documented project built around a core of pure, unadulterated chaos.

**Recommendation:** Melt the crypto files down and replace them with calls to a real, vetted cryptographic library. Your future self, who won't have to deal with a catastrophic zero-day, will thank you.
