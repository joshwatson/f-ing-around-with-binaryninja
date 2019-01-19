# Episode 7: Actually Automating Things!

Lots of progress this time! In this [episode](https://www.twitch.tv/videos/365523417), we continue our work removing obfuscation techniques in an obfuscated binary. We fixed some corner case bugs in our opaque predicate removal, and added a queuing system for new places to analyze! Right at the end, we ran into a new type of obfuscation, an obfuscated indirect jump, so we patched that up as well.

You can find this episode's code [here](https://github.com/joshwatson/f-ing-around-with-binaryninja/tree/master/ep7-pelock-3/unlock.py)

In the next episode, we'll figure out why we seem to be infinite looping, and then hopefully move on to some new techniques to deobfuscate!