Eternal Zunder: Zelda Classic 1.92 - 2.50 Quest Deprotector

Requires Python3.x

This was a project that took me about a week's time to complete. This script can decrypt, decompress, and remove the password from any Zelda Classic quest from v 1.92 to 2.50. It may work with higher versions, but the ZC maintainers may have changed the encryption or added keys since this script was written.

Additonally, this script was written in 2015 when I was still a very VERY novice programmer, so it is very VERY full of stylistic muck. I just don't care enough or have enough time to spend cleaning it up and making it pretty. I spent a little time tweaking but it was mostly slight speedups and making the GUI work better on most operating systems


I started to experiment with deprotecting save files so they can be edited just for shits and giggles, but I just didn't care enough to finish it. The code is in place to decrypt them and uncompress them, but not to recompress and re-encrypt them. If you feed the program a .sav file it'll properly decrypt and decompress it, but if you want to actually modify them and save them back, then someone's gonna need to write a routine to re-compress and re-encrypt them.


Older quests can't be deprotected for two reasons:

1: The algorithm the quests are compressed with is different than the newer ones and I don't want to spend any more time on this trying to figure it out. It looks like it's still LZSS, but the flag byte's value makes no sense and I'm not going to try and figure it out.

2: More importantly, the older quests have a different file structure, and as such the password hash(or it might just be a plaintext password) are not going to be in the same spot. Even if I could replace it, I don't think that .qsu files existed at that point. Because of that, if I were to deprotect the quest I'd have to recompress and re-encrypt it; I'm not writing code for that.
