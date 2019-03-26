### aes.js - JavaScript AES

> Just as it's possible to write a TCP/IP protocol stack in some utterly
> inappropriate programing language like ML or Visual Basic, so too, it's
> possible to implement TCP/IP over carrier pidgeons, or paper tape, or
> demons summoned from the vasty deep.
>
> -- <cite>Stross, C., The Jennifer Morgue</cite>

This package provides a pure-JavaScript bitsliced AES implementation,
as logical operations on 32 bit unsigned integers, ported from the
[Go port][0] of the [BearSSL code][1].

#### WARNING

THIS IS NOT INTENDED AS A GENERAL PURPOSE AES IMPLEMENTATION.  Unless
you need access to AES algorithm internals (ie: `AddRoundKey`, `SubBytes`,
`ShiftRows`, and or `MixColumns`) it is strongly recommended that you use
`crypto` instead.

While sensible languages and compilers generally would transform an AES
implementation of this design into something that is timing side-channel
free, JavaScript and it's various implementations are not sensible by any
common definition of the word.

#### Notes

 * The inverse transformations are not currently implemented for reasons
   of brevity.

 * The bitsliced nature of the implementation means that under the hood
   each operation is applied to 2 blocks at once.  This can be used to
   increase performance of certain constructs.

 * If timing side-channels are beyond your threat model, this could be
   more easily accomplished via a table driven implementation, with better
   performance.

 * The package is not documented as developers that can't figure it out
   really have no business using it, at all.

[0]: https://git.schwanenlied.me/yawning/bsaes
[1]: https://bearssl.org/
