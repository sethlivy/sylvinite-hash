{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

module Sylvinite.Hash 
  ( sha1
{-  , sha224
  , sha256
  , sha384
  , sha512
  , sha512_224
  , sha512_256
  , sha3_224
  , sha3_256
  , sha3_384
  , sha3_512
-}
  )
where

import Data.Bits 
import Data.Word
import qualified Data.Vector.Unboxed as Vx
import qualified Data.Vector as Vc
import Data.Bit as Bit
import Data.Functor.Identity

{-
sha1 = undefined
sha224 = undefined
sha256 = undefined
sha384 = undefined
sha512 = undefined
sha512_224 = undefined
sha512_256 = undefined
sha3_224 = undefined
sha3_256 = undefined
sha3_384 = undefined
sha3_512 = undefined
-}

-- | Right shift operation, x is a w-bit word and 0 <= n < w.
shr :: Bits a => Int -> a -> a
shr n x = x `shiftR` n

-- | Circular right shift operation. x is a w-bit word and 0 <= n < w.
rotr :: Bits a => Int -> a -> a
rotr n x = x `rotateR` n
-- rotr n x = (x `shiftR` n) .|. (x `shiftL` ((bitSize x) - n))

-- | Circular left shift operation. x is a w-bit word and 0 <= n < w.
rotl :: Bits a => Int -> a -> a
rotl n x = x `rotateL` n
-- rotl n x = (x `shiftL` n) .|. (x `shiftR` ((bitSize x) - n))

-- SHA1 Functions

-- WHAT IS THE PURPOSE OF THIS. THE FEDERAL GOVERNMENT DOES NOT SAY.
sha1Function :: Word32 -> Word32 -> Word32 -> Int -> Word32
sha1Function a b c t 
  | (0 <= t) && (t <= 19) = ch a b c -- Let's make this contravariant one day!
  | (20 <= t) && (t <= 39) = parity a b c
  | (40 <= t) && (t <= 59) = maj a b c
  | (60 <= t) && (t <= 79) = parity a b c
  | otherwise = error "Hey, we should use some type wizardry to make this \
    \ unrepresentable. Like some Nat weirdness. Sandy Maguire, email me."
  where  parity x y z = x `xor` y `xor` z

-- SHA224 & SHA256 Functions

ch :: Bits a => a -> a -> a -> a
ch x y z = (x .&. y) `xor` ((complement x) .&. z) 
maj :: Bits a => a -> a -> a -> a
maj x y z = (x .&. y) `xor` (x .&. z) `xor` (y .&. z) 

sigma0_256 :: Bits a => a -> a
sigma0_256 x = (rotr 2 x) `xor` (rotr 13 x) `xor` (rotr 22 x)
sigma1_256 :: Bits a => a -> a
sigma1_256 x = (rotr 6 x) `xor` (rotr 11 x) `xor` (rotr 25 x)
rho0_256 :: Bits a => a -> a
rho0_256 x = (rotr 7 x) `xor` (rotr 18 x) `xor` (shr 3 x)
rho1_256 :: Bits a => a -> a
rho1_256 x = (rotr 17 x) `xor` (rotr 19 x) `xor` (shr 10 x)

-- SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions

sigma0_512 :: Bits a => a -> a
sigma0_512 x = (rotr 28 x) `xor` (rotr 34 x) `xor` (rotr 39 x)
sigma1_512 :: Bits a => a -> a
sigma1_512 x = (rotr 14 x) `xor` (rotr 18 x) `xor` (rotr 41 x)
rho0_512 :: Bits a => a -> a
rho0_512 x = (rotr 1 x) `xor` (rotr 8 x) `xor` (shr 7 x)
rho1_512 :: Bits a => a -> a
rho1_512 x = (rotr 19 x) `xor` (rotr 61 x) `xor` (shr 6 x)

-- SHA1 Constants

sha1Constants :: Int -> Word32
sha1Constants t 
  | (0 <= t) && (t <= 19) = 0x5a827999
  | (20 <= t) && (t <= 39) = 0x6ed9eba1
  | (40 <= t) && (t <= 59) = 0x8f1bbcdc
  | (60 <= t) && (t <= 79) = 0xca62c1d6
  | otherwise = error "Same as the function errors." 

-- SHA-224 and SHA-256 Constants

sha256Constants :: [Word32]
sha256Constants =
  [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]

-- SHA-512 Constants

sha512Constants :: [Word64]
sha512Constants = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

-- Pad message for SHA-1, SHA-224, SHA-256

padMessage512 :: Vector Bit -> Vector Bit
padMessage512 message = 
  let messageAppend1 = message `Vx.snoc` (Bit True)
      messageLength = countBits message
      messageLength' = countBits messageAppend1
      paddingK = Vx.replicate ((448 - messageLength') `mod` 512) (Bit False)
      messageLengthBitVector = castFromWords $ Vx.singleton (fromIntegral messageLength)
      paddingL = 
        (Vx.replicate (64 - countBits messageLengthBitVector) (Bit False))
        Vx.++
        messageLengthBitVector
   in if messageLength >= (2 ^ (64 :: Int)) -- hate you, ^
      then error "Message is too large. What do you have \
                    \ that is possibly bigger than 2^64 bits?"
      else message Vx.++ paddingK Vx.++ paddingL

-- author's note. 2^64 bits is about 2 and a quarter exabytes. Who has a single thing
-- of that size? Facebook?
-- author's note. soon i shall deduplicate this

-- Pad message for SHA-384, SHA-512, SHA-512/224, SHA-512/256

padMessage1024 :: Vector Bit -> Vector Bit
padMessage1024 message = 
  let messageAppend1 = message `Vx.snoc` (Bit True)
      messageLength = countBits message
      messageLength' = countBits messageAppend1
      paddingK = Vx.replicate ((896 - messageLength') `mod` 1024) (Bit False)
      messageLengthBitVector = castFromWords $ Vx.singleton (fromIntegral messageLength)
      paddingL = 
        (Vx.replicate (128 - countBits messageLengthBitVector) (Bit False))
        Vx.++
        messageLengthBitVector
   in if messageLength >= (2 ^ (128 :: Int)) -- hate you, ^
      then error "Message is too large. What do you have \
                    \ that is possibly bigger than 2^128 bits?"
      else message Vx.++ paddingK Vx.++ paddingL

-- Parsing message for SHA-1, SHA-224, SHA-256

-- This function snaps apart a bit vector into a vector of words of a certain size of bits.
-- sliceAndConvert 32 as takes a Vector Bit and turns it into a Vector Word32.
-- This function is so very unsafe, it doesn't check at all if you've given it enough bits.
-- There also isn't anything constraining your return type besides `Integral`.
-- If you slice things into 128 bits and turns things into Word64's, THAT IS ON YOU.

-- Good luck finding out the type constraints for THIS ONE.

-- God I suck.
sliceAndConvert x as =
  let (ys, zs) = Vx.splitAt x as
   in (pure $ ((Vx.map fromIntegral) . cloneToWords) ys) ++ (sliceAndConvert x zs)

splitAts :: (Vx.Unbox a) => Int -> Vector a -> [Vector a]
splitAts x as =
  let (ys, zs) = Vx.splitAt x as
   in (pure ys) ++ (splitAts x zs)

-- Makes a list of 512-bit message blocks. Sixteen 32-bit words are in each vector.
parse512 :: Vector Bit -> [Vector Word32]
parse512 message = (splitAts 16) . Vx.concat $ (sliceAndConvert 32 message)

-- Parsing message for SHA-384, SHA-512, SHA-512/224, SHA-512/256

parse1024 :: Vector Bit -> Vector Word64 
parse1024 message = Vx.concat $ sliceAndConvert 64 message 

-- Initial hash values

h0_sha1 = 
  ( 0
  , 0x67452301
  , 0xefcdab89
  , 0x98badcfe
  , 0x10325476
  , 0xc3d2e1f0
  )

h0_sha224 :: Vector Word32
h0_sha224 = Vx.fromList
  [ 0xc1059ed8
  , 0x367cd507
  , 0x3070dd17
  , 0xf70e5939
  , 0xffc00b31
  , 0x68581511
  , 0x64f98fa7
  , 0xbefa4fa4
  ]

h0_sha384 :: Vector Word64
h0_sha384 = Vx.fromList
  [ 0xcbbb9d5dc1059ed8
  , 0x629a292a367cd507
  , 0x9159015a3070dd17
  , 0x152fecd8f70e5939
  , 0x67332667ffc00b31
  , 0x8eb44a8768581511
  , 0xdb0c2e0d64f98fa7
  , 0x47b5481dbefa4fa4
  ]

h0_sha512 :: Vector Word64
h0_sha512 = Vx.fromList
  [ 0x6a09e667f3bbc908
  , 0xbb67ae8584caa73b
  , 0x3c6ef372fe94f82b
  , 0xa54ff53a5f1d36f1
  , 0x510e527fade682d1
  , 0x9b05688c2b3e6c1f
  , 0x1f83d9abfb41bd6b
  , 0x5be0cd19137e2179
  ]

h0_sha512t :: Vector Word64
h0_sha512t = Vx.map (xor 0xa5a5a5a5a5a5a5a5) h0_sha512

h0_sha512224 :: Vector Word64
h0_sha512224 = Vx.fromList
  [ 0x8c3d37c819544da2
  , 0x73e1996689dcd4d6
  , 0x1dfab7ae32ff9cb2
  , 0x679dd514582f9fcf
  , 0x0f6d2b697bd44da8
  , 0x77e36f7304c48942
  , 0x3f9d85a86a1d36c8
  , 0x1112e6ad91d692a1
  ]

h0_sha512256 :: Vector Word64
h0_sha512256 = Vx.fromList
  [ 0x22312194fc2bf72c
  , 0x9f555fa3c84c64c2
  , 0x2393b86b6f53b151
  , 0x963877195940eabd
  , 0x96283ee2a88effe3
  , 0xbe5e1e2553863992
  , 0x2b0199fc2c85b8aa
  , 0x0eb72ddc81c52ca1
  ]

-- SHA-1 hashing algorithm. Message must be of length l bits, where 
-- 0 <= l <= 2^64.



data SHA1HashValues = SHA1HashValues
  { a :: Word32
  , b :: Word32
  , c :: Word32
  , d :: Word32
  , e :: Word32 
  }

wt :: (Bits a, Vx.Unbox a) => Vector a -> Int -> a
wt msg t -- message schedule gen function. spits out words, not bit vectors
  | (0 <= t) && (t <= 15) = msg Vx.! t
  | (16 <= t) && (t <= 79) = -- this could be cleaner
      rotl 1 $ foldl1 xor [wt msg (t-3), wt msg (t-8), wt msg (t-14), wt msg (t-16)] 

sha1 :: Vector Bit -> Vector Bit 
sha1 message =
  let initHash = h0_sha1
      parsedMessage = parse512 . padMessage512 $ message
      messageLength = length parsedMessage
      prepare (_,a,b,c,d,e) = 
        castFromWords . (Vx.map fromIntegral) . Vx.fromList $ [a,b,c,d,e]
   in prepare . Vx.last $ 
        Vx.unfoldrExactN messageLength (\a -> coalg parsedMessage a) h0_sha1


messageSchedule :: Int -> [Vector Word32] -> Vector Word32
messageSchedule index parsed = Vx.fromList $ (wt $ parsed !! index) <$> [0..79] 

step3 :: w ~ Word32 => Vector w -> (w,w,w,w,w,w,Int) -> (w,w,w,w,w,w,Int) 
step3 msg startval = Vc.last $ Vc.unfoldrExactN 80 (\old@(t,e,d,c,b,a,idx) -> 
  (,) old -- this is so ugly.
    ((rotl 5 a) + (sha1Function b c d idx) + e + (sha1Constants idx) + (wt msg idx),
    d,
    c,
    rotl 30 b,
    a,
    t,
    idx+1))
  startval 

coalg :: (w ~ Word32, xx ~ (Int,w,w,w,w,w)) => [Vector w] -> xx -> (xx,xx) -- fuck you
coalg msg old@(idx,a,b,c,d,e) = (,) old $ runIdentity $ do
  let w = messageSchedule idx msg
      prepare (_,e,d,c,b,a,_) = (a,b,c,d,e)
      (a',b',c',d',e') = prepare $ step3 w (0,e,d,c,b,a,idx)
  return (idx+1,a+a',b+b',c+c',d+d',e+e')

