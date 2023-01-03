{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeFamilies #-}

-- As described in FIPS PUB 180-4
module Sylvinite.Hash (
    sha1,
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
) where

import qualified Control.Foldl as Fold
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Base16 as BS16
import Data.Bifunctor
import Data.Bit as Bit
import Data.Bits
import qualified Data.Vector as Vc
import qualified Data.Vector.Unboxed as Vx
import Data.Word

{-
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

sha1 :: BS.ByteString -> BS.ByteString
sha1 bs = 
  let bitvec = cloneFromByteString bs
      wordvec = sha1Internal bitvec
   in BS16.encodeBase16' . BS.concat $ 
        fmap (BSL.toStrict . BSB.toLazyByteString . BSB.word32BE) (Vx.toList wordvec) 


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

sha1Function :: Word32 -> Word32 -> Word32 -> Int -> Word32
sha1Function a b c t
    | (0 <= t) && (t <= 19) = ch a b c -- Let's make this contravariant one day!
    | (20 <= t) && (t <= 39) = parity a b c
    | (40 <= t) && (t <= 59) = maj a b c
    | (60 <= t) && (t <= 79) = parity a b c
    | otherwise =
        error
            "Hey, we should use some type wizardry to make this \
            \ unrepresentable. Like some Nat weirdness. Sandy Maguire, email me."
  where
    parity x y z = x `xor` y `xor` z

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
    [ 0x428a2f98
    , 0x71374491
    , 0xb5c0fbcf
    , 0xe9b5dba5
    , 0x3956c25b
    , 0x59f111f1
    , 0x923f82a4
    , 0xab1c5ed5
    , 0xd807aa98
    , 0x12835b01
    , 0x243185be
    , 0x550c7dc3
    , 0x72be5d74
    , 0x80deb1fe
    , 0x9bdc06a7
    , 0xc19bf174
    , 0xe49b69c1
    , 0xefbe4786
    , 0x0fc19dc6
    , 0x240ca1cc
    , 0x2de92c6f
    , 0x4a7484aa
    , 0x5cb0a9dc
    , 0x76f988da
    , 0x983e5152
    , 0xa831c66d
    , 0xb00327c8
    , 0xbf597fc7
    , 0xc6e00bf3
    , 0xd5a79147
    , 0x06ca6351
    , 0x14292967
    , 0x27b70a85
    , 0x2e1b2138
    , 0x4d2c6dfc
    , 0x53380d13
    , 0x650a7354
    , 0x766a0abb
    , 0x81c2c92e
    , 0x92722c85
    , 0xa2bfe8a1
    , 0xa81a664b
    , 0xc24b8b70
    , 0xc76c51a3
    , 0xd192e819
    , 0xd6990624
    , 0xf40e3585
    , 0x106aa070
    , 0x19a4c116
    , 0x1e376c08
    , 0x2748774c
    , 0x34b0bcb5
    , 0x391c0cb3
    , 0x4ed8aa4a
    , 0x5b9cca4f
    , 0x682e6ff3
    , 0x748f82ee
    , 0x78a5636f
    , 0x84c87814
    , 0x8cc70208
    , 0x90befffa
    , 0xa4506ceb
    , 0xbef9a3f7
    , 0xc67178f2
    ]

-- SHA-512 Constants

sha512Constants :: [Word64]
sha512Constants =
    [ 0x428a2f98d728ae22
    , 0x7137449123ef65cd
    , 0xb5c0fbcfec4d3b2f
    , 0xe9b5dba58189dbbc
    , 0x3956c25bf348b538
    , 0x59f111f1b605d019
    , 0x923f82a4af194f9b
    , 0xab1c5ed5da6d8118
    , 0xd807aa98a3030242
    , 0x12835b0145706fbe
    , 0x243185be4ee4b28c
    , 0x550c7dc3d5ffb4e2
    , 0x72be5d74f27b896f
    , 0x80deb1fe3b1696b1
    , 0x9bdc06a725c71235
    , 0xc19bf174cf692694
    , 0xe49b69c19ef14ad2
    , 0xefbe4786384f25e3
    , 0x0fc19dc68b8cd5b5
    , 0x240ca1cc77ac9c65
    , 0x2de92c6f592b0275
    , 0x4a7484aa6ea6e483
    , 0x5cb0a9dcbd41fbd4
    , 0x76f988da831153b5
    , 0x983e5152ee66dfab
    , 0xa831c66d2db43210
    , 0xb00327c898fb213f
    , 0xbf597fc7beef0ee4
    , 0xc6e00bf33da88fc2
    , 0xd5a79147930aa725
    , 0x06ca6351e003826f
    , 0x142929670a0e6e70
    , 0x27b70a8546d22ffc
    , 0x2e1b21385c26c926
    , 0x4d2c6dfc5ac42aed
    , 0x53380d139d95b3df
    , 0x650a73548baf63de
    , 0x766a0abb3c77b2a8
    , 0x81c2c92e47edaee6
    , 0x92722c851482353b
    , 0xa2bfe8a14cf10364
    , 0xa81a664bbc423001
    , 0xc24b8b70d0f89791
    , 0xc76c51a30654be30
    , 0xd192e819d6ef5218
    , 0xd69906245565a910
    , 0xf40e35855771202a
    , 0x106aa07032bbd1b8
    , 0x19a4c116b8d2d0c8
    , 0x1e376c085141ab53
    , 0x2748774cdf8eeb99
    , 0x34b0bcb5e19b48a8
    , 0x391c0cb3c5c95a63
    , 0x4ed8aa4ae3418acb
    , 0x5b9cca4f7763e373
    , 0x682e6ff3d6b2b8a3
    , 0x748f82ee5defb2fc
    , 0x78a5636f43172f60
    , 0x84c87814a1f0ab72
    , 0x8cc702081a6439ec
    , 0x90befffa23631e28
    , 0xa4506cebde82bde9
    , 0xbef9a3f7b2c67915
    , 0xc67178f2e372532b
    , 0xca273eceea26619c
    , 0xd186b8c721c0c207
    , 0xeada7dd6cde0eb1e
    , 0xf57d4f7fee6ed178
    , 0x06f067aa72176fba
    , 0x0a637dc5a2c898a6
    , 0x113f9804bef90dae
    , 0x1b710b35131c471b
    , 0x28db77f523047d84
    , 0x32caab7b40c72493
    , 0x3c9ebe0a15c9bebc
    , 0x431d67c49c100d4c
    , 0x4cc5d4becb3e42b6
    , 0x597f299cfc657e2a
    , 0x5fcb6fab3ad6faec
    , 0x6c44198c4a475817
    ]

-- Initial hash values

h0_sha1 :: w ~ Word32 => (w,w,w,w,w,w)
h0_sha1 =
    ( 0
    , 0x67452301
    , 0xefcdab89
    , 0x98badcfe
    , 0x10325476
    , 0xc3d2e1f0
    )

h0_sha224 :: Vector Word32
h0_sha224 =
    Vx.fromList
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
h0_sha384 =
    Vx.fromList
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
h0_sha512 =
    Vx.fromList
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
h0_sha512224 =
    Vx.fromList
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
h0_sha512256 =
    Vx.fromList
        [ 0x22312194fc2bf72c
        , 0x9f555fa3c84c64c2
        , 0x2393b86b6f53b151
        , 0x963877195940eabd
        , 0x96283ee2a88effe3
        , 0xbe5e1e2553863992
        , 0x2b0199fc2c85b8aa
        , 0x0eb72ddc81c52ca1
        ]

-- Pad message for SHA-1, SHA-224, SHA-256

padMessage512 :: Vector Bit -> Vector Bit
padMessage512 message =
    let messageAppend1 = message `Vx.snoc` (Bit True)
        messageLength = Vx.length message
        messageLength' = Vx.length messageAppend1
        paddingK = Vx.replicate ((448 - messageLength') `mod` 512) (Bit False)
        messageLengthBitVector = castFromWords $ Vx.singleton (fromIntegral messageLength)
        paddingL = Vx.reverse $
            (Vx.replicate (64 - Vx.length messageLengthBitVector) (Bit False))
                Vx.++ messageLengthBitVector
     in messageAppend1 Vx.++ paddingK Vx.++ paddingL

-- author's note. 2^64 bits is about 2 and a quarter exabytes. Who has a single thing
-- of that size? Facebook?
-- author's note. soon i shall deduplicate this.
-- author's note. why do i keep having these giant let bindings? maybe i should
-- use Cont or Identity monad or something for readability. or maybe arrows.

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
                Vx.++ messageLengthBitVector
     in if messageLength >= (2 ^ (128 :: Int)) -- hate you, ^
            then
                error
                    "Message is too large. What do you have \
                    \ that is possibly bigger than 2^128 bits?"
            else message Vx.++ paddingK Vx.++ paddingL

-- Parsing message for SHA-1, SHA-224, SHA-256

data WordSize = ThirtyTwo | SixtyFour deriving (Eq)

parse :: (Vx.Unbox a, Num a) => Vector Bit -> WordSize -> Vc.Vector (Vector a)
parse bitvec wordsize = smallChunks (largeChunks bitvec wordsize) wordsize

largeChunks :: Vector Bit -> WordSize -> Vc.Vector (Vector Bit)
largeChunks bitvec = \case
  ThirtyTwo -> splitAtsVec 512 bitvec
  SixtyFour -> splitAtsVec 1024 bitvec

{-
TODO: Make an Unbox instance for Vector Vector Bit. 
Should be easy, Vector Vector Bool already has one.
-}


-- Should this be hylo? It's an unfold followed by a fold, so it is.
-- It'd just look weird.
smallChunks :: (Num a, Vx.Unbox a) => Vc.Vector (Vector Bit) -> WordSize -> Vc.Vector (Vector a)
smallChunks bitvec = \case
  ThirtyTwo -> Vc.map (Vc.foldr1 (Vx.++) . splitAtsVecWord 32) bitvec
  SixtyFour -> Vc.map (Vc.foldr1 (Vx.++) . splitAtsVecWord 64) bitvec


splitAtsVec :: Int -> Vector Bit -> Vc.Vector (Vector Bit)
splitAtsVec x as = Vc.unfoldr 
  (\as -> if Vx.null as 
          then Nothing 
          else Just $ Vx.splitAt x as
  ) as

splitAtsVecWord :: (Num a, Vx.Unbox a) => Int -> Vector Bit -> Vc.Vector (Vector a)
splitAtsVecWord x as = Vc.unfoldr
  (\as -> if Vx.null as 
          then Nothing
          else Just $ first ((Vx.map fromIntegral) . cloneToWords . Vx.reverse) (Vx.splitAt x as)
  ) as

-- Makes a list of 512-bit message blocks. Sixteen 32-bit words are in each vector.
parse512 :: Vector Bit -> Vc.Vector (Vector Word32)
parse512 message = parse message ThirtyTwo

-- Parsing message for SHA-384, SHA-512, SHA-512/224, SHA-512/256

parse1024 :: Vector Bit -> Vc.Vector (Vector Word64)
parse1024 message = parse message SixtyFour

-- SHA-1 hashing algorithm. Message must be of length l bits, where
-- 0 <= l <= 2^64.

wt :: (Bits a, Vx.Unbox a) => Vector a -> Int -> a
wt msg t -- message schedule gen function. spits out words, not bit vectors
    | (0 <= t) && (t <= 15) = msg Vx.! t
    | (16 <= t) && (t <= 79) -- this could be cleaner
        =
        rotl 1 $ foldl1 xor [wt msg (t - 3), wt msg (t - 8), wt msg (t - 14), wt msg (t - 16)]
    | otherwise = error "Went past 79 in message scheduling function. How could this happen?"

-- Can I compose these folds with Applicative?
-- Can I use type families so that this works with any textlike input?
sha1Internal :: Vector Bit -> Vector Word32
sha1Internal bitvec = Fold.fold (sha1_folder :: Fold.Fold (Vector Word32) (Vector Word32)) parsed
  where parsed = parse512 . padMessage512 $ bitvec :: Vc.Vector (Vector Word32)
        k = sha1Constants
        tcalc a b c d e w idx = (rotl 5 a) + (sha1Function b c d idx) + e + (k idx) + w
        sha1_folder = Fold.Fold step begin done
        step temp messageBlock = 
          let schedule = fmap (wt messageBlock) [0..79]
           in Fold.fold (Fold.Fold step3 temp (second . step4 $ snd temp)) schedule
        begin = (0,h0_sha1)
        done (_,(_,a,b,c,d,e)) = Vx.fromList $ [a,b,c,d,e]
        step3 (idx,(t,a,b,c,d,e)) w = (idx+1,(tcalc a b c d e w idx,t,a, rotl 30 b, c, d))
        step4 (_,a,b,c,d,e) (_,a',b',c',d',e') = (0,a+a',b+b',c+c',d+d',e+e')
