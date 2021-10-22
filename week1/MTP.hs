module MTP where

import Data.Binary (Word8)
import Data.Bits   (xor)
import Data.Char   (chr, isAlpha)
import Data.Ord    (comparing)
import Data.List   (maximumBy, sortOn)
import qualified Data.ByteString as B
import qualified Data.Map.Strict as M

main :: IO ()
main = do
    cts <- lines <$> readFile "ciphers.txt"
    let Right pts = decrypt cts
    sequence_ [putStrLn $ "Text #" ++ show i ++ "\n" ++ pt ++ "\n" | 
               (i, pt) <- zip [1..] pts]

decrypt :: [String] -> Either String [String]
decrypt cts = do 
    bss <- mapM hexToBytes cts
    let key = getKey bss
    Right [chr . fromEnum <$> B.zipWith xor bs key | bs <- bss]

hexToBytes :: String -> Either String B.ByteString
hexToBytes []   = Left "Error: no hexademical characters provided"
hexToBytes xs
    | valid xs  = B.pack . map toEnum <$> go xs []
    | otherwise = Left "Error: text contains invalid hexadecimal characters"
    where
        hexChars         = ['0'..'9'] ++ ['A'..'F'] ++ ['a'..'f']
        hexVals          = [0..9] ++ [10..15] ++ [10..15]
        hexMap           = M.fromList $ zip hexChars hexVals
        valid h          = even (length h) && all (`M.member` hexMap) h
        go [] acc        = Right $ reverse acc
        go [_] _         = Left "Error: hex string must be even length"
        go (y:y':ys) acc = let (d1, d2) = ((hexMap M.! y) * 16, hexMap M.! y') 
                           in go ys (d1 + d2 : acc)

getKey :: [B.ByteString] -> B.ByteString
getKey bss = B.pack [keyChar i (pairs bss) | i <- [0..maxLen bss]]
    where 
        pairs xs   = let enumXs = zip [0..] xs 
                     in [(x, x') | (i, x) <- enumXs, (j, x') <- enumXs, i < j]
        maxLen []  = 0
        maxLen bss = (B.length . head $ sortOn B.length bss) - 1

keyChar :: Int -> [(B.ByteString, B.ByteString)] -> Word8
keyChar i cps = getMax $ go cps M.empty
    where
        getMax lc            = fst . maximumBy (comparing snd) . M.toList $ lc
        go [] lc             = lc
        go ((c1, c2):cps) lc =
            go cps $ update (c1 `B.index` i) (c2 `B.index` i) lc
        xorSp = xor (32 :: Word8)
        update b b' lc
            | isAlpha (chr . fromEnum $ b `xor` b') =
                  M.unionWith (+) lc (M.fromList [(xorSp b, 1), (xorSp b', 1)])
            | otherwise = lc