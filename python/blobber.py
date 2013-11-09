CRYPTO_MIRROR_HEADER = "+CRYPTO"
CRYPTO_MIRROR_TRAILER = "+MIRROR"
BLOB_LIMIT = 32
BLOB_SIZE_LIMIT = 1024*1024

def extract_blobs(msg):
  """
  Extract all blobs from a message
  """
  blobs = []
  i = msg.find(CRYPTO_MIRROR_HEADER, i)
  while i != -1:
    j = msg.find(CRYPTO_MIRROR_TRAILER, i)
    if (j != -1):
      if (j - i < BLOB_SIZE_LIMIT):
        blobs += msg[i:j]
        if len(blobs) > BLOB_LIMIT:
          break
    i = msg.find(CRYPTO_MIRROR_HEADER, i+1)
  return blobs

def make_blob_string(msg):
  """
  Make a single blob string
  """
  return CRYPTO_MIRROR_HEADER + msg.encode("base64")[:-1] + CRYPTO_MIRROR_TRAILER

def decode_blob_string(msg):
  """
  Decode a blob string back into raw bytes
  """
  if msg[:len(CRYPTO_MIRROR_HEADER)] != CRYPTO_MIRROR_HEADER:
    raise Exception("Mismatched header")
  if msg[-len(CRYPTO_MIRROR_TRAILER):] != CRYPTO_MIRROR_TRAILER:
    raise Exception("Mismatched trailer")
  inner = msg[len(CRYPTO_MIRROR_HEADER):-len(CRYPTO_MIRROR_TRAILER)]
  return inner.decode("base64")

if __name__ == "__main__":
  test = make_blob_string("Hello World")
  print decode_blob_string(test)
