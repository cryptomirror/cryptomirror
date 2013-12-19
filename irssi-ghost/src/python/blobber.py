import base64

CRYPTO_MIRROR_HEADER = "+C"
CRYPTO_MIRROR_TRAILER = "=M"
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
  return CRYPTO_MIRROR_HEADER + base64.b64encode(msg) + CRYPTO_MIRROR_TRAILER

def decode_blob_string(msg):
  """
  Decode a blob string back into raw bytes
  """
  if msg[:len(CRYPTO_MIRROR_HEADER)] != CRYPTO_MIRROR_HEADER:
    raise Exception("Mismatched header")
  if msg[-len(CRYPTO_MIRROR_TRAILER):] != CRYPTO_MIRROR_TRAILER:
    raise Exception("Mismatched trailer")
  inner = msg[len(CRYPTO_MIRROR_HEADER):-len(CRYPTO_MIRROR_TRAILER)]
  return base64.b64decode(inner)

if __name__ == "__main__":
  test = make_blob_string("Hello World")
  print decode_blob_string(test)
