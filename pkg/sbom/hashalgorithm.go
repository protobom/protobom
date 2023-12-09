package sbom

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

func HashAlgorithmFromCycloneDX(cdxAlgo cdx.HashAlgorithm) HashAlgorithm {
	switch cdxAlgo {
	case cdx.HashAlgoMD5:
		return HashAlgorithm_MD5
	case cdx.HashAlgoSHA1:
		return HashAlgorithm_SHA1
	case cdx.HashAlgoSHA256:
		return HashAlgorithm_SHA256
	case cdx.HashAlgoSHA384:
		return HashAlgorithm_SHA384
	case cdx.HashAlgoSHA512:
		return HashAlgorithm_SHA512
	case cdx.HashAlgoSHA3_256:
		return HashAlgorithm_SHA3_256
	case cdx.HashAlgoSHA3_384:
		return HashAlgorithm_SHA3_384
	case cdx.HashAlgoSHA3_512:
		return HashAlgorithm_SHA3_512
	case cdx.HashAlgoBlake2b_256:
		return HashAlgorithm_BLAKE2B_256
	case cdx.HashAlgoBlake2b_384:
		return HashAlgorithm_BLAKE2B_384
	case cdx.HashAlgoBlake2b_512:
		return HashAlgorithm_BLAKE2B_512
	case cdx.HashAlgoBlake3:
		return HashAlgorithm_BLAKE3
	default:
		return HashAlgorithm_UNKNOWN
	}
}

// ToSPDX returns the SPDX label equivalent of the HashAlgorithm
func (ha HashAlgorithm) ToSPDX() common.ChecksumAlgorithm {
	switch ha {
	case HashAlgorithm_ADLER32:
		return common.ADLER32
	case HashAlgorithm_MD4:
		return common.MD4
	case HashAlgorithm_MD5:
		return common.MD5
	case HashAlgorithm_MD6:
		return common.MD6
	case HashAlgorithm_SHA1:
		return common.SHA1
	case HashAlgorithm_SHA224:
		return common.SHA224
	case HashAlgorithm_SHA256:
		return common.SHA256
	case HashAlgorithm_SHA384:
		return common.SHA384
	case HashAlgorithm_SHA512:
		return common.SHA512
	case HashAlgorithm_SHA3_256:
		return common.SHA3_256
	case HashAlgorithm_SHA3_384:
		return common.SHA3_384
	case HashAlgorithm_SHA3_512:
		return common.SHA3_512
	case HashAlgorithm_BLAKE2B_256:
		return common.BLAKE2b_256
	case HashAlgorithm_BLAKE2B_384:
		return common.BLAKE2b_384
	case HashAlgorithm_BLAKE2B_512:
		return common.BLAKE2b_512
	case HashAlgorithm_BLAKE3:
		return common.BLAKE3
	default:
		return common.ChecksumAlgorithm("")
	}
}

func HashAlgorithmFromSPDX(spdxAlgo common.ChecksumAlgorithm) HashAlgorithm {
	switch spdxAlgo {
	case common.ADLER32:
		return HashAlgorithm_ADLER32
	case common.MD4:
		return HashAlgorithm_MD4
	case common.MD5:
		return HashAlgorithm_MD5
	case common.MD6:
		return HashAlgorithm_MD6
	case common.SHA1:
		return HashAlgorithm_SHA1
	case common.SHA224:
		return HashAlgorithm_SHA224
	case common.SHA256:
		return HashAlgorithm_SHA256
	case common.SHA384:
		return HashAlgorithm_SHA384
	case common.SHA512:
		return HashAlgorithm_SHA512
	case common.SHA3_256:
		return HashAlgorithm_SHA3_256
	case common.SHA3_384:
		return HashAlgorithm_SHA3_384
	case common.SHA3_512:
		return HashAlgorithm_SHA3_512
	case common.BLAKE2b_256:
		return HashAlgorithm_BLAKE2B_256
	case common.BLAKE2b_384:
		return HashAlgorithm_BLAKE2B_384
	case common.BLAKE2b_512:
		return HashAlgorithm_BLAKE2B_512
	case common.BLAKE3:
		return HashAlgorithm_BLAKE3
	default:
		return HashAlgorithm_UNKNOWN
	}
}

// ToSPDX3 converts the hash algorithm enumeration to an SPDX3 algorithm label.
// As the SPDX3 spec is still changing these values could change at any moment
// while we track changers to the vocabulary defined here:
// https://github.com/spdx/spdx-3-model/blob/main/model/Core/Vocabularies/HashAlgorithm.md
func (ha HashAlgorithm) ToSPDX3() string {
	switch ha {
	case HashAlgorithm_MD4:
		return "md4"
	case HashAlgorithm_MD5:
		return "md5"
	case HashAlgorithm_MD6:
		return "md6"
	case HashAlgorithm_SHA1:
		return "sha1"
	case HashAlgorithm_SHA224:
		return "sha224"
	case HashAlgorithm_SHA256:
		return "sha256"
	case HashAlgorithm_SHA384:
		return "sha384"
	case HashAlgorithm_SHA512:
		return "sha512"
	case HashAlgorithm_SHA3_256:
		return "sha3_256"
	case HashAlgorithm_SHA3_384:
		return "sha3_384"
	case HashAlgorithm_SHA3_512:
		return "sha3_512"
	case HashAlgorithm_BLAKE2B_256:
		return "blake2b256"
	case HashAlgorithm_BLAKE2B_384:
		return "blake2b384"
	case HashAlgorithm_BLAKE2B_512:
		return "blake2b512"
	case HashAlgorithm_BLAKE3:
		return "blake3"
	default:
		return ""
	}
}
