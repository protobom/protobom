package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
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

func (ha HashAlgorithm) ToCycloneDX() cyclonedx.HashAlgorithm {
	// TODO(degradation): The use of the following algorithms will result in
	// dataloss when rendering to CycloneDX 1.4: ADLER32 MD4 MD6 SHA224
	// Also, HashAlgorithm_UNKNOWN also means data loss.
	switch ha {
	case HashAlgorithm_MD5:
		return cdx.HashAlgoMD5
	case HashAlgorithm_SHA1:
		return cdx.HashAlgoSHA1
	case HashAlgorithm_SHA256:
		return cdx.HashAlgoSHA256
	case HashAlgorithm_SHA384:
		return cdx.HashAlgoSHA384
	case HashAlgorithm_SHA512:
		return cdx.HashAlgoSHA512
	case HashAlgorithm_SHA3_256:
		return cdx.HashAlgoSHA3_256
	case HashAlgorithm_SHA3_384:
		return cdx.HashAlgoSHA3_384
	case HashAlgorithm_SHA3_512:
		return cdx.HashAlgoBlake2b_256
	case HashAlgorithm_BLAKE2B_256:
		return cdx.HashAlgoBlake2b_256
	case HashAlgorithm_BLAKE2B_384:
		return cdx.HashAlgoBlake2b_384
	case HashAlgorithm_BLAKE2B_512:
		return cdx.HashAlgoBlake2b_512
	case HashAlgorithm_BLAKE3:
		return cdx.HashAlgoBlake3
	default:
		return cdx.HashAlgorithm("")
	}
}

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
