package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

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
