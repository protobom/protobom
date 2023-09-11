# SBOM Translators Specification

## Goals
- Document decisions made by the cohort regarding the SBOM tranlation project.
- Provide a concise reference for decisions - to be later translated into design, code and test cases.
- Basis for future documentation - to allow users or the tools developed understand our translation decisions and rationale.

Notes:
-   Since most of the translation decisions are doen in the context of protobom readers and writers, this document is located here.
-   This document is a documentation platform; the discussions are to be done through GitHub issues and the cohort meetings.

# Design Decisions
Note: this section documents main design decisions - these decisions do not directly map to spec, code or test cases but they do convay our approach and our understanding of the SBOM problem space.

## A Translated SBOM is a New SBOM
-   A translated SBOM is a new SBOM - it is not a copy of the original SBOM.
-   As a result
    -   The translated SBOM-ID should be generated upon translation and not copied from the original SBOM.
    -   The creator of the SBOM should not be automatically translated from the original SBOM created.  

## Conversion Tool Should Support a Configuration File to Enable Users to Control the Translation
Uses:
-   Override tools default behavior, in cases that the default behavior reflexes a specific translation decision.
-   Enable users to add data that does not exist in the original SBOM but is required or at least supported by the target SBOM format.

# Protobom Design Decisions
## Protobom readers should not modify data


# Common Subjects


# CycloneDX <> SPDX Issues
## Populating the SPDX [SPDXID](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#63-spdx-identifier-field) field
-   The document ID will be randomized
-   Enable user to override the ID through configuration.
-   Error or warn if user provided the same document ID as from the CycloneDX SBOM.

Notes:
-   Find the discussion [here](https://github.com/bom-squad/protobom/issues/5)
-   It was discussed to approach upstream projects to solve this fundumentally.

## Populating the SPDX [Creator](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field) field
-   Since this field allows for describing the tool, we stick to the decision that the SBOM we created is a new one. 
-   Thus:
    -   The SBOM translation tool should populate this field with the string describing itself.
    -   Enable user to override the name through configuration.

Notes:
-   Find the discussion [here](https://github.com/bom-squad/protobom/issues/7)

## Populating the SPDX documentName field
-   Use the top-level SBOM component name as the SBOM name.
    - In CycloneDX this is the metadata->component->name field.
    - In the Protobom implementation - use the component name of the root node of the read-SBOM.
-   Enable user to override the name through configuration.

Notes:
-   Find the discussion [here](https://github.com/bom-squad/protobom/issues/6)



## Populating the SPDX [Primary Package Purpose](https://spdx.github.io/spdx-spec/v2.3/package-information/#724-primary-package-purpose-field) field
-   This field is to be populated from the CycloneDX component type field.
-   If the file type of the cycloneDX component is ```file``` create an SPDX file component in the translated SBOM.

Notes:
-   Find the discussion [here](https://github.com/bom-squad/protobom/issues/8)


# SPDX <> CycloneDX Issues
## Singel Top Level Component in CycloneDX vs. Multiple Top Level Components in SPDX
-   Generate a 'virtual' top level component in the translated CycloneDX SBOM.
-   The virtual top level component details:
    -   name - the (generated) SPDX DocumentName.
    -   files analyzed should be false
    -   package verification code - omitted

Notes:
-   Find the discussion [here](https://github.com/bom-squad/protobom/issues/26)