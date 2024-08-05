# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [api/sbom.proto](#api_sbom-proto)
    - [Document](#bomsquad-protobom-Document)
    - [DocumentType](#bomsquad-protobom-DocumentType)
    - [Edge](#bomsquad-protobom-Edge)
    - [ExternalReference](#bomsquad-protobom-ExternalReference)
    - [ExternalReference.HashesEntry](#bomsquad-protobom-ExternalReference-HashesEntry)
    - [Metadata](#bomsquad-protobom-Metadata)
    - [Node](#bomsquad-protobom-Node)
    - [Node.HashesEntry](#bomsquad-protobom-Node-HashesEntry)
    - [Node.IdentifiersEntry](#bomsquad-protobom-Node-IdentifiersEntry)
    - [NodeList](#bomsquad-protobom-NodeList)
    - [Person](#bomsquad-protobom-Person)
    - [Tool](#bomsquad-protobom-Tool)
  
    - [DocumentType.SBOMType](#bomsquad-protobom-DocumentType-SBOMType)
    - [Edge.Type](#bomsquad-protobom-Edge-Type)
    - [ExternalReference.ExternalReferenceType](#bomsquad-protobom-ExternalReference-ExternalReferenceType)
    - [HashAlgorithm](#bomsquad-protobom-HashAlgorithm)
    - [Node.NodeType](#bomsquad-protobom-Node-NodeType)
    - [Purpose](#bomsquad-protobom-Purpose)
    - [SoftwareIdentifierType](#bomsquad-protobom-SoftwareIdentifierType)
  
- [Scalar Value Types](#scalar-value-types)



<a name="api_sbom-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## api/sbom.proto



<a name="bomsquad-protobom-Document"></a>

### Document
Document is the top-level structure representing the entire Software Bill of Materials (SBOM).
It serves as the core neutral ground for the SBOM translation process, encapsulating metadata,
components (nodes), and the graph structure (edges).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| metadata | [Metadata](#bomsquad-protobom-Metadata) |  | Metadata associated with the SBOM document |
| node_list | [NodeList](#bomsquad-protobom-NodeList) |  | List of nodes and edges forming the SBOM graph |






<a name="bomsquad-protobom-DocumentType"></a>

### DocumentType
DocumentType represents the type of document in the Software Bill of Materials (SBOM) ecosystem.
It categorizes the SBOM document based on its purpose or stage in the software development lifecycle.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [DocumentType.SBOMType](#bomsquad-protobom-DocumentType-SBOMType) | optional | SBOM document type. |
| name | [string](#string) | optional | Name associated with the document type. |
| description | [string](#string) | optional | Description of the document type. |






<a name="bomsquad-protobom-Edge"></a>

### Edge
Edge represents relationships between nodes in the Software Bill of Materials (SBOM) graph.
Each Edge captures the type of relationship and the nodes involved, providing a structured
way to model dependencies and connections within the SBOM.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [Edge.Type](#bomsquad-protobom-Edge-Type) |  | Type enumerator representing the node relationship. |
| from | [string](#string) |  | Source node of the edge. |
| to | [string](#string) | repeated | Target nodes of the edge. |






<a name="bomsquad-protobom-ExternalReference"></a>

### ExternalReference
ExternalReference is an entry linking an element to a resource defined outside the SBOM standard.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| url | [string](#string) |  | URL providing reference to an external resource. |
| comment | [string](#string) |  | string type = 2; // Deprecated (string) use ExternalReferenceType instead, see https://github.com/bom-squad/protobom/issues/148..

Comments associated with the external reference. |
| authority | [string](#string) |  | Authority responsible for the external reference. |
| hashes | [ExternalReference.HashesEntry](#bomsquad-protobom-ExternalReference-HashesEntry) | repeated | string type = 5; // Deprecated (string map) use hashes field instead, see https://github.com/bom-squad/protobom/issues/89.

Hashes associated with the external reference, Replaced field 5. |
| type | [ExternalReference.ExternalReferenceType](#bomsquad-protobom-ExternalReference-ExternalReferenceType) |  | Type of the external reference, Replaced field 2. |






<a name="bomsquad-protobom-ExternalReference-HashesEntry"></a>

### ExternalReference.HashesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [int32](#int32) |  |  |
| value | [string](#string) |  |  |






<a name="bomsquad-protobom-Metadata"></a>

### Metadata
Metadata encapsulates document-related details about the Software Bill of Materials (SBOM) document.
It includes information such as the document&#39;s identifier, version, authorship, creation date,
associated tools, and document types.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Unique identifier for the document. Serial number in CycloneDX foramts, SPDXID in spdx formats. |
| version | [string](#string) |  | Version of the document. In Cyclone formats the version is translated from `Int` field in to a more general `String` field. |
| name | [string](#string) |  | Name associated with the document. |
| date | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Created date of the Document. In SPDX formats mapped to the created date field. |
| tools | [Tool](#bomsquad-protobom-Tool) | repeated | Tools used in the creation or processing of the document. |
| authors | [Person](#bomsquad-protobom-Person) | repeated | Individuals or organizations involved in the creation or maintenance of the document. |
| comment | [string](#string) |  | Comments on the document. |
| documentTypes | [DocumentType](#bomsquad-protobom-DocumentType) | repeated | Types categorizing the document based on its purpose or stage in the software development lifecycle. |






<a name="bomsquad-protobom-Node"></a>

### Node
Node represents a central element within the Software Bill of Materials (SBOM) graph,
serving as a vertex that captures vital information about a software component.
Each Node in the SBOM graph signifies a distinct software component, forming the vertices of the graph.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Unique identifier for the node. |
| type | [Node.NodeType](#bomsquad-protobom-Node-NodeType) |  | Type of the software component. |
| name | [string](#string) |  | Name of the software component. |
| version | [string](#string) |  | Version string of the software component. |
| file_name | [string](#string) |  | Package filename when there is one. |
| url_home | [string](#string) |  | Website of the package. |
| url_download | [string](#string) |  | Location to download the package. |
| licenses | [string](#string) | repeated | Multiple licenses applicable to the software component, Multiple licenses can be specified for CycloneDX 1.4 and files in SPDX. |
| license_concluded | [string](#string) |  | Concluded license applicable to the software component, This is only in SPDX and it is just one. |
| license_comments | [string](#string) |  | Comments on the license. |
| copyright | [string](#string) |  | Copyright information applicable to the software component. |
| source_info | [string](#string) |  | This field is intended to capture details related to the source or origin of the software component. It may include any relevant background information or additional comments. |
| comment | [string](#string) |  | Comments on the software component. |
| summary | [string](#string) |  | Concise description of the software component (short description). |
| description | [string](#string) |  | Detailed description of the software component (full description). |
| attribution | [string](#string) | repeated | One or more contributions or acknowledgments associated with the software component. |
| suppliers | [Person](#bomsquad-protobom-Person) | repeated | One or more entities providing the software component. |
| originators | [Person](#bomsquad-protobom-Person) | repeated | One or more entities involved in the creation or maintenance of the software component. |
| release_date | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Release date of the software component. |
| build_date | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Build date of the software component. |
| valid_until_date | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Valid until date of the software component. |
| external_references | [ExternalReference](#bomsquad-protobom-ExternalReference) | repeated | External references associated with the software component. |
| file_types | [string](#string) | repeated | File types associated with the component |
| identifiers | [Node.IdentifiersEntry](#bomsquad-protobom-Node-IdentifiersEntry) | repeated | Software identifer map used by the component. Maps between the software identifier types and the identifier values. |
| hashes | [Node.HashesEntry](#bomsquad-protobom-Node-HashesEntry) | repeated | Hashes map associated with the software component. Maps between hash algorithms types and hash values. |
| primary_purpose | [Purpose](#bomsquad-protobom-Purpose) | repeated | Primary purpose or role assigned to the software component. |






<a name="bomsquad-protobom-Node-HashesEntry"></a>

### Node.HashesEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [int32](#int32) |  |  |
| value | [string](#string) |  |  |






<a name="bomsquad-protobom-Node-IdentifiersEntry"></a>

### Node.IdentifiersEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [int32](#int32) |  |  |
| value | [string](#string) |  |  |






<a name="bomsquad-protobom-NodeList"></a>

### NodeList
NodeList represents a collection of nodes and edges forming the Software Bill of Materials (SBOM) graph.
It encapsulates the fundamental components of the SBOM, including software entities (nodes) and their relationships (edges).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [Node](#bomsquad-protobom-Node) | repeated | List of software components (nodes) in the SBOM graph. |
| edges | [Edge](#bomsquad-protobom-Edge) | repeated | List of relationships (edges) between nodes in the SBOM graph. |
| root_elements | [string](#string) | repeated | List of root elements in the SBOM graph. |






<a name="bomsquad-protobom-Person"></a>

### Person
Person represents an individual or organization involved in the creation or maintenance
of the document or node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name of the person or organization. |
| is_org | [bool](#bool) |  | Indicates whether the entity is an organization (true) or an individual (false). |
| email | [string](#string) |  | Email address of the person or organization. |
| url | [string](#string) |  | URL associated with the person or organization. |
| phone | [string](#string) |  | Phone number associated with the person or organization. |
| contacts | [Person](#bomsquad-protobom-Person) | repeated | Contacts associated with the person or organization. |






<a name="bomsquad-protobom-Tool"></a>

### Tool
Tool represents a software tool used in the creation or processing of the Software Bill of Materials (SBOM) document.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name of the software tool. |
| version | [string](#string) |  | Version of the software tool. |
| vendor | [string](#string) |  | Vendor or creator of the software tool. |





 


<a name="bomsquad-protobom-DocumentType-SBOMType"></a>

### DocumentType.SBOMType
Enumeration of SBOM document types.

| Name | Number | Description |
| ---- | ------ | ----------- |
| OTHER | 0 | Other document type. |
| DESIGN | 1 | Design document type. (CDX: design) |
| SOURCE | 2 | Source document type. (CDX: pre-build) |
| BUILD | 3 | Build document type. (CDX: build) |
| ANALYZED | 4 | Analyzed document type. (CDX: post-build) |
| DEPLOYED | 5 | Deployed document type. (CDX: operations) |
| RUNTIME | 6 | Runtime document type. (CDX: none) |
| DISCOVERY | 7 | Discovery document type. (CDX Specific) |
| DECOMISSION | 8 | Decommission document type. (CDX Specific) |



<a name="bomsquad-protobom-Edge-Type"></a>

### Edge.Type
Type enumerator representing the node relationship.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 | Unknown type. |
| amends | 1 | Amends relationship type. |
| ancestor | 2 | Ancestor relationship type. |
| buildDependency | 3 | Build dependency relationship type. |
| buildTool | 4 | Build tool relationship type. |
| contains | 5 | Contains relationship type. |
| contained_by | 6 | Contained by relationship type. In SPDX 3.x, this field is not supported. |
| copy | 7 | Copy relationship type. |
| dataFile | 8 | Data file relationship type. |
| dependencyManifest | 9 | Dependency manifest relationship type. |
| dependsOn | 10 | Depends on relationship type. |
| dependencyOf | 11 | Dependency of relationship type. In SPDX 3.x, this field is not supported. |
| descendant | 12 | Descendant relationship type. |
| describes | 13 | Describes relationship type. |
| describedBy | 14 | Described by relationship type. In SPDX 3.x, this field is not supported. |
| devDependency | 15 | Development dependency relationship type. |
| devTool | 16 | Development tool relationship type. |
| distributionArtifact | 17 | Distribution artifact relationship type. |
| documentation | 18 | Documentation relationship type. |
| dynamicLink | 19 | Dynamic link relationship type. |
| example | 20 | Example relationship type. |
| expandedFromArchive | 21 | Expanded from archive relationship type. |
| fileAdded | 22 | File added relationship type. |
| fileDeleted | 23 | File deleted relationship type. |
| fileModified | 24 | File modified relationship type. |
| generates | 25 | Generates relationship type. |
| generatedFrom | 26 | Generated from relationship type. In SPDX 3.x, this field is not supported. |
| metafile | 27 | Metafile relationship type. |
| optionalComponent | 28 | Optional component relationship type. |
| optionalDependency | 29 | Optional dependency relationship type. |
| other | 30 | Other relationship type. |
| packages | 31 | Packages relationship type. |
| patch | 32 | Patch relationship type. |
| prerequisite | 33 | Prerequisite relationship type. |
| prerequisiteFor | 34 | Prerequisite for relationship type. In SPDX 3.x, this field is not supported. |
| providedDependency | 35 | Provided dependency relationship type. |
| requirementFor | 36 | Requirement for relationship type. |
| runtimeDependency | 37 | Runtime dependency relationship type. |
| specificationFor | 38 | Specification for relationship type. |
| staticLink | 39 | Static link relationship type. |
| test | 40 | Test relationship type. |
| testCase | 41 | Test case relationship type. |
| testDependency | 42 | Test dependency relationship type. |
| testTool | 43 | Test tool relationship type. |
| variant | 44 | Variant relationship type. |



<a name="bomsquad-protobom-ExternalReference-ExternalReferenceType"></a>

### ExternalReference.ExternalReferenceType
Type enumerator representing of the external reference.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 | Unknown type. |
| ATTESTATION | 1 | Attestation type. |
| BINARY | 2 | Binary type. |
| BOM | 3 | BOM type. |
| BOWER | 4 | Bower type. |
| BUILD_META | 5 | Build meta type. |
| BUILD_SYSTEM | 6 | Build system type. |
| CERTIFICATION_REPORT | 7 | Certification report type. |
| CHAT | 8 | Chat type. |
| CODIFIED_INFRASTRUCTURE | 9 | Codified infrastructure type. |
| COMPONENT_ANALYSIS_REPORT | 10 | Component analysis report type. |
| CONFIGURATION | 11 | Configuration type. |
| DISTRIBUTION_INTAKE | 12 | Distribution intake type. |
| DOCUMENTATION | 13 | Documentation type. |
| DOWNLOAD | 14 | Download type. |
| DYNAMIC_ANALYSIS_REPORT | 15 | Dynamic analysis report type. |
| EOL_NOTICE | 16 | End-of-life notice type. |
| EVIDENCE | 17 | Evidence type. |
| EXPORT_CONTROL_ASSESSMENT | 18 | Export control assessment type. |
| FORMULATION | 19 | Formulation type. |
| FUNDING | 20 | Funding type. |
| ISSUE_TRACKER | 21 | Issue tracker type. |
| LICENSE | 22 | License type. |
| LOG | 23 | Log type. |
| MAILING_LIST | 24 | Mailing list type. |
| MATURITY_REPORT | 25 | Maturity report type. |
| MAVEN_CENTRAL | 26 | Maven Central type. |
| METRICS | 27 | Metrics type. |
| MODEL_CARD | 28 | Model card type. |
| NPM | 29 | NPM type. |
| NUGET | 30 | NuGet type. |
| OTHER | 31 | Other type. |
| POAM | 32 | POAM type. |
| PRIVACY_ASSESSMENT | 33 | Privacy assessment type. |
| PRODUCT_METADATA | 34 | Product metadata type. |
| PURCHASE_ORDER | 35 | Purchase order type. |
| QUALITY_ASSESSMENT_REPORT | 36 | Quality assessment report type. |
| QUALITY_METRICS | 37 | Quality metrics type. |
| RELEASE_HISTORY | 38 | Release history type. |
| RELEASE_NOTES | 39 | Release notes type. |
| RISK_ASSESSMENT | 40 | Risk assessment type. |
| RUNTIME_ANALYSIS_REPORT | 41 | Runtime analysis report type. |
| SECURE_SOFTWARE_ATTESTATION | 42 | Secure software attestation type. |
| SECURITY_ADVERSARY_MODEL | 43 | Security adversary model type. |
| SECURITY_ADVISORY | 44 | Security advisory type. |
| SECURITY_CONTACT | 45 | Security contact type. |
| SECURITY_FIX | 46 | Security fix type. |
| SECURITY_OTHER | 47 | Security other type. |
| SECURITY_PENTEST_REPORT | 48 | Security pentest report type. |
| SECURITY_POLICY | 49 | Security policy type. |
| SECURITY_SWID | 50 | Security SWID type. |
| SECURITY_THREAT_MODEL | 51 | Security threat model type. |
| SOCIAL | 52 | Social type. |
| SOURCE_ARTIFACT | 53 | Source artifact type. |
| STATIC_ANALYSIS_REPORT | 54 | Static analysis report type. |
| SUPPORT | 55 | Support type. |
| VCS | 56 | VCS type. |
| VULNERABILITY_ASSERTION | 57 | Vulnerability assertion type. |
| VULNERABILITY_DISCLOSURE_REPORT | 58 | Vulnerability disclosure report type. |
| VULNERABILITY_EXPLOITABILITY_ASSESSMENT | 59 | Vulnerability exploitability assessment type. |
| WEBSITE | 60 | Website type. |



<a name="bomsquad-protobom-HashAlgorithm"></a>

### HashAlgorithm
HashAlgorithm represents the hashing algorithms used within the Software Bill of Materials (SBOM) document.
It enumerates various hash algorithms that can be employed to generate checksums or unique identifiers for files or data.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 | Unknown hash algorithm. |
| MD5 | 1 | MD5 hash algorithm. |
| SHA1 | 2 | SHA-1 hash algorithm. |
| SHA256 | 3 | SHA-256 hash algorithm. |
| SHA384 | 4 | SHA-384 hash algorithm. |
| SHA512 | 5 | SHA-512 hash algorithm. |
| SHA3_256 | 6 | SHA3-256 hash algorithm. |
| SHA3_384 | 7 | SHA3-384 hash algorithm. |
| SHA3_512 | 8 | SHA3-512 hash algorithm. |
| BLAKE2B_256 | 9 | BLAKE2B-256 hash algorithm. |
| BLAKE2B_384 | 10 | BLAKE2B-384 hash algorithm. |
| BLAKE2B_512 | 11 | BLAKE2B-512 hash algorithm. |
| BLAKE3 | 12 | BLAKE3 hash algorithm. |
| MD2 | 13 | MD2 hash algorithm, not supported by SPDX formats. |
| ADLER32 | 14 | Adler-32 hash algorithm, not supported by SPDX formats.. |
| MD4 | 15 | MD4 hash algorithm, not supported by SPDX formats.. |
| MD6 | 16 | MD6 hash algorithm, not supported by SPDX formats.. |
| SHA224 | 17 | SHA-224 hash algorithm, not supported by SPDX formats.. |



<a name="bomsquad-protobom-Node-NodeType"></a>

### Node.NodeType
Type of the software component.

| Name | Number | Description |
| ---- | ------ | ----------- |
| PACKAGE | 0 | Software component type is a package. |
| FILE | 1 | Software component type is a file. |



<a name="bomsquad-protobom-Purpose"></a>

### Purpose
Purpose represents different purposes or roles assigned to software entities within the Software Bill of Materials (SBOM).
It categorizes the roles that software components can fulfill.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_PURPOSE | 0 | Unknown purpose. |
| APPLICATION | 1 | Application purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| ARCHIVE | 2 | Archive purpose. (SPDX2.3, SPDX3.0) |
| BOM | 3 | BOM purpose. (SPDX3.0) |
| CONFIGURATION | 4 | Configuration purpose. (SPDX3.0) |
| CONTAINER | 5 | Container purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| DATA | 6 | Data purpose. (CDX1.5, SPDX3.0) |
| DEVICE | 7 | Device purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| DEVICE_DRIVER | 8 | Device Driver purpose. (CDX1.5, SPDX3.0) |
| DOCUMENTATION | 9 | Documentation purpose. (SPDX3.0) |
| EVIDENCE | 10 | Evidence purpose. (SPDX3.0) |
| EXECUTABLE | 11 | Executable purpose. (SPDX3.0) |
| FILE | 12 | File purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| FIRMWARE | 13 | Firmware purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| FRAMEWORK | 14 | Framework purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| INSTALL | 15 | Install purpose. (SPDX2.3, SPDX3.0) |
| LIBRARY | 16 | Library purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| MACHINE_LEARNING_MODEL | 17 | Machine Learning Model purpose. (CDX1.5) |
| MANIFEST | 18 | Manifest purpose. (SPDX3.0) |
| MODEL | 19 | Model purpose. (SPDX3.0) |
| MODULE | 20 | Module purpose. (SPDX3.0) |
| OPERATING_SYSTEM | 21 | Operating System purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| OTHER | 22 | Other purpose. (SPDX2.3, SPDX3.0) |
| PATCH | 23 | Patch purpose. (SPDX3.0) |
| PLATFORM | 24 | Platform purpose. (SPDX2.3, CDX1.5, SPDX3.0) |
| REQUIREMENT | 25 | Requirement purpose. (SPDX3.0) |
| SOURCE | 26 | Source purpose. (SPDX2.3, SPDX3.0) |
| SPECIFICATION | 27 | Specification purpose. (SPDX3.0) |
| TEST | 28 | Test purpose. (SPDX3.0) |



<a name="bomsquad-protobom-SoftwareIdentifierType"></a>

### SoftwareIdentifierType
SoftwareIdentifierType represents different types of identifiers used for software entities within the Software Bill of Materials (SBOM).

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_IDENTIFIER_TYPE | 0 | Unknown software identifier type. |
| PURL | 1 | Package URL (PURL) identifier type. |
| CPE22 | 2 | Common Platform Enumeration (CPE) version 2.2 identifier type. |
| CPE23 | 3 | Common Platform Enumeration (CPE) version 2.3 identifier type. |
| GITOID | 4 | Git Object Identifier (OID) identifier type. |


 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

