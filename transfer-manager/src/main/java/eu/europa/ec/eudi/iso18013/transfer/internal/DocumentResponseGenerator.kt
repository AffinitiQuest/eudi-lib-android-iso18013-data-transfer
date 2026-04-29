/*
 * Copyright (c) 2024 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.iso18013.transfer.internal

import eu.europa.ec.eudi.wallet.document.ElementIdentifier
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.NameSpace
import eu.europa.ec.eudi.wallet.document.credential.CredentialIssuedData
import eu.europa.ec.eudi.wallet.document.credential.getIssuedData
import eu.europa.ec.eudi.wallet.document.format.LdpVcData
import eu.europa.ec.eudi.wallet.document.format.LdpVcFormat
import eu.europa.ec.eudi.wallet.document.format.MsoMdocData
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcData
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.document.format.W3CJwtData
import eu.europa.ec.eudi.wallet.document.format.W3CJwtFormat
import kotlinx.coroutines.runBlocking
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.RawCbor
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.document.DocumentRequest
import org.multipaz.document.NameSpacedData
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.response.DocumentGenerator
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.securearea.KeyUnlockData

internal object DocumentResponseGenerator {

    /**
     * Generate a device response for a given document.
     *
     * Document must be in MsoMdocFormat and not have an invalidated key.
     *
     * @param document the document to generate the response for
     * @param transcript the transcript to use for the response
     * @param elements the elements to include in the response
     * @param keyUnlockData the key unlock data for unlocking the document key if needed
     * @throws IllegalArgumentException if the document format is not MsoMdocFormat, the document key is invalidated,
     * @throws org.multipaz.securearea.KeyLockedException if the document key is locked and cannot be unlocked
     */
    @JvmStatic
    @JvmOverloads
    fun generate(
        document: IssuedDocument,
        transcript: ByteArray,
        elements: Map<NameSpace, List<ElementIdentifier>>? = null,
        keyUnlockData: KeyUnlockData? = null
    ): ByteArray {
        return runBlocking {
            document.consumingCredential {
                if(document.data is MsoMdocData) {
                    require(this is MdocCredential) { "Document must be in MsoMdocFormat" }
                    val credentialIssuedData =
                        getIssuedData<CredentialIssuedData.MsoMdoc>()
                    val (nameSpacedData, staticAuthData) = credentialIssuedData.getOrThrow()
                    val dataElements = (elements ?: nameSpacedData.nameSpaceNames.associateWith {
                        nameSpacedData.getDataElementNames(it)
                    }).flatMap { (nameSpace, elementIdentifiers) ->
                        elementIdentifiers.map { elementIdentifier ->
                            DocumentRequest.DataElement(nameSpace, elementIdentifier, false)
                        }
                    }

                    val request = DocumentRequest(dataElements)

                    val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
                        request, nameSpacedData, staticAuthData
                    )
                    DocumentGenerator(docType, staticAuthData.issuerAuth, transcript)
                        .setIssuerNamespaces(mergedIssuerNamespaces)
                        .setDeviceNamespacesSignature(
                            dataElements = NameSpacedData.Builder().build(),
                            secureArea = secureArea,
                            keyAlias = alias,
                            keyUnlockData = keyUnlockData
                        )
                        .generate()
                } else {
                    suspend fun buildDeviceAuth(docType: String): DataItem {
                        val deviceAuthentication = Cbor.encode(
                            CborArray.builder()
                                .add("DeviceAuthentication")
                                .add(RawCbor(transcript))
                                .add(docType)
                                .addTaggedEncodedCbor(byteArrayOf(0xA0.toByte()))
                                .end()
                                .build()
                        )
                        val deviceAuthenticationBytes = Cbor.encode(Tagged(24, Bstr(deviceAuthentication)))
                        val encodedDeviceSignature = Cbor.encode(
                            Cose.coseSign1Sign(
                                document.secureArea,
                                document.keyAlias,
                                deviceAuthenticationBytes,
                                false,
                                mapOf(
                                    Pair(
                                        CoseNumberLabel(Cose.COSE_LABEL_ALG),
                                        Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem()
                                    )
                                ),
                                mapOf<CoseLabel, DataItem>(),
                                keyUnlockData
                            ).toDataItem()
                        )
                        val deviceSignedMap = CborMap.builder()
                        deviceSignedMap.put("deviceSignature", Cbor.decode(encodedDeviceSignature))
                        return deviceSignedMap.end().build()
                    }

                    when (val documentData = document.data) {
                        is W3CJwtData -> {
                            val docType = documentData.format.types.last()
                            val mapBuilder = CborMap.builder()
                            mapBuilder.put("docType", docType)
                            mapBuilder.put("jwt", String(document.issuerProvidedData))
                            mapBuilder.put("deviceAuth", buildDeviceAuth(docType))
                            Cbor.encode(mapBuilder.end().build())
                        }
                        is SdJwtVcData -> {
                            val vct = documentData.format.vct
                            val mapBuilder = CborMap.builder()
                            mapBuilder.put("docType", vct)
                            mapBuilder.put("sdJwt", String(document.issuerProvidedData))
                            mapBuilder.put("deviceAuth", buildDeviceAuth(vct))
                            Cbor.encode(mapBuilder.end().build())
                        }
                        is LdpVcData -> {
                            val docType = documentData.format.types.last()
                            val mapBuilder = CborMap.builder()
                            mapBuilder.put("docType", docType)
                            mapBuilder.put("ldpVc", String(document.issuerProvidedData))
                            mapBuilder.put("deviceAuth", buildDeviceAuth(docType))
                            Cbor.encode(mapBuilder.end().build())
                        }
                        else -> throw IllegalArgumentException("Unsupported document format: ${document.data?.javaClass?.simpleName}")
                    }
                }
            }.getOrThrow()
        }
    }

    fun IssuedDocument.generateDocumentResponse(
        transcript: ByteArray,
        elements: Map<NameSpace, List<ElementIdentifier>>? = null,
        keyUnlockData: KeyUnlockData? = null
    ): Result<ByteArray> {
        return try {
            Result.success(
                generate(
                    this,
                    transcript,
                    elements,
                    keyUnlockData
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}