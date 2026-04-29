/*
 * Copyright (c) 2024-2025 European Commission
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

package eu.europa.ec.eudi.iso18013.transfer.response.device

import eu.europa.ec.eudi.iso18013.transfer.asMap
import eu.europa.ec.eudi.iso18013.transfer.internal.DocumentResponseGenerator.generateDocumentResponse
import eu.europa.ec.eudi.iso18013.transfer.internal.assertAgeOverRequestLimitForIso18013
import eu.europa.ec.eudi.iso18013.transfer.internal.filterWithRequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.internal.getValidIssuedMsoMdocDocumentById
import eu.europa.ec.eudi.iso18013.transfer.internal.getValidJwtVcJsonDocumentById
import eu.europa.ec.eudi.iso18013.transfer.internal.getValidLdpVcDocumentById
import eu.europa.ec.eudi.iso18013.transfer.internal.getValidSdJwtDocumentById
import eu.europa.ec.eudi.wallet.document.format.LdpVcFormat
import eu.europa.ec.eudi.wallet.document.generateLdpVcVp
import java.security.MessageDigest
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import kotlinx.coroutines.runBlocking
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.Tagged
import org.multipaz.crypto.Algorithm
import org.multipaz.mdoc.response.DeviceResponseGenerator
import org.multipaz.util.Constants

/**
 * Implementation of [RequestProcessor.ProcessedRequest.Success] for [DeviceRequest].
 * @property documentManager the document manager to use for resolving documents
 * @property sessionTranscript the session transcript
 * @property requestedDocuments the requested documents
 * @property includeOnlyRequested whether to include only the requested documents or all the disclosed documents. Default is true.
 */
class ProcessedDeviceRequest(
    private val documentManager: DocumentManager,
    private val sessionTranscript: ByteArray,
    requestedDocuments: RequestedDocuments,
    val requestedDocTypes: Array<String>,
    val verifierName: String
) : RequestProcessor.ProcessedRequest.Success(requestedDocuments) {

    var includeOnlyRequested: Boolean = true

    /**
     * Generate the response for the disclosed documents.
     * @param disclosedDocuments the disclosed documents
     * @param signatureAlgorithm the signature algorithm to use for the document responses
     * @return the response result with the device response or the error
     */
    override fun generateResponse(
        disclosedDocuments: DisclosedDocuments,
        signatureAlgorithm: Algorithm? // TODO: signatureAlgorithm remove this parameter ?
    ): ResponseResult {
        try {
            val documentIds = mutableListOf<DocumentId>()
            val deviceResponse = DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)
            disclosedDocuments
                .let {
                    if (includeOnlyRequested) it.filterWithRequestedDocuments(requestedDocuments)
                    else it
                }
                .forEachIndexed { index, disclosedDocument ->
                    android.util.Log.d("BLE_ITEMS", "format=${disclosedDocument.format} items=${disclosedDocument.disclosedItems}")
                    android.util.Log.d("BLE_ITEMS", "asMap=${disclosedDocument.disclosedItems.asMap()}")
                    if (disclosedDocument.format == "cbor") {
                        val documentResponse = runBlocking {
                            documentManager
                                .getValidIssuedMsoMdocDocumentById(disclosedDocument.documentId)
                                .assertAgeOverRequestLimitForIso18013(disclosedDocument)
                                .generateDocumentResponse(
                                    transcript = sessionTranscript,
                                    elements = disclosedDocument.disclosedItems.asMap(),
                                    keyUnlockData = disclosedDocument.keyUnlockData,
                                    //signatureAlgorithm = signatureAlgorithm ?: Algorithm.ES256
                                )
                                .getOrThrow()
                        }
                        deviceResponse.addDocument(documentResponse)
                        documentIds.add(disclosedDocument.documentId)
                    } else {
                        val documentResponse = runBlocking {
                            if (disclosedDocument.format == "ldp_vc") {
                                val doc = documentManager.getValidLdpVcDocumentById(disclosedDocument.documentId)
                                val transcriptTag24 = Cbor.encode(Tagged(24, Bstr(sessionTranscript)))
                                val nonce = MessageDigest.getInstance("SHA-256")
                                    .digest(transcriptTag24)
                                    .joinToString("") { "%02x".format(it) }
                                val docType = (doc.format as LdpVcFormat).types.last()
                                val vpJson = doc.generateLdpVcVp(nonce, "ble", disclosedDocument.keyUnlockData)
                                val mapBuilder = CborMap.builder()
                                mapBuilder.put("docType", docType)
                                mapBuilder.put("ldpVc", vpJson)
                                Cbor.encode(mapBuilder.end().build())
                            } else {
                                val doc = when (disclosedDocument.format) {
                                    "vc+sd-jwt", "dc+sd-jwt", "sd-jwt" -> documentManager.getValidSdJwtDocumentById(disclosedDocument.documentId)
                                    "jwt_vc_json", "jwt_vc", "vc+jwt", "w3cjwt" -> documentManager.getValidJwtVcJsonDocumentById(disclosedDocument.documentId)
                                    else -> throw IllegalArgumentException("Unsupported format: ${disclosedDocument.format}")
                                }
                                doc.generateDocumentResponse(
                                    transcript = sessionTranscript,
                                    elements = disclosedDocument.disclosedItems.asMap(),
                                    keyUnlockData = disclosedDocument.keyUnlockData,
                                ).getOrThrow()
                            }
                        }
                        val documentsArray = CborArray.builder()
                        documentsArray.add(Cbor.decode(documentResponse))
                        val mapBuilder = CborMap.builder()
                        mapBuilder.put("version", "1.0")
                        mapBuilder.put("documents", documentsArray.end().build())
                        mapBuilder.put("status", Constants.DEVICE_RESPONSE_STATUS_OK)
                            .end()

                        documentIds.add(disclosedDocument.documentId)
                        return ResponseResult.Success(
                            DeviceResponse(
                                deviceResponseBytes = Cbor.encode(mapBuilder.end().build()),
                                sessionTranscriptBytes = sessionTranscript,
                                documentIds = documentIds
                            )
                        )
                    }
                }
            val responseBytes = deviceResponse.generate()
            val hex = responseBytes.joinToString("") { "%02x".format(it) }
            hex.chunked(800).forEachIndexed { i, chunk ->
                android.util.Log.d("BLE_CBOR", "[$i] $chunk")
            }
            return ResponseResult.Success(
                DeviceResponse(
                    deviceResponseBytes = responseBytes,
                    sessionTranscriptBytes = sessionTranscript,
                    documentIds = documentIds
                )
            )
        } catch (e: Exception) {
            return ResponseResult.Failure(e)
        }
    }

}