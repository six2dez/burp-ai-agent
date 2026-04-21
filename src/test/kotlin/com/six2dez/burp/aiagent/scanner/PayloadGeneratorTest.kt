package com.six2dez.burp.aiagent.scanner

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PayloadGeneratorTest {
    private val generator = PayloadGenerator()

    @Test
    fun quickPayloadsRespectRiskLevel() {
        val safeOnly = generator.getQuickPayloads(VulnClass.SQLI, PayloadRisk.SAFE)
        val withModerate = generator.getQuickPayloads(VulnClass.SQLI, PayloadRisk.MODERATE)

        assertTrue(safeOnly.isNotEmpty())
        assertTrue(safeOnly.all { it.risk <= PayloadRisk.SAFE })
        assertTrue(withModerate.size >= safeOnly.size)
        assertTrue(withModerate.any { it.risk == PayloadRisk.MODERATE })
    }

    @Test
    fun generatesIdorPayloadsForNumericValues() {
        val payloads = generator.generateContextAwarePayloads(VulnClass.IDOR, "42", maxPayloads = 10)
        val values = payloads.map { it.value }

        assertTrue(values.contains("41"))
        assertTrue(values.contains("43"))
        assertTrue(values.contains("1"))
        assertTrue(values.contains("0"))
        assertTrue(values.contains("-1"))
    }

    @Test
    fun generatesIdorPayloadForUuid() {
        val uuid = "123e4567-e89b-12d3-a456-426614174000"
        val payloads = generator.generateContextAwarePayloads(VulnClass.IDOR, uuid, maxPayloads = 10)

        assertTrue(payloads.any { it.value != uuid && it.value.length == uuid.length })
    }

    @Test
    fun generatesSqliPayloadsByInputType() {
        val numericPayloads = generator.generateContextAwarePayloads(VulnClass.SQLI, "123", maxPayloads = 5)
        val stringPayloads = generator.generateContextAwarePayloads(VulnClass.SQLI, "admin", maxPayloads = 5)

        assertTrue(numericPayloads.any { it.value.contains("123 AND 1=1") })
        assertTrue(numericPayloads.any { it.value.contains("123 AND 1=2") })
        assertTrue(stringPayloads.any { it.value.contains("admin' AND '1'='1") })
        assertTrue(stringPayloads.any { it.value.contains("admin' AND '1'='2") })
        assertEquals(DetectionMethod.BLIND_BOOLEAN, numericPayloads.first().detectionMethod)
    }
}
