package com.v2ray.ang.core

import com.google.gson.JsonObject
import com.tencent.mmkv.MMKV
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.V2rayConfig.OutboundBean
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.handler.MmkvManager
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.mock

class CoreOutboundBuilderMasqueTest {

    @Test
    fun masqueTransportCarriesAuthorityPathCredentialsAndHeaders() {
        val stream = OutboundBean.StreamSettingsBean()
        val profile = ProfileItem(
            configType = EConfigType.MASQUE,
            network = NetworkType.MASQUE.type,
            security = AppConfig.TLS,
            username = "u",
            password = "pass",
            host = "cdn.example.com:8443",
            path = "/.well-known/masque/ip/*/*/",
            masqueHeaders = """{"User-Agent":"chrome","X-Token":"abc"}""",
        )

        CoreOutboundBuilder.populateTransportSettings(stream, profile)

        assertEquals(NetworkType.MASQUE.type, stream.network)
        val settings = stream.masqueSettings
        assertNotNull(settings)
        assertEquals("cdn.example.com:8443", settings?.host)
        assertEquals("/.well-known/masque/ip/*/*/", settings?.path)
        assertEquals("u", settings?.user)
        assertEquals("pass", settings?.pass)
        val headers = settings?.headers as? JsonObject
        assertEquals("chrome", headers?.get("User-Agent")?.asString)
        assertEquals("abc", headers?.get("X-Token")?.asString)
    }

    @Test
    fun masqueTransportOmitsBlankOptionalSettings() {
        val stream = OutboundBean.StreamSettingsBean()
        val profile = ProfileItem(
            configType = EConfigType.MASQUE,
            network = NetworkType.MASQUE.type,
            security = AppConfig.TLS,
        )

        CoreOutboundBuilder.populateTransportSettings(stream, profile)

        val settings = stream.masqueSettings
        assertNotNull(settings)
        assertNull(settings?.host)
        assertNull(settings?.path)
        assertNull(settings?.user)
        assertNull(settings?.pass)
        assertNull(settings?.headers)
    }

    @Test
    fun createInitOutboundReturnsMasqueTemplate() {
        val outbound = CoreOutboundBuilder.createInitOutbound(EConfigType.MASQUE)

        assertNotNull(outbound)
        assertEquals("masque", outbound?.protocol)
        assertNotNull(outbound?.settings)
        assertNotNull(outbound?.streamSettings)
    }

    @Test
    fun convertBuildsMasqueOutboundWithRemoteDnsAndDisabledMux() {
        val profile = ProfileItem(
            configType = EConfigType.MASQUE,
            server = "example.com",
            serverPort = "443",
            username = "u",
            password = "p",
            host = "example.com:8443",
            path = "/.well-known/masque/ip/*/*/",
            remoteDNS = "1.1.1.1, 2606:4700:4700::1111",
            network = NetworkType.MASQUE.type,
            security = AppConfig.TLS,
            sni = "example.com",
            alpn = "h3",
            fingerPrint = "chrome",
            masqueHeaders = """{"User-Agent":"chrome"}""",
            finalMask = """{"quicParams":{"congestion":"bbr"}}""",
        )

        val outbound = CoreOutboundBuilder.convert(profile)

        assertNotNull(outbound)
        assertEquals("masque", outbound?.protocol)
        assertEquals("example.com", outbound?.settings?.address)
        assertEquals(443, outbound?.settings?.port)
        assertEquals(listOf("1.1.1.1", "2606:4700:4700::1111"), outbound?.settings?.remoteDNS)

        val stream = outbound?.streamSettings
        assertEquals(NetworkType.MASQUE.type, stream?.network)
        assertEquals(AppConfig.TLS, stream?.security)
        assertEquals("example.com", stream?.tlsSettings?.serverName)
        assertEquals(listOf("h3"), stream?.tlsSettings?.alpn)
        assertEquals("chrome", stream?.tlsSettings?.fingerprint)
        assertEquals("example.com:8443", stream?.masqueSettings?.host)
        assertEquals("u", stream?.masqueSettings?.user)
        assertEquals("p", stream?.masqueSettings?.pass)

        val headers = stream?.masqueSettings?.headers as? JsonObject
        assertEquals("chrome", headers?.get("User-Agent")?.asString)
        val finalMask = stream?.finalmask as? JsonObject
        assertEquals("bbr", finalMask?.getAsJsonObject("quicParams")?.get("congestion")?.asString)

        assertFalse(outbound?.mux?.enabled ?: true)
        assertEquals(-1, outbound?.mux?.concurrency)
    }

    companion object {
        private val settings: MMKV = mock()

        @BeforeAll
        @JvmStatic
        fun initializeSettingsStorage() {
            mockStatic(MMKV::class.java).use { mmkv ->
                mmkv.`when`<MMKV> { MMKV.mmkvWithID("SETTING", MMKV.MULTI_PROCESS_MODE) }
                    .thenReturn(settings)
                MmkvManager.decodeSettingsBool("masque-test-initialize")
            }
        }
    }
}
