package com.v2ray.ang.ui.server

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ServerMasqueUiStateTest {

    @Test
    fun toProfileItemKeepsMasqueFieldsAndClearsOtherProtocolFields() {
        val state = ServerUiState(
            configType = EConfigType.MASQUE,
            remarks = "r",
            address = "example.com",
            port = "443",
            username = "u",
            password = "p",
            host = "example.com:8443",
            path = "/.well-known/masque/ip/*/*/",
            masqueHeaders = """{"User-Agent":"chrome"}""",
            remoteDNS = "1.1.1.1",
            network = NetworkType.MASQUE.type,
            streamSecurity = AppConfig.TLS,
            sni = "example.com",
            alpn = "h3",
            allowInsecure = true,
            fingerPrint = "chrome",
            echConfigList = "ECH",
            verifyPeerCertByName = "example.com",
            pinnedCA256 = "PIN",
            finalMask = """{"quicParams":{}}""",
            secretKey = "wg-secret",
            publicKey = "wg-public",
            localAddress = "10.0.0.2/32",
            mtu = "1400",
            obfsPassword = "obfs",
            portHopping = "1-2",
        )

        val config = state.toProfileItem(ProfileItem.create(EConfigType.MASQUE))

        assertEquals(EConfigType.MASQUE, config.configType)
        assertEquals("example.com", config.server)
        assertEquals("443", config.serverPort)
        assertEquals("u", config.username)
        assertEquals("p", config.password)
        assertEquals("example.com:8443", config.host)
        assertEquals("/.well-known/masque/ip/*/*/", config.path)
        assertEquals("""{"User-Agent":"chrome"}""", config.masqueHeaders)
        assertEquals("1.1.1.1", config.remoteDNS)
        assertEquals(NetworkType.MASQUE.type, config.network)
        assertEquals(AppConfig.TLS, config.security)
        assertEquals("example.com", config.sni)
        assertEquals("h3", config.alpn)
        assertEquals(true, config.insecure)
        assertEquals("chrome", config.fingerPrint)
        assertEquals("ECH", config.echConfigList)
        assertEquals("example.com", config.verifyPeerCertByName)
        assertEquals("PIN", config.pinnedCA256)
        assertEquals("""{"quicParams":{}}""", config.finalMask)

        assertNull(config.secretKey)
        assertNull(config.publicKey)
        assertNull(config.localAddress)
        assertNull(config.mtu)
        assertNull(config.obfsPassword)
        assertNull(config.portHopping)
        assertNull(config.flow)
        assertNull(config.method)
    }

    @Test
    fun fromProfileItemRestoresMasqueFields() {
        val config = ProfileItem(
            configType = EConfigType.MASQUE,
            server = "example.com",
            serverPort = "443",
            network = NetworkType.MASQUE.type,
            security = AppConfig.TLS,
            username = "u",
            password = "p",
            host = "example.com:8443",
            path = "/p",
            masqueHeaders = """{"X-Token":"a"}""",
            remoteDNS = "1.1.1.1",
        )

        val state = ServerUiState.from(config)

        assertEquals(EConfigType.MASQUE, state.configType)
        assertEquals(NetworkType.MASQUE.type, state.network)
        assertEquals(AppConfig.TLS, state.streamSecurity)
        assertEquals("u", state.username)
        assertEquals("p", state.password)
        assertEquals("example.com:8443", state.host)
        assertEquals("/p", state.path)
        assertEquals("""{"X-Token":"a"}""", state.masqueHeaders)
        assertEquals("1.1.1.1", state.remoteDNS)
    }

    @Test
    fun toProfileItemDropsMasqueHeadersForOtherProtocols() {
        val state = ServerUiState(
            configType = EConfigType.TROJAN,
            masqueHeaders = """{"X-Token":"a"}""",
        )

        val config = state.toProfileItem(ProfileItem.create(EConfigType.TROJAN))

        assertNull(config.masqueHeaders)
    }
}
