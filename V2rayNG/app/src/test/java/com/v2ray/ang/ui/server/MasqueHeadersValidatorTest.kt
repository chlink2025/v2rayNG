package com.v2ray.ang.ui.server

import android.util.Log
import com.tencent.mmkv.MMKV
import com.v2ray.ang.R
import com.v2ray.ang.handler.MmkvManager
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.mock

class MasqueHeadersValidatorTest {

    @Test
    fun blankHeadersAreValid() {
        assertNull(masqueHeadersErrorRes(null, false))
        assertNull(masqueHeadersErrorRes("   ", false))
    }

    @Test
    fun validHeadersAreAccepted() {
        assertNull(masqueHeadersErrorRes("""{"User-Agent":"chrome","X-Token":"abc"}""", false))
        assertNull(masqueHeadersErrorRes("""{"Authorization":"Bearer token"}""", false))
    }

    @Test
    fun invalidJsonIsRejected() {
        mockStatic(Log::class.java).use {
            assertEquals(R.string.server_lab_masque_headers, masqueHeadersErrorRes("{", false))
        }
    }

    @Test
    fun reservedHeadersAreRejected() {
        assertEquals(R.string.server_lab_masque_headers, masqueHeadersErrorRes("""{"Host":"example.com"}""", false))
        assertEquals(R.string.server_lab_masque_headers, masqueHeadersErrorRes("""{"capsule-protocol":"?0"}""", false))
    }

    @Test
    fun authorizationIsRejectedOnlyWhenUserOrPassIsSet() {
        assertEquals(
            R.string.server_lab_masque_headers,
            masqueHeadersErrorRes("""{"Authorization":"Basic dTpw"}""", true)
        )
        assertNull(masqueHeadersErrorRes("""{"Authorization":"Basic dTpw"}""", false))
    }

    @Test
    fun malformedNamesAndValuesAreRejected() {
        assertEquals(R.string.server_lab_masque_headers, masqueHeadersErrorRes("""{"Bad Name":"a"}""", false))
        assertEquals(R.string.server_lab_masque_headers, masqueHeadersErrorRes("""{"X":1}""", false))
        assertEquals(R.string.server_lab_masque_headers, masqueHeadersErrorRes("""{"X":"a\nb"}""", false))
    }

    @Test
    fun remoteDnsAcceptsBlankAndIpLists() {
        assertTrue(masqueRemoteDnsIsValid(null))
        assertTrue(masqueRemoteDnsIsValid(""))
        assertTrue(masqueRemoteDnsIsValid("   "))
        assertTrue(masqueRemoteDnsIsValid("1.1.1.1"))
        assertTrue(masqueRemoteDnsIsValid("1.1.1.1, 2606:4700:4700::1111"))
        assertTrue(masqueRemoteDnsIsValid("[2606:4700:4700::1111]"))
    }

    @Test
    fun remoteDnsRejectsNonAddressEntries() {
        assertFalse(masqueRemoteDnsIsValid("local"))
        assertFalse(masqueRemoteDnsIsValid("dns.example.com"))
        assertFalse(masqueRemoteDnsIsValid("1.1.1.1,local"))
        assertFalse(masqueRemoteDnsIsValid("999.1.1.1"))
    }

    companion object {
        private val settings: MMKV = mock()

        @BeforeAll
        @JvmStatic
        fun initializeSettingsStorage() {
            mockStatic(MMKV::class.java).use { mmkv ->
                mmkv.`when`<MMKV> { MMKV.mmkvWithID("SETTING", MMKV.MULTI_PROCESS_MODE) }
                    .thenReturn(settings)
                MmkvManager.decodeSettingsBool("masque-headers-test-initialize")
            }
        }
    }
}
