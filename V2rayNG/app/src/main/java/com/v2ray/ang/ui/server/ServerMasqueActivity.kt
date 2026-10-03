package com.v2ray.ang.ui.server

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.extension.nullIfBlank
import com.v2ray.ang.extension.toast
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.Utils

class ServerMasqueActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.MASQUE

    @Composable
    override fun ScreenContent() {
        val options = rememberFieldOptions()
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(
                initialConfig = initialConfig
            )
        }.apply {
            configType = EConfigType.MASQUE
            network = NetworkType.MASQUE.type
            streamSecurity = AppConfig.TLS
        }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            MasqueProtocolFields(uiState)
            MasqueStreamSecurityFields(uiState, options)
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean {
        config.security = AppConfig.TLS

        if (!masqueRemoteDnsIsValid(config.remoteDNS)) {
            toast(R.string.server_lab_masque_remote_dns)
            return false
        }

        val hasUserPass = !config.username.isNullOrBlank() || !config.password.isNullOrBlank()
        masqueHeadersErrorRes(config.masqueHeaders, hasUserPass)?.let { errorRes ->
            toast(errorRes)
            return false
        }

        return true
    }

    @Composable
    private fun MasqueProtocolFields(state: ServerUiState) {
        FormTextField(
            label = stringResource(R.string.server_lab_security4),
            value = state.username,
            onValueChange = { state.username = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_id4),
            value = state.password,
            onValueChange = { state.password = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_masque_host),
            value = state.host,
            onValueChange = { state.host = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_masque_path),
            value = state.path,
            onValueChange = { state.path = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_masque_headers),
            value = state.masqueHeaders,
            onValueChange = { state.masqueHeaders = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_masque_remote_dns),
            value = state.remoteDNS,
            onValueChange = { state.remoteDNS = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_final_mask),
            value = state.finalMask,
            onValueChange = { state.finalMask = it }
        )
    }

    @Composable
    private fun MasqueStreamSecurityFields(
        state: ServerUiState,
        options: BaseServerActivity.FieldOptions
    ) {
        FormDropdownField(
            stringResource(R.string.server_lab_stream_alpn),
            state.alpn,
            options.alpnOptions,
            { state.alpn = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_sni),
            state.sni,
            { state.sni = it }
        )
        FormDropdownField(
            stringResource(R.string.server_lab_stream_fingerprint),
            state.fingerPrint,
            options.uTlsOptions,
            { state.fingerPrint = it }
        )
        SettingsSwitchItem(
            title = stringResource(R.string.server_lab_allow_insecure),
            checked = state.allowInsecure,
            onCheckedChange = { state.allowInsecure = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_ech_config_list),
            state.echConfigList,
            { state.echConfigList = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_verify_peer_cert_by_name),
            state.verifyPeerCertByName,
            { state.verifyPeerCertByName = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_pinned_ca256),
            state.pinnedCA256,
            { state.pinnedCA256 = it }
        )
    }
}

private const val HEADER_NAME_TOKEN_CHARS = "!#$%&'*+-.^_`|~"

private fun isValidHeaderName(name: String): Boolean =
    name.isNotEmpty() && name.all { char ->
        char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' || char in HEADER_NAME_TOKEN_CHARS
    }

private fun isValidHeaderValue(value: String): Boolean =
    value.none { it == '\r' || it == '\n' || (it < ' ' && it != '\t') }

/**
 * Validates the raw masque settings.remoteDNS value for the MASQUE editor.
 *
 * Each comma-separated entry must be a plain IPv4/IPv6 address, matching the
 * xray-core requirement. Blank input is valid and keeps the core defaults.
 */
internal fun masqueRemoteDnsIsValid(rawRemoteDns: String?): Boolean =
    rawRemoteDns
        ?.split(",")
        ?.map { it.trim() }
        ?.filter { it.isNotEmpty() }
        ?.all { Utils.isPureIpAddress(it) }
        ?: true

/**
 * Validates the raw masqueSettings.headers JSON for the MASQUE editor.
 *
 * Mirrors the xray-core constraints: a JSON object of string values, valid HTTP
 * header names, no "host"/"capsule-protocol", and no "authorization" when
 * masqueSettings.user/pass are set.
 *
 * @return the error string resource, or null when the headers are valid.
 */
@StringRes
internal fun masqueHeadersErrorRes(rawHeaders: String?, hasUserPass: Boolean): Int? {
    val trimmed = rawHeaders?.nullIfBlank() ?: return null
    val parsed = JsonUtil.parseString(trimmed) ?: return R.string.server_lab_masque_headers

    for ((key, value) in parsed.entrySet()) {
        val name = key.trim()
        if (!isValidHeaderName(name)) {
            return R.string.server_lab_masque_headers
        }
        if (!value.isJsonPrimitive || !value.asJsonPrimitive.isString) {
            return R.string.server_lab_masque_headers
        }
        if (!isValidHeaderValue(value.asString)) {
            return R.string.server_lab_masque_headers
        }

        when (name.lowercase()) {
            "host", "capsule-protocol" -> return R.string.server_lab_masque_headers
            "authorization" -> if (hasUserPass) return R.string.server_lab_masque_headers
        }
    }
    return null
}
