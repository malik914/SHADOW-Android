package com.shadow.security

import java.net.HttpURLConnection
import java.net.URL

/**
 * Non-destructive HTTP/API posture checks.
 * No injection payloads, authentication guessing, fuzzing, or state-changing requests.
 */
object AdvancedWebApiAudit {
    fun run(rawTarget: String): String {
        val raw = rawTarget.trim()
        require(raw.isNotBlank()) { "Enter an authorized website or API URL." }
        val address = if (raw.startsWith("http://", true) || raw.startsWith("https://", true)) raw else "https://$raw"
        val url = URL(address)
        require(url.protocol == "https" || url.protocol == "http") { "Only HTTP and HTTPS targets are supported." }

        val findings = mutableListOf<String>()
        val observations = mutableListOf<String>()
        var status = -1
        var contentType = ""
        var authChallenge = ""
        var corsOrigin = ""
        var corsCredentials = ""
        var allowMethods = ""

        fun request(method: String): HttpURLConnection {
            val connection = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = 7000
                readTimeout = 7000
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", "SHADOW-Android/2.0 (authorized-audit)")
                setRequestProperty("Accept", "*/*")
            }
            return connection
        }

        val get = request("GET")
        try {
            status = get.responseCode
            contentType = get.getHeaderField("Content-Type") ?: ""
            authChallenge = get.getHeaderField("WWW-Authenticate") ?: ""
            corsOrigin = get.getHeaderField("Access-Control-Allow-Origin") ?: ""
            corsCredentials = get.getHeaderField("Access-Control-Allow-Credentials") ?: ""
            observations.add("GET response: HTTP $status")
            observations.add("Content-Type: ${contentType.ifBlank { "not supplied" }}")
            observations.add("Authentication challenge: ${if (authChallenge.isBlank()) "not supplied" else "present"}")
            observations.add("Access-Control-Allow-Origin: ${corsOrigin.ifBlank { "not supplied" }}")
            observations.add("Access-Control-Allow-Credentials: ${corsCredentials.ifBlank { "not supplied" }}")

            if (status == 401 || status == 403) {
                observations.add("Endpoint denied this unauthenticated request (HTTP $status).")
            } else if (status in 200..299) {
                findings.add("INFO: Endpoint returned HTTP $status without credentials; this alone does not prove data is public or authorization is missing.")
            } else if (status in 300..399) {
                observations.add("Endpoint redirects; Location: ${get.getHeaderField("Location") ?: "not supplied"}")
            }

            val headers = listOf(
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
                "Cache-Control"
            )
            headers.forEach { name ->
                val value = get.getHeaderField(name)
                observations.add("$name: ${value ?: "not supplied"}")
                if (name != "Cache-Control" && value.isNullOrBlank() && url.protocol == "https") {
                    findings.add("LOW: $name is not present on this response.")
                }
            }
            val server = get.getHeaderField("Server")
            val powered = get.getHeaderField("X-Powered-By")
            if (!server.isNullOrBlank()) findings.add("INFO: Server header disclosure: $server")
            if (!powered.isNullOrBlank()) findings.add("INFO: X-Powered-By disclosure: $powered")
            if (corsOrigin == "*" && corsCredentials.equals("true", true)) {
                findings.add("REVIEW: CORS returns wildcard origin together with credentials; verify actual browser behavior and intended policy.")
            }
        } finally {
            get.disconnect()
        }

        try {
            val options = request("OPTIONS")
            try {
                val optionsStatus = options.responseCode
                allowMethods = options.getHeaderField("Allow") ?: options.getHeaderField("Access-Control-Allow-Methods") ?: ""
                observations.add("OPTIONS response: HTTP $optionsStatus")
                observations.add("Allowed methods advertised: ${allowMethods.ifBlank { "not supplied" }}")
                if (allowMethods.split(",").any { it.trim().equals("TRACE", true) }) {
                    findings.add("REVIEW: TRACE is advertised; confirm it is required and safely configured.")
                }
            } finally {
                options.disconnect()
            }
        } catch (e: Exception) {
            observations.add("OPTIONS check unavailable: ${e.message ?: e.javaClass.simpleName}")
        }

        return buildString {
            append("SHADOW — ADVANCED WEBSITE & API AUDIT\n")
            append("Target: $address\n")
            append("Findings: ${findings.size}\n\n")
            append("FINDINGS\n")
            append(if (findings.isEmpty()) "No findings from completed checks." else findings.joinToString("\n"))
            append("\n\nTECHNICAL OBSERVATIONS\n")
            append(observations.joinToString("\n"))
            append("\n\nTEST COVERAGE & LIMITATIONS\n")
            append("This module performs a single unauthenticated GET and a safe OPTIONS request to the exact URL supplied. ")
            append("It does not submit forms, alter data, guess credentials, fuzz parameters, or send SQL injection/XSS payloads. ")
            append("SQL injection, stored/reflected XSS, broken object authorization, and authenticated access-control flaws require ")
            append("a controlled test environment, test accounts, and explicitly supplied test cases; they are not claimed as tested here. ")
            append("A successful response alone does not prove an authorization flaw. Only assess systems you own or are authorized to test.")
        }
    }
}
