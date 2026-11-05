package com.shadow.security

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.File
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection

class MainActivity : Activity() {
    private lateinit var hostInput: EditText
    private lateinit var portsInput: EditText
    private lateinit var output: TextView
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor()
    private val pickApkRequest = 4102

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20, 24, 20, 20)
            setBackgroundColor(0xFF101820.toInt())
        }

        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val title = TextView(this).apply {
            text = "SHADOW"
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(0xFF62D6C8.toInt())
            gravity = Gravity.CENTER
        }
        content.addView(title, matchWrap())

        val subtitle = TextView(this).apply {
            text = "ANDROID SECURITY LAB  •  AUTHORIZED TESTING ONLY"
            textSize = 11f
            gravity = Gravity.CENTER
            setTextColor(0xFFB7C6D1.toInt())
            setPadding(0, 4, 0, 20)
        }
        content.addView(subtitle, matchWrap())

        hostInput = EditText(this).apply {
            hint = "Target host or URL (example.com)"
            singleLine = true
            setTextColor(0xFFFFFFFF.toInt())
            setHintTextColor(0xFF9AAAB5.toInt())
            setBackgroundColor(0xFF24323D.toInt())
        }
        content.addView(hostInput, matchWrap())

        portsInput = EditText(this).apply {
            hint = "TCP ports, comma-separated"
            setText("22,80,443,8080,8443")
            singleLine = true
            setTextColor(0xFFFFFFFF.toInt())
            setHintTextColor(0xFF9AAAB5.toInt())
            setBackgroundColor(0xFF24323D.toInt())
        }
        val portParams = matchWrap()
        portParams.topMargin = 10
        content.addView(portsInput, portParams)

        addAction(content, "SCAN TCP PORTS") { scanPorts() }
        addAction(content, "CHECK HTTP SECURITY HEADERS") { inspectHeaders() }
        addAction(content, "INSPECT HTTPS CERTIFICATE") { inspectCertificate() }
        addAction(content, "BASIC VULNERABILITY / CONFIGURATION SCAN") { runBasicVulnerabilityScan() }
        addAction(content, "ANALYZE APK PERMISSIONS") { chooseApk() }

        output = TextView(this).apply {
            text = "Ready. Enter a host above and choose a check.\n\nOnly test systems you own or have permission to assess."
            textSize = 14f
            setTextColor(0xFFE5EDF2.toInt())
            setPadding(14, 18, 14, 24)
            setBackgroundColor(0xFF1A2832.toInt())
        }
        val outParams = matchWrap()
        outParams.topMargin = 18
        content.addView(output, outParams)

        scroll.addView(content)
        root.addView(scroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT
        ))
        setContentView(root)
    }

    private fun matchWrap(): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        )

    private fun addAction(parent: LinearLayout, label: String, action: () -> Unit) {
        val button = Button(this).apply {
            text = label
            setOnClickListener { action() }
        }
        val params = matchWrap()
        params.topMargin = 10
        parent.addView(button, params)
    }

    private fun setResultText(value: String) {
        runOnUiThread { output.text = value }
    }

    private fun targetHost(): String {
        val raw = hostInput.text.toString().trim()
        require(raw.isNotBlank()) { "Enter a target host first." }
        val cleaned = raw.removePrefix("https://").removePrefix("http://").substringBefore("/")
        require(cleaned.isNotBlank() && !cleaned.contains(" ")) { "Enter a valid host or URL." }
        return cleaned.substringBefore(":").ifBlank { cleaned }
    }

    private fun runCheck(label: String, task: () -> String) {
        setResultText("$label\n\nWorking…")
        worker.execute {
            try {
                setResultText(task())
            } catch (e: Exception) {
                setResultText("ERROR\n\n${e.message ?: e.javaClass.simpleName}")
            }
        }
    }

    private fun scanPorts() {
        val host = try { targetHost() } catch (e: Exception) {
            setResultText(e.message ?: "Invalid host"); return
        }
        val ports = try {
            portsInput.text.toString().split(",").map { it.trim().toInt() }.distinct()
        } catch (_: Exception) {
            setResultText("Enter ports as comma-separated numbers, for example 22,80,443."); return
        }
        if (ports.isEmpty() || ports.size > 64 || ports.any { it !in 1..65535 }) {
            setResultText("Use between 1 and 64 valid TCP ports (1–65535)."); return
        }
        runCheck("TCP CONNECT SCAN  •  $host") {
            val lines = mutableListOf<String>()
            for (port in ports) {
                val open = try {
                    Socket().use { socket ->
                        socket.connect(java.net.InetSocketAddress(host, port), 800)
                    }
                    true
                } catch (_: Exception) { false }
                lines.add("$port/tcp  " + if (open) "OPEN" else "closed or filtered")
            }
            "TCP SCAN RESULTS\nTarget: $host\nPorts checked: ${ports.size}\n\n" +
                lines.joinToString("\n") +
                "\n\nA closed/filtered result can also mean a firewall or timeout."
        }
    }

    private fun inspectHeaders() {
        val raw = hostInput.text.toString().trim()
        if (raw.isBlank()) { setResultText("Enter a website host or URL first."); return }
        runCheck("HTTP SECURITY HEADERS") {
            val address = if (raw.startsWith("http://") || raw.startsWith("https://")) raw else "https://$raw"
            val connection = URL(address).openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "GET"
                connection.connectTimeout = 7000
                connection.readTimeout = 7000
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("User-Agent", "SHADOW-Android/1.0")
                val status = connection.responseCode
                val names = listOf(
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy",
                    "Permissions-Policy"
                )
                val lines = names.map { name ->
                    "$name: ${connection.getHeaderField(name) ?: "NOT PRESENT"}"
                }
                "HTTP HEADER RESULTS\nURL: $address\nHTTP status: $status\n\n" +
                    lines.joinToString("\n") +
                    "\n\nMissing headers are observations, not proof of a vulnerability. Redirects are not followed."
            } finally {
                connection.disconnect()
            }
        }
    }


    // Safe, low-impact checks only. No exploitation, brute force, or hidden probing.
    private fun runBasicVulnerabilityScan() {
        val host = try { targetHost() } catch (e: Exception) {
            setResultText(e.message ?: "Invalid host"); return
        }
        runCheck("VULNERABILITY & SECURITY CONFIGURATION SCAN  •  $host") {
            val findings = mutableListOf<String>()
            val observations = mutableListOf<String>()
            var checksPassed = 0

            try {
                val addresses = java.net.InetAddress.getAllByName(host)
                observations.add("DNS: resolved to " + addresses.joinToString { it.hostAddress })
                checksPassed++
            } catch (e: Exception) {
                findings.add("REVIEW: DNS lookup failed: ${e.message ?: e.javaClass.simpleName}")
            }

            try {
                val https = URL("https://$host").openConnection() as HttpsURLConnection
                try {
                    https.connectTimeout = 7000
                    https.readTimeout = 7000
                    https.instanceFollowRedirects = false
                    https.setRequestProperty("User-Agent", "SHADOW-Android/1.0")
                    val status = https.responseCode
                    checksPassed++
                    observations.add("HTTPS: reachable (HTTP $status); Android accepted the TLS certificate and hostname.")
                    val cert = https.serverCertificates.firstOrNull() as? X509Certificate
                    if (cert != null) {
                        val now = java.util.Date()
                        val daysLeft = ((cert.notAfter.time - now.time) / 86400000L)
                        observations.add("TLS certificate expires: ${cert.notAfter} (${daysLeft} days remaining).")
                        if (now.after(cert.notAfter)) findings.add("HIGH: TLS certificate is expired.")
                        else if (daysLeft <= 30) findings.add("MEDIUM: TLS certificate expires within 30 days.")
                        if (now.before(cert.notBefore)) findings.add("HIGH: TLS certificate is not valid yet.")
                    }

                    val hsts = https.getHeaderField("Strict-Transport-Security")
                    if (hsts.isNullOrBlank()) {
                        findings.add("MEDIUM: HSTS header is missing on the HTTPS response.")
                    } else {
                        val maxAge = Regex("max-age\\s*=\\s*(\\d+)", RegexOption.IGNORE_CASE)
                            .find(hsts)?.groupValues?.getOrNull(1)?.toLongOrNull()
                        if (maxAge == null || maxAge < 15552000L) {
                            findings.add("LOW: HSTS max-age is missing or shorter than 180 days.")
                        }
                        if (!hsts.contains("includeSubDomains", true)) {
                            observations.add("HSTS does not include subdomains.")
                        }
                    }

                    val csp = https.getHeaderField("Content-Security-Policy")
                    if (csp.isNullOrBlank()) findings.add("LOW: Content-Security-Policy header is missing.")
                    else if (csp.contains("unsafe-inline", true) || csp.contains("unsafe-eval", true)) {
                        findings.add("LOW: CSP contains unsafe-inline or unsafe-eval; review whether these are necessary.")
                    }

                    val headerChecks = listOf(
                        "X-Content-Type-Options" to "MIME sniffing protection",
                        "X-Frame-Options" to "Clickjacking protection",
                        "Referrer-Policy" to "Referrer policy",
                        "Permissions-Policy" to "Browser permissions policy"
                    )
                    for ((header, label) in headerChecks) {
                        if (https.getHeaderField(header).isNullOrBlank()) {
                            findings.add("LOW: $label header is missing.")
                        }
                    }
                    val xfo = https.getHeaderField("X-Frame-Options")
                    if (!xfo.isNullOrBlank() && !xfo.equals("DENY", true) &&
                        !xfo.equals("SAMEORIGIN", true)) {
                        observations.add("X-Frame-Options value may need review: $xfo")
                    }

                    val server = https.getHeaderField("Server")
                    if (!server.isNullOrBlank()) findings.add("INFO: Server banner is disclosed: $server")
                    val powered = https.getHeaderField("X-Powered-By")
                    if (!powered.isNullOrBlank()) findings.add("INFO: X-Powered-By is disclosed: $powered")

                    val cookies = https.headerFields.entries
                        .filter { it.key.equals("Set-Cookie", true) }
                        .flatMap { it.value ?: emptyList() }
                    for (cookie in cookies) {
                        val name = cookie.substringBefore("=").ifBlank { "(unnamed)" }
                        if (!cookie.contains("; Secure", true)) findings.add("LOW: Cookie '$name' lacks Secure.")
                        if (!cookie.contains("; HttpOnly", true)) findings.add("LOW: Cookie '$name' lacks HttpOnly.")
                        if (!Regex(";\\s*SameSite\\s*=", RegexOption.IGNORE_CASE).containsMatchIn(cookie)) {
                            findings.add("LOW: Cookie '$name' does not specify SameSite.")
                        }
                    }
                    if (cookies.isEmpty()) observations.add("No Set-Cookie headers were returned on this response.")
                } finally {
                    https.disconnect()
                }
            } catch (e: Exception) {
                findings.add("REVIEW: HTTPS/TLS check failed: ${e.message ?: e.javaClass.simpleName}")
            }

            try {
                val http = URL("http://$host").openConnection() as HttpURLConnection
                try {
                    http.connectTimeout = 7000
                    http.readTimeout = 7000
                    http.instanceFollowRedirects = false
                    http.setRequestProperty("User-Agent", "SHADOW-Android/1.0")
                    val status = http.responseCode
                    val location = http.getHeaderField("Location")
                    if (status in 300..399 && !location.isNullOrBlank() &&
                        location.startsWith("https://", ignoreCase = true)) {
                        observations.add("HTTP: redirects to HTTPS (status $status).")
                        checksPassed++
                    } else {
                        findings.add("MEDIUM: HTTP did not return a direct HTTPS redirect (status $status).")
                    }
                } finally {
                    http.disconnect()
                }
            } catch (e: Exception) {
                observations.add("HTTP endpoint could not be checked: ${e.message ?: e.javaClass.simpleName}")
            }

            val high = findings.count { it.startsWith("HIGH:") }
            val medium = findings.count { it.startsWith("MEDIUM:") }
            val low = findings.count { it.startsWith("LOW:") }
            val info = findings.count { it.startsWith("INFO:") }
            val report = if (findings.isEmpty()) "No findings from the checks that completed."
                else findings.joinToString("\\n")
            "SHADOW SCAN REPORT\\nTarget: $host\\nChecks completed: $checksPassed\\n" +
                "Findings: HIGH $high | MEDIUM $medium | LOW $low | INFO $info\\n\\n" +
                report + "\\n\\nOBSERVATIONS\\n" +
                (if (observations.isEmpty()) "No additional observations." else observations.joinToString("\\n")) +
                "\\n\\nSCOPE & LIMITATIONS\\nThis is a non-intrusive configuration review. It does not exploit systems, " +
                "test application logic, enumerate hidden paths, or identify every CVE. Header findings are recommendations, " +
                "not proof of exploitability. Some checks depend on the server response to this single request. " +
                "Only scan systems you own or are explicitly authorized to assess."
        }
    }

    private fun inspectCertificate() {
        val host = try { targetHost() } catch (e: Exception) {
            setResultText(e.message ?: "Invalid host"); return
        }
        runCheck("HTTPS CERTIFICATE INSPECTION  •  $host") {
            val connection = URL("https://$host").openConnection() as HttpsURLConnection
            try {
                connection.connectTimeout = 7000
                connection.readTimeout = 7000
                connection.connect()
                val cert = connection.serverCertificates.firstOrNull() as? X509Certificate
                    ?: error("No X.509 server certificate was returned.")
                val fingerprint = MessageDigest.getInstance("SHA-256")
                    .digest(cert.encoded)
                    .joinToString(":") { "%02X".format(it) }
                "TLS CERTIFICATE\nHost: $host\nTLS cipher: ${connection.cipherSuite}\n" +
                    "Subject: ${cert.subjectX500Principal.name}\n" +
                    "Issuer: ${cert.issuerX500Principal.name}\n" +
                    "Valid from: ${cert.notBefore}\nValid until: ${cert.notAfter}\n" +
                    "SHA-256: $fingerprint\n\nCertificate validation uses Android's normal HTTPS trust and hostname checks."
            } finally {
                connection.disconnect()
            }
        }
    }

    private fun chooseApk() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/vnd.android.package-archive"
        }
        startActivityForResult(intent, pickApkRequest)
    }

    @Deprecated("Deprecated by Android, retained for broad API compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != pickApkRequest || resultCode != RESULT_OK) return
        val uri: Uri = data?.data ?: return
        runCheck("APK PERMISSION INVENTORY") {
            val temp = File(cacheDir, "selected-analysis.apk")
            contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "Could not open the selected APK." }
                temp.outputStream().use { outputStream -> input.copyTo(outputStream) }
            }
            val info = readPackageInfo(temp.absolutePath)
                ?: error("Android could not read this APK. Select a valid APK file.")
            val permissions = info.requestedPermissions?.toList().orEmpty()
            "APK ANALYSIS\nPackage: ${info.packageName}\nVersion: ${info.versionName ?: "unknown"}\n" +
                "Requested permissions: ${permissions.size}\n\n" +
                (if (permissions.isEmpty()) "No requested permissions listed."
                else permissions.joinToString("\n") { "• $it" }) +
                "\n\nThis is a permission inventory only; it does not execute or install the APK."
        }
    }

    @Suppress("DEPRECATION")
    private fun readPackageInfo(path: String): PackageInfo? =
        packageManager.getPackageArchiveInfo(path, PackageManager.GET_PERMISSIONS)

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }
}
