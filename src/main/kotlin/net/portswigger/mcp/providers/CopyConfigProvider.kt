package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import net.portswigger.mcp.config.McpConfig
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection

class CopyConfigProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    override val name = "Other MCP Clients"
    override val installButtonText = "Copy SSE config to clipboard"
    override val confirmationText = null

    override fun install(config: McpConfig): String {
        val sseUrl = "http://${config.host}:${config.port}/sse"

        val configSnippet = buildString {
            appendLine("{")
            appendLine("  \"servers\": {")
            appendLine("    \"burp\": {")
            appendLine("      \"url\": \"$sseUrl\"")
            appendLine("    }")
            appendLine("  }")
            appendLine("}")
        }

        val clipboard = Toolkit.getDefaultToolkit().systemClipboard
        clipboard.setContents(StringSelection(configSnippet), null)

        logging.logToOutput("Copied SSE config to clipboard: $sseUrl")

        return "SSE config copied to clipboard.\n\n" +
                "Paste into your MCP client's configuration.\n" +
                "SSE URL: $sseUrl\n\n" +
                "See README for client-specific setup instructions\n" +
                "(VS Code, GitHub Copilot, Cursor, Windsurf, opencode, etc.)"
    }
}

class CopyStdioConfigProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    override val name = "Other MCP Clients (Stdio)"
    override val installButtonText = "Copy Stdio config to clipboard"
    override val confirmationText = null

    override fun install(config: McpConfig): String {
        val proxyJarFile = proxyJarManager.getProxyJar()
        val javaPath = javaPath()
        val sseUrl = "http://${config.host}:${config.port}"

        val configSnippet = buildString {
            appendLine("{")
            appendLine("  \"servers\": {")
            appendLine("    \"burp\": {")
            appendLine("      \"type\": \"stdio\",")
            appendLine("      \"command\": \"$javaPath\",")
            appendLine("      \"args\": [\"-jar\", \"$proxyJarFile\", \"--sse-url\", \"$sseUrl\"]")
            appendLine("    }")
            appendLine("  }")
            appendLine("}")
        }

        val clipboard = Toolkit.getDefaultToolkit().systemClipboard
        clipboard.setContents(StringSelection(configSnippet), null)

        logging.logToOutput("Copied Stdio proxy config to clipboard")

        return "Stdio proxy config copied to clipboard.\n\n" +
                "Paste into your MCP client's configuration.\n\n" +
                "See README for client-specific setup instructions\n" +
                "(VS Code, GitHub Copilot, Cursor, Windsurf, opencode, etc.)"
    }

    private fun javaPath(): String {
        val javaHome = System.getProperty("java.home")
        val os = System.getProperty("os.name").lowercase()

        return if (os.contains("win")) {
            "$javaHome\\bin\\java.exe"
        } else {
            "$javaHome/bin/java"
        }
    }
}
