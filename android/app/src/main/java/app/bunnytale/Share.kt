package app.bunnytale

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.WebResourceResponse
import androidx.core.content.IntentCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream

/**
 * "Share to Bunny Tale" from other apps. The page asks the bridge what was shared (takeShared) and fetches each file
 * from /__appshare/<i>, which the app answers itself from the sharing app's content URI (no copy, no upload by the app).
 */
object ShareInbox {
    class Item(val uri: Uri, val name: String, val mime: String)

    @Volatile private var text = ""
    @Volatile private var items: List<Item> = emptyList()
    @Volatile private var fresh = false  // not handed to the page yet

    /** Returns true if the intent was a share. */
    fun take(ctx: Context, i: Intent?): Boolean {
        if (i == null || (i.action != Intent.ACTION_SEND && i.action != Intent.ACTION_SEND_MULTIPLE)) return false
        val uris = mutableListOf<Uri>()
        if (i.action == Intent.ACTION_SEND) IntentCompat.getParcelableExtra(i, Intent.EXTRA_STREAM, Uri::class.java)?.let { uris += it }
        else IntentCompat.getParcelableArrayListExtra(i, Intent.EXTRA_STREAM, Uri::class.java)?.let { uris += it }
        if (uris.isEmpty()) i.clipData?.let { c -> for (n in 0 until c.itemCount) c.getItemAt(n).uri?.let { uris += it } }
        var t = i.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()?.trim().orEmpty()
        if (t.isEmpty() && uris.isEmpty()) t = i.getStringExtra(Intent.EXTRA_SUBJECT)?.trim().orEmpty()
        items = uris.distinct().take(10).map { Item(it, nameOf(ctx, it), ctx.contentResolver.getType(it) ?: i.type?.takeIf { m -> '*' !in m } ?: "application/octet-stream") }
        text = t
        fresh = true
        i.action = null  // handled: not again after the activity is recreated
        return true
    }

    private fun nameOf(ctx: Context, u: Uri): String = try {
        ctx.contentResolver.query(u, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    } catch (_: Exception) { null } ?: u.lastPathSegment?.substringAfterLast('/') ?: "file"

    /** For the page: {"text": "...", "files": [{"n": name, "t": mime}]}, or "" when nothing new was shared.
     *  Stays fresh until the page calls done(): the chat may reload into the fake error screen while fetching. */
    fun forPage(): String {
        if (!fresh) return ""
        return JSONObject().put("text", text)
            .put("files", JSONArray(items.map { JSONObject().put("n", it.name).put("t", it.mime) })).toString()
    }

    fun done() { fresh = false }

    /** Answers /__appshare/<i> on our server's origin, from both the WebView and its service worker. */
    fun intercept(ctx: Context, url: Uri): WebResourceResponse? {
        val server = Uri.parse(BuildConfig.SERVER_URL)
        if (url.host != server.host || url.path?.startsWith("/__appshare/") != true) return null
        val item = url.lastPathSegment?.toIntOrNull()?.let { n -> items.getOrNull(n) }
        val stream = try { item?.let { x -> ctx.contentResolver.openInputStream(x.uri) } } catch (_: Exception) { null }
            ?: return WebResourceResponse("text/plain", null, 404, "Not Found", emptyMap(), ByteArrayInputStream(ByteArray(0)))
        return WebResourceResponse(item!!.mime, null, 200, "OK", mapOf("Cache-Control" to "no-store"), stream)
    }
}
