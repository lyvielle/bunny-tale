package app.bunnytale

import android.Manifest
import android.annotation.SuppressLint
import android.app.AlertDialog
import android.app.DownloadManager
import android.app.NotificationManager
import android.content.ClipData
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.MimeTypeMap
import android.webkit.PermissionRequest
import android.webkit.URLUtil
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.google.firebase.messaging.FirebaseMessaging
import java.io.File

object AppState {
    @Volatile var foreground = false  // the chat is on screen: no message notifications, alarms open directly
}

class MainActivity : AppCompatActivity() {
    private lateinit var web: WebView
    private var chooser: ValueCallback<Array<Uri>>? = null
    private var micRequest: PermissionRequest? = null
    private var camFiles: List<Pair<File, Uri>> = emptyList()  // where the camera was asked to save a photo / video
    private var full: View? = null  // a video in full screen
    private var fullCb: WebChromeClient.CustomViewCallback? = null
    private var pendingDl: (() -> Unit)? = null  // Android 8/9: a download waiting for the storage permission
    private val pick = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r -> deliverFiles(r.resultCode, r.data) }
    // "Attach media": the system photo / video picker only (falls back to the document picker on old phones)
    private val pickMedia = registerForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(10)) { deliverUris(it) }
    private val pickOneMedia = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { deliverUris(listOfNotNull(it)) }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        setContentView(web)
        with(web.settings) {
            javaScriptEnabled = true
            domStorageEnabled = true
            mediaPlaybackRequiresUserGesture = false
            allowFileAccess = false
            cacheMode = WebSettings.LOAD_DEFAULT
        }
        web.addJavascriptInterface(Bridge(), "BunnyApp")
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest): Boolean {
                if (r.url.toString().startsWith(BuildConfig.SERVER_URL)) return false
                startActivity(Intent(Intent.ACTION_VIEW, r.url)); return true  // external links open in the browser
            }
            // WebView writes cookies to disk only every ~30 s: save the login right away, phones kill apps quickly
            override fun onPageFinished(v: WebView, url: String) { CookieManager.getInstance().flush() }
        }
        // file chips ("?dl=1" links): WebView ignores downloads unless the app handles them
        web.setDownloadListener { url, _, disp, mime, _ -> download(url, URLUtil.guessFileName(url, disp, mime)) }
        web.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(v: WebView, cb: ValueCallback<Array<Uri>>, p: FileChooserParams): Boolean {
                chooser?.onReceiveValue(null); chooser = cb
                return try { launchPicker(p); true } catch (e: Exception) { chooser = null; false }
            }
            // the video's full-screen button only appears (and works) when the app shows the view WebView hands over
            override fun onShowCustomView(view: View, cb: CustomViewCallback) {
                if (full != null) { cb.onCustomViewHidden(); return }
                full = view; fullCb = cb
                view.setBackgroundColor(Color.BLACK)
                (window.decorView as FrameLayout).addView(view, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
                WindowCompat.getInsetsController(window, window.decorView).apply {
                    systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
                    hide(WindowInsetsCompat.Type.systemBars())
                }
            }
            override fun onHideCustomView() { exitFull() }
            // WebView paints a grey play-button poster over videos without a poster image; a transparent one shows the first frame
            override fun getDefaultVideoPoster(): Bitmap = Bitmap.createBitmap(1, 1, Bitmap.Config.ARGB_8888)
            override fun onPermissionRequest(r: PermissionRequest) {
                runOnUiThread {
                    if (PermissionRequest.RESOURCE_AUDIO_CAPTURE in r.resources &&
                        ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                        micRequest = r
                        ActivityCompat.requestPermissions(this@MainActivity, arrayOf(Manifest.permission.RECORD_AUDIO), 8)
                    } else r.grant(r.resources)
                }
            }
        }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() { if (full != null) exitFull() else if (web.canGoBack()) web.goBack() else finish() }
        })
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 9)
        askFullScreen()
        if (savedInstanceState == null) {
            File(cacheDir, "camera").listFiles()?.forEach { it.delete() }  // photos from earlier sessions were uploaded or dropped
            web.loadUrl(BuildConfig.SERVER_URL.ifEmpty { "about:blank" })
        } else web.restoreState(savedInstanceState)
    }

    private fun exitFull() {
        val v = full ?: return
        full = null
        (window.decorView as FrameLayout).removeView(v)
        WindowCompat.getInsetsController(window, window.decorView).show(WindowInsetsCompat.Type.systemBars())
        fullCb?.onCustomViewHidden(); fullCb = null
    }

    /** Saves a chat file with the login cookie: photos to Pictures, videos to Movies (both show in the gallery), the rest to Downloads. */
    private fun download(url: String, name: String) {
        if (Build.VERSION.SDK_INT < 29 && ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            pendingDl = { download(url, name) }
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE), 10)
            return
        }
        try {
            val safe = name.replace(Regex("[\\u0000-\\u001f/\\\\:*?\"<>|]"), "_").trim().ifEmpty { "file" }.take(120)
            val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(safe.substringAfterLast('.', "").lowercase())
            val dir = when {
                mime?.startsWith("image/") == true -> Environment.DIRECTORY_PICTURES
                mime?.startsWith("video/") == true -> Environment.DIRECTORY_MOVIES
                else -> Environment.DIRECTORY_DOWNLOADS
            }
            val req = DownloadManager.Request(Uri.parse(url))
                .addRequestHeader("Cookie", CookieManager.getInstance().getCookie(url) ?: "")
                .addRequestHeader("User-Agent", web.settings.userAgentString)
                .setTitle(safe)
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                .setDestinationInExternalPublicDir(dir, if (dir == Environment.DIRECTORY_DOWNLOADS) safe else "Bunny Tale/$safe")
            if (mime != null) req.setMimeType(mime)
            getSystemService(DownloadManager::class.java).enqueue(req)
            Toast.makeText(this, "Downloading $safe", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Download failed", Toast.LENGTH_SHORT).show()
        }
    }

    /** Android 14+: full-screen alarms need a special permission, granted in the system settings. Asked once. */
    private fun askFullScreen() {
        if (Build.VERSION.SDK_INT < 34) return
        val prefs = getSharedPreferences("app", MODE_PRIVATE)
        if (getSystemService(NotificationManager::class.java).canUseFullScreenIntent() || prefs.getBoolean("fsiAsked", false)) return
        prefs.edit().putBoolean("fsiAsked", true).apply()
        AlertDialog.Builder(this)
            .setTitle("Full-screen alarms")
            .setMessage("To wake you with a full-screen alarm when someone sends one, Bunny Tale needs the \"full-screen notifications\" permission.")
            .setPositiveButton("Open settings") { _, _ ->
                try { startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, Uri.parse("package:$packageName"))) } catch (_: Exception) {}
            }
            .setNegativeButton("Not now", null)
            .show()
    }

    private fun launchPicker(p: WebChromeClient.FileChooserParams) {
        val types = p.acceptTypes.flatMap { it.split(',') }.map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        val media = types.isNotEmpty() && types.all { it.startsWith("image/") || it.startsWith("video/") }
        if (!media) { pick.launch(buildChooser(p)); return }
        val kind = when {
            types.all { it.startsWith("image/") } -> ActivityResultContracts.PickVisualMedia.ImageOnly
            types.all { it.startsWith("video/") } -> ActivityResultContracts.PickVisualMedia.VideoOnly
            else -> ActivityResultContracts.PickVisualMedia.ImageAndVideo
        }
        val req = PickVisualMediaRequest.Builder().setMediaType(kind).build()
        if (p.mode == WebChromeClient.FileChooserParams.MODE_OPEN_MULTIPLE) pickMedia.launch(req) else pickOneMedia.launch(req)
    }

    private fun deliverUris(uris: List<Uri>) {
        val cb = chooser ?: return
        chooser = null
        cb.onReceiveValue(if (uris.isEmpty()) null else uris.toTypedArray())
    }

    /** Like Chrome's picker: the file / gallery picker, with "take a photo" and "record a video" next to it. */
    private fun buildChooser(p: WebChromeClient.FileChooserParams): Intent {
        val types = p.acceptTypes.flatMap { it.split(',') }.map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        val content = Intent(Intent.ACTION_GET_CONTENT).addCategory(Intent.CATEGORY_OPENABLE).apply {
            type = if (types.size == 1) types[0] else "*/*"
            if (types.size > 1) putExtra(Intent.EXTRA_MIME_TYPES, types.toTypedArray())
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, p.mode == WebChromeClient.FileChooserParams.MODE_OPEN_MULTIPLE)
        }
        val any = types.isEmpty() || "*/*" in types
        val cams = mutableListOf<Intent>()
        val files = mutableListOf<Pair<File, Uri>>()
        if (any || types.any { it.startsWith("image/") }) camIntent(MediaStore.ACTION_IMAGE_CAPTURE, "IMG", ".jpg")?.let { cams += it.first; files += it.second }
        if (any || types.any { it.startsWith("video/") }) camIntent(MediaStore.ACTION_VIDEO_CAPTURE, "VID", ".mp4")?.let { cams += it.first; files += it.second }
        camFiles = files
        return Intent.createChooser(content, "Attach").putExtra(Intent.EXTRA_INITIAL_INTENTS, cams.toTypedArray())
    }

    private fun camIntent(action: String, prefix: String, ext: String): Pair<Intent, Pair<File, Uri>>? {
        val i = Intent(action)
        if (i.resolveActivity(packageManager) == null) return null
        val dir = File(cacheDir, "camera").apply { mkdirs() }
        val f = File(dir, "${prefix}_${System.currentTimeMillis()}$ext")
        val uri = FileProvider.getUriForFile(this, "$packageName.files", f)
        i.putExtra(MediaStore.EXTRA_OUTPUT, uri)
        i.clipData = ClipData.newRawUri("", uri)
        i.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        return i to (f to uri)
    }

    /** Pickers return one file in data, several in clipData (multi-select: "Attach media"); the camera writes to our file. */
    private fun deliverFiles(code: Int, data: Intent?) {
        val cb = chooser ?: return
        chooser = null
        val out = mutableListOf<Uri>()
        if (code == RESULT_OK) {
            val own = camFiles.map { it.second }.toSet()
            data?.clipData?.let { c -> for (i in 0 until c.itemCount) c.getItemAt(i).uri?.let { if (it !in own) out += it } }
            data?.data?.let { if (it !in own && it !in out) out += it }
            camFiles.filter { it.first.length() > 0 }.forEach { out += it.second }
        }
        camFiles.filter { it.first.length() == 0L }.forEach { it.first.delete() }
        camFiles = emptyList()
        cb.onReceiveValue(if (out.isEmpty()) null else out.toTypedArray())
    }

    inner class Bridge {
        @JavascriptInterface
        fun requestToken() {  // answers by calling window.__fcm(token) in the page
            FirebaseMessaging.getInstance().token.addOnSuccessListener { t ->
                getSharedPreferences("app", MODE_PRIVATE).edit().putString("fcmTok", t).apply()
                web.post { web.evaluateJavascript("window.__fcm&&window.__fcm('$t')", null) }
            }
        }

        @JavascriptInterface
        fun download(url: String, name: String) {  // long-press on a photo / video in the chat
            if (url.startsWith(BuildConfig.SERVER_URL)) runOnUiThread { this@MainActivity.download(url, name) }
        }

        @JavascriptInterface
        fun setMessages(on: Boolean) {  // remembered for a token refresh while the app is closed
            getSharedPreferences("app", MODE_PRIVATE).edit().putBoolean("msgs", on).apply()
        }
    }

    override fun onResume() {
        super.onResume()
        AppState.foreground = true
        web.onResume()
        web.evaluateJavascript("window.__appVis&&window.__appVis(true)", null)
    }

    override fun onPause() {
        AppState.foreground = false
        web.evaluateJavascript("window.__appVis&&window.__appVis(false)", null)  // the server stops treating the chat as open
        web.onPause()
        CookieManager.getInstance().flush()
        super.onPause()
    }

    override fun onRequestPermissionsResult(req: Int, perms: Array<out String>, results: IntArray) {
        super.onRequestPermissionsResult(req, perms, results)
        if (req == 8) {
            val r = micRequest; micRequest = null
            if (results.firstOrNull() == PackageManager.PERMISSION_GRANTED) r?.grant(r.resources) else r?.deny()
        }
        if (req == 10) {
            val d = pendingDl; pendingDl = null
            if (results.firstOrNull() == PackageManager.PERMISSION_GRANTED) d?.invoke()
            else Toast.makeText(this, "Saving needs the storage permission", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onSaveInstanceState(out: Bundle) { super.onSaveInstanceState(out); web.saveState(out) }
}
