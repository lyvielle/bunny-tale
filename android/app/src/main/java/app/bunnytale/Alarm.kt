package app.bunnytale

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioAttributes
import android.media.MediaPlayer
import android.media.RingtoneManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/** Small JSON POST to the server, off the main thread. */
object Api {
    fun post(path: String, body: JSONObject, cookie: String? = null) = thread {
        try {
            val c = URL(BuildConfig.SERVER_URL + path).openConnection() as HttpURLConnection
            c.requestMethod = "POST"; c.connectTimeout = 15000; c.readTimeout = 15000; c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            if (cookie != null) c.setRequestProperty("Cookie", cookie)
            c.outputStream.use { it.write(body.toString().toByteArray()) }
            Log.i("BunnyTale", "POST $path → ${c.responseCode}")
            c.disconnect()
        } catch (e: Exception) {
            Log.w("BunnyTale", "POST $path failed: $e")
        }
    }
}

/**
 * One ringing alarm at a time: looping alarm sound + vibration, a full-screen notification (opens AlarmActivity
 * over the lock screen and turns the screen on), stops by itself after [secs] and reports what happened.
 */
object Alarm {
    private const val CH = "alarms"
    const val NID = 2
    var id: String? = null; private set
    var from = ""; private set
    private var tok = ""
    private var ring = ""
    private var player: MediaPlayer? = null
    private var vib: Vibrator? = null
    private var wake: PowerManager.WakeLock? = null
    private val h = Handler(Looper.getMainLooper())
    private val timeout = Runnable { appCtx?.let { answer(it, "timeout") } }
    private var appCtx: Context? = null

    fun start(ctx: Context, id: String, tok: String, ring: String, from: String, secs: Int) = h.post {
        if (this.id != null) release(ctx)
        this.id = id; this.tok = tok; this.ring = ring; this.from = from; appCtx = ctx
        respond("ring")
        try {
            ctx.startForegroundService(Intent(ctx, AlarmService::class.java))
        } catch (e: Exception) {  // background start refused (app restricted): ring from here and show the notification
            Log.w("BunnyTale", "alarm service not started: $e")
            ctx.getSystemService(NotificationManager::class.java).notify(NID, notification(ctx))
        }
        sound(ctx)
        wake = ctx.getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "bunnytale:alarm")
            .apply { acquire((secs + 10) * 1000L) }
        h.postDelayed(timeout, secs * 1000L)
        if (AppState.foreground) ctx.startActivity(Intent(ctx, AlarmActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    /** The user (or the timeout) answered: tell the server, stop ringing. */
    fun answer(ctx: Context, action: String, mins: Int? = null) = h.post {
        if (id == null) return@post
        respond(action, mins)
        release(ctx)
    }

    /** Answered on another device or over on the server: stop without reporting. */
    fun stop(ctx: Context, which: String?) = h.post { if (id != null && (which == null || which == id)) release(ctx) }

    private fun respond(action: String, mins: Int? = null) =
        Api.post("/alarm/respond", JSONObject().put("id", id).put("tok", tok).put("ring", ring).put("action", action)
            .apply { if (mins != null) put("mins", mins) })

    private fun sound(ctx: Context) {
        val attrs = AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_ALARM).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build()
        val uri = RingtoneManager.getActualDefaultRingtoneUri(ctx, RingtoneManager.TYPE_ALARM)
            ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE) ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
        player = try {
            MediaPlayer().apply { setAudioAttributes(attrs); setDataSource(ctx, uri); isLooping = true; prepare(); start() }
        } catch (e: Exception) { Log.w("BunnyTale", "alarm sound failed: $e"); null }
        vib = if (Build.VERSION.SDK_INT >= 31) ctx.getSystemService(VibratorManager::class.java).defaultVibrator
              else legacyVibrator(ctx)
        vibrate(vib, attrs)
    }

    @Suppress("DEPRECATION")
    private fun legacyVibrator(ctx: Context): Vibrator? = ctx.getSystemService(Vibrator::class.java)

    @Suppress("DEPRECATION")
    private fun vibrate(v: Vibrator?, attrs: AudioAttributes) = v?.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 800, 600), 0), attrs)

    private fun release(ctx: Context) {
        h.removeCallbacks(timeout)
        try { player?.stop() } catch (_: Exception) {}
        player?.release(); player = null
        vib?.cancel(); vib = null
        wake?.let { if (it.isHeld) it.release() }; wake = null
        id = null
        ctx.getSystemService(NotificationManager::class.java).cancel(NID)
        ctx.stopService(Intent(ctx, AlarmService::class.java))
        AlarmActivity.close()
    }

    fun notification(ctx: Context): Notification {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH, "Alarms", NotificationManager.IMPORTANCE_HIGH).apply {
            setSound(null, null); enableVibration(false)  // sound and vibration come from Alarm itself (looping)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        })
        val full = PendingIntent.getActivity(ctx, 10, Intent(ctx, AlarmActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        fun act(a: String, code: Int) = PendingIntent.getBroadcast(ctx, code, Intent(ctx, AlarmActions::class.java).setAction(a),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return NotificationCompat.Builder(ctx, CH)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("Alarm")
            .setContentText("$from is trying to wake you")
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setOngoing(true)
            .setFullScreenIntent(full, true)
            .setContentIntent(full)
            .addAction(0, "Snooze 5 min", act("snooze", 11))
            .addAction(0, "Dismiss", act("dismiss", 12))
            .build()
    }
}

/** Keeps the process alive and in the foreground while the alarm rings. */
class AlarmService : Service() {
    override fun onBind(i: Intent?): IBinder? = null
    override fun onStartCommand(i: Intent?, flags: Int, startId: Int): Int {
        ServiceCompat.startForeground(this, Alarm.NID, Alarm.notification(this),
            if (Build.VERSION.SDK_INT >= 29) ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK else 0)
        if (Alarm.id == null) stopSelf()
        return START_NOT_STICKY
    }
}

/** Snooze / Dismiss buttons on the notification. */
class AlarmActions : BroadcastReceiver() {
    override fun onReceive(ctx: Context, i: Intent) {
        when (i.action) { "snooze" -> Alarm.answer(ctx.applicationContext, "snooze", 5); "dismiss" -> Alarm.answer(ctx.applicationContext, "dismiss") }
    }
}
