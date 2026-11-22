package app.bunnytale

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.util.Log
import android.webkit.CookieManager
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.json.JSONObject

class MessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(m: RemoteMessage) {
        val d = m.data
        Log.i("BunnyTale", "FCM ${d["type"]} (priority ${m.priority}/${m.originalPriority})")
        when (d["type"]) {
            "alarm" -> Alarm.start(applicationContext, d["id"] ?: return, d["tok"] ?: return, d["ring"] ?: "1",
                d["from"] ?: "Someone", d["secs"]?.toIntOrNull() ?: 90)
            "alarm_stop" -> Alarm.stop(applicationContext, d["id"])
            else -> message(d["title"], d["body"])
        }
    }

    private fun message(title: String?, body: String?) {
        if (AppState.foreground) return  // the chat is on screen: the message is already visible
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("messages", "Messages", NotificationManager.IMPORTANCE_HIGH))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        nm.notify(1, NotificationCompat.Builder(this, "messages")
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(title ?: "Bunny Tale")
            .setContentText(body ?: "New message")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(open)
            .build())
    }

    /** A rotated token is registered right away (with the WebView's login cookie), not only when the app is opened next. */
    override fun onNewToken(token: String) {
        val prefs = getSharedPreferences("app", MODE_PRIVATE)
        prefs.edit().putString("fcmTok", token).apply()
        val cookie = try { CookieManager.getInstance().getCookie(BuildConfig.SERVER_URL) } catch (_: Exception) { null } ?: return
        Api.post("/push/fcm", JSONObject().put("token", token).put("msgs", prefs.getBoolean("msgs", false)), cookie)
    }
}
