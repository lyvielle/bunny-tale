package app.bunnytale

import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import java.lang.ref.WeakReference

/** Full-screen alarm, shown over the lock screen with the screen turned on. */
class AlarmActivity : AppCompatActivity() {
    companion object {
        private var current: WeakReference<AlarmActivity>? = null
        fun close() { current?.get()?.let { a -> a.runOnUiThread { a.finish() } }; current = null }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Alarm.id == null) { finish(); return }  // already answered or over
        current = WeakReference(this)
        if (Build.VERSION.SDK_INT >= 27) { setShowWhenLocked(true); setTurnScreenOn(true) } else legacyLockFlags()
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        val dp = resources.displayMetrics.density
        fun text(s: String, size: Float, color: Int, bold: Boolean = false) = TextView(this).apply {
            this.text = s; textSize = size; setTextColor(color); gravity = Gravity.CENTER
            if (bold) typeface = Typeface.DEFAULT_BOLD
            setPadding(0, (8 * dp).toInt(), 0, (8 * dp).toInt())
        }
        fun round(color: Int) = GradientDrawable().apply { setColor(color); cornerRadius = 999f }
        fun button(label: String, bg: Int, h: Int, onClick: () -> Unit) = Button(this).apply {
            text = label; textSize = 17f; setTextColor(Color.WHITE); background = round(bg); isAllCaps = false
            stateListAnimator = null; minWidth = 0; minimumWidth = 0; setPadding(0, 0, 0, 0)
            layoutParams = LinearLayout.LayoutParams(0, (h * dp).toInt(), 1f).apply { val m = (5 * dp).toInt(); setMargins(m, 0, m, 0) }
            setOnClickListener { onClick(); finish() }
        }
        fun row(vararg bs: Button) = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                .apply { topMargin = (12 * dp).toInt() }
            bs.forEach { addView(it) }
        }
        val gray = Color.parseColor("#27272a")
        fun snooze(label: String, mins: Int) = button(label, gray, 56) { Alarm.answer(applicationContext, "snooze", mins) }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#09090b"))
            val pad = (24 * dp).toInt(); setPadding(pad, pad, pad, pad)
            addView(text("⏰", 72f, Color.parseColor("#f59e0b")))
            addView(text("Alarm", 32f, Color.WHITE, true))
            addView(text("${Alarm.from} is trying to wake you", 18f, Color.parseColor("#a1a1aa")))
            addView(LinearLayout(context).apply { minimumHeight = (28 * dp).toInt() })
            addView(text("Snooze", 14f, Color.parseColor("#71717a")))
            addView(row(snooze("5 min", 5), snooze("10 min", 10)))
            addView(row(snooze("30 min", 30), snooze("1 h", 60)))
            addView(row(button("Dismiss", Color.parseColor("#8b5cf6"), 64) { Alarm.answer(applicationContext, "dismiss") })
                .apply { (layoutParams as LinearLayout.LayoutParams).topMargin = (26 * dp).toInt() })
        })
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {}  // snooze or dismiss, not back
        })
    }

    @Suppress("DEPRECATION")
    private fun legacyLockFlags() = window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)

    override fun onDestroy() {
        if (current?.get() === this) current = null
        super.onDestroy()
    }
}
