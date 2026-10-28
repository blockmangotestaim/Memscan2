package com.memscan

import android.content.pm.ApplicationInfo
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { App() }
            }
        }
    }
}

data class AppEntry(val label: String, val pkg: String)
data class Hit(val addr: String, val hex: String)

val TYPES = listOf(
    "1 Byte" to "1", "2 Bytes" to "2", "4 Bytes" to "4", "8 Bytes" to "8",
    "Float" to "f", "Double" to "d", "Group" to ""
)

fun decode(type: String, hex: String): String {
    if (type == "Group") return hex
    val b = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    val bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
    return when (type) {
        "1 Byte" -> bb.get().toString()
        "2 Bytes" -> bb.short.toString()
        "4 Bytes" -> bb.int.toString()
        "8 Bytes" -> bb.long.toString()
        "Float" -> bb.float.toString()
        "Double" -> bb.double.toString()
        else -> hex
    }
}

@Composable
fun App() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val session = remember { RootSession(ctx.applicationInfo.sourceDir) }
    val apps = remember {
        val pm = ctx.packageManager
        pm.getInstalledApplications(0)
            .filter { it.packageName != ctx.packageName }
            .map { AppEntry(pm.getApplicationLabel(it).toString(), it.packageName) to ((it.flags and ApplicationInfo.FLAG_SYSTEM) != 0) }
            .sortedBy { it.first.label.lowercase() }
    }

    var target by remember { mutableStateOf<AppEntry?>(null) }
    var showPicker by remember { mutableStateOf(false) }
    var type by remember { mutableStateOf(TYPES[2]) }
    var typeMenu by remember { mutableStateOf(false) }
    var value by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0f) }
    var count by remember { mutableStateOf<Long?>(null) }
    var hits by remember { mutableStateOf(listOf<Hit>()) }
    var err by remember { mutableStateOf<String?>(null) }
    var scannedType by remember { mutableStateOf("4 Bytes") }
    var pidShown by remember { mutableStateOf(-1) }

    fun runScan() {
        val t = target ?: run { err = "Select a target app first."; return }
        val v = value.trim()
        if (v.isEmpty()) { err = "Enter a value."; return }
        val pat = if (type.second.isEmpty()) v else "${type.second}:$v"
        val tName = type.first
        busy = true; err = null; count = null; hits = emptyList(); progress = 0f
        scope.launch(Dispatchers.IO) {
            try {
                var pid = -1
                session.cmd("PID ${t.pkg}") { if (it.startsWith("PID ")) pid = it.substring(4).trim().toInt() }
                if (pid < 0) { err = "${t.label} is not running. Open it first."; return@launch }
                val list = mutableListOf<Hit>(); var c = 0L
                session.cmd("SCAN $pid $pat") { l ->
                    when {
                        l.startsWith("P ") -> progress = l.substring(2).trim().toFloat() / 100f
                        l.startsWith("R ") -> l.split(" ").let { list.add(Hit(it[1], it[2])) }
                        l.startsWith("C ") -> c = l.substring(2).trim().toLong()
                        l.startsWith("ERR") -> err = l
                    }
                }
                hits = list; count = c; scannedType = tName; pidShown = pid
            } catch (e: Exception) {
                err = e.message ?: e.toString()
            } finally { busy = false }
        }
    }

    Column(Modifier.fillMaxSize().statusBarsPadding().padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("MemScan  (read-only, root)", style = MaterialTheme.typography.titleLarge)

        OutlinedButton(onClick = { showPicker = true }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(target?.let { "${it.label}  (${it.pkg})" } ?: "Select target app")
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box {
                OutlinedButton(onClick = { typeMenu = true }, enabled = !busy) { Text(type.first) }
                DropdownMenu(expanded = typeMenu, onDismissRequest = { typeMenu = false }) {
                    TYPES.forEach { t ->
                        DropdownMenuItem(text = { Text(t.first) }, onClick = { type = t; typeMenu = false })
                    }
                }
            }
            OutlinedTextField(
                value = value, onValueChange = { value = it }, singleLine = type.first != "Group",
                label = { Text(if (type.first == "Group") "Group pattern" else "Value (a-b for range)") },
                modifier = Modifier.weight(1f), enabled = !busy
            )
        }
        if (type.first == "Group") {
            Text("e.g.  2:0 2:65535 4:100-200 w:35 1:* f:1.5 d:2.5~3\n" +
                "N:value (N=1,2,4,8 bytes)  f/d = float/double  w:N = skip N bytes  * = any",
                style = MaterialTheme.typography.bodySmall)
        }

        Button(onClick = { runScan() }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Scanning…" else "Scan")
        }
        if (busy) LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
        err?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        count?.let {
            Text("Found: $it" + if (pidShown > 0) "   (pid $pidShown)" else "", style = MaterialTheme.typography.titleMedium)
            if (it > hits.size) Text("Showing first ${hits.size}", style = MaterialTheme.typography.bodySmall)
        }
        LazyColumn(Modifier.weight(1f)) {
            items(hits) { h ->
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(h.addr.padStart(12, '0'), fontFamily = FontFamily.Monospace)
                    Text(decode(scannedType, h.hex), fontFamily = FontFamily.Monospace)
                }
                HorizontalDivider()
            }
        }
    }

    if (showPicker) {
        var q by remember { mutableStateOf("") }
        var sys by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { showPicker = false },
            confirmButton = { TextButton(onClick = { showPicker = false }) { Text("Close") } },
            title = { Text("Select app") },
            text = {
                Column {
                    OutlinedTextField(q, { q = it }, singleLine = true, label = { Text("Search") }, modifier = Modifier.fillMaxWidth())
                    Row { Checkbox(sys, { sys = it }); Text("Show system apps", Modifier.padding(top = 12.dp)) }
                    LazyColumn(Modifier.height(320.dp)) {
                        items(apps.filter { (a, s) ->
                            (sys || !s) && (a.label.contains(q, true) || a.pkg.contains(q, true))
                        }) { (a, _) ->
                            Column(Modifier.fillMaxWidth().clickable { target = a; showPicker = false }.padding(vertical = 8.dp)) {
                                Text(a.label); Text(a.pkg, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
        )
    }
}
