package com.memscan

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.IOException

class RootSession(private val apk: String) {
    private var p: Process? = null
    private var w: BufferedWriter? = null
    private var r: BufferedReader? = null

    @Synchronized
    private fun ensure() {
        if (p?.isAlive == true) return
        val pr = ProcessBuilder("su").redirectErrorStream(true).start()
        p = pr; w = pr.outputStream.bufferedWriter(); r = pr.inputStream.bufferedReader()
        w!!.write("CLASSPATH=$apk exec app_process /system/bin com.memscan.RootMain\n")
        w!!.flush()
    }

    @Synchronized
    fun cmd(c: String, onLine: (String) -> Unit) {
        ensure()
        w!!.write(c + "\n"); w!!.flush()
        while (true) {
            val l = r!!.readLine() ?: throw IOException("Root process ended (is the device rooted?)")
            if (l == "END") break
            onLine(l)
        }
    }
}
