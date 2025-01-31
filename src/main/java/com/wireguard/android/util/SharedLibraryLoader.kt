package com.wireguard.android.util

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.annotation.RestrictTo
import com.wireguard.util.NonNullForAll
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.zip.ZipFile

@NonNullForAll
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
object SharedLibraryLoader {
    private const val TAG = "WireGuard/SharedLibraryLoader"

    @Throws(IOException::class)
    fun extractLibrary(context: Context, libName: String, destination: File): Boolean {
        val apks = context.applicationInfo.let { appInfo ->
            buildList {
                appInfo.sourceDir?.let { add(it) }
                appInfo.splitSourceDirs?.let { addAll(it) }
            }
        }

        val mappedLibName = System.mapLibraryName(libName)
        for (abi in Build.SUPPORTED_ABIS) {
            val libZipPath = "lib${File.separatorChar}$abi${File.separatorChar}$mappedLibName"
            for (apk in apks) {
                if (extractFromApk(apk, libZipPath, destination)) {
                    return true
                }
            }
        }
        return false
    }

    private fun extractFromApk(apk: String, libZipPath: String, destination: File): Boolean {
        return try {
            ZipFile(File(apk)).use { zipFile ->
                val zipEntry = zipFile.getEntry(libZipPath) ?: return false

                Log.d(TAG, "Extracting apk:/$libZipPath to ${destination.absolutePath}")
                zipFile.getInputStream(zipEntry).use { input ->
                    Files.copy(input, destination.toPath(), StandardCopyOption.REPLACE_EXISTING)
                }
                true
            }
        } catch (e: IOException) {
            Log.w(TAG, "Failed to extract library from APK: $apk", e)
            false
        }
    }

    @JvmStatic
    fun loadSharedLibrary(context: Context, libName: String) {
        try {
            System.loadLibrary(libName)
            return
        } catch (e: UnsatisfiedLinkError) {
            Log.d(TAG, "Failed to load library normally, so attempting to extract from apk", e)
        }

        val tempLib = File.createTempFile("lib", ".so", context.codeCacheDir)
        try {
            if (extractLibrary(context, libName, tempLib)) {
                System.load(tempLib.absolutePath)
                return
            }
            throw RuntimeException("Unable to find native library")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load library apk:/$libName", e)
            throw RuntimeException("Unable to load native library", e)
        } finally {
            tempLib.delete()
        }
    }
}
