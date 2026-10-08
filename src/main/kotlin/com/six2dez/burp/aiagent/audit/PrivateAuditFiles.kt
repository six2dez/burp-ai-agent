package com.six2dez.burp.aiagent.audit

import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel
import java.nio.file.Files
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

/**
 * Owner-only file system helpers for the audit trail (quick 261008-sqa).
 *
 * On a POSIX file system, files are created through a channel opened with the `rw-------`
 * attribute and audit-owned directories with `rwx------` set at creation, so there is no
 * create-then-chmod window. A file or audit-owned directory that already exists is tightened on
 * every write before any new byte lands: group and other bits are removed and the owner bits are
 * kept exactly, so a permission is never added. A failed tighten propagates as an [java.io.IOException]
 * and the caller writes nothing for that record (fail closed). The shared base directory
 * (`~/.burp-ai-agent`, also used by backends/, certs/, logs/ and profiles) is created owner-only
 * when the audit trail creates it and is left as it is otherwise. Non-POSIX file systems get plain
 * creation (best effort; Windows relies on the user-profile ACL).
 */
internal object PrivateAuditFiles {
    private val OWNER_ONLY_FILE = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
    private val OWNER_ONLY_DIRECTORY = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    private val OWNER_BITS =
        setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
    private val APPEND: Set<OpenOption> =
        setOf(StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE)
    private val REPLACE: Set<OpenOption> =
        setOf(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)

    fun isPosix(path: Path): Boolean = path.fileSystem.supportedFileAttributeViews().contains("posix")

    /**
     * Makes sure [dir] exists. A missing directory (and any missing parent) is created owner-only on
     * POSIX. An existing directory is tightened only when [ownedByAudit] is true.
     */
    fun ensureDirectory(
        dir: Path,
        ownedByAudit: Boolean,
    ) {
        if (Files.isDirectory(dir)) {
            if (ownedByAudit) tighten(dir)
        } else if (isPosix(dir)) {
            Files.createDirectories(dir, OWNER_ONLY_DIRECTORY)
        } else {
            Files.createDirectories(dir)
        }
    }

    /** Opens [file] for appending; created `rw-------`, or tightened before anything is written. */
    fun openForAppend(file: Path): SeekableByteChannel = open(file, APPEND)

    /** Opens [file] for replacing its content; created `rw-------`, or tightened before anything is written. */
    fun openForReplace(file: Path): SeekableByteChannel = open(file, REPLACE)

    fun append(
        file: Path,
        bytes: ByteArray,
    ) {
        openForAppend(file).use { writeFully(it, bytes) }
    }

    fun replace(
        file: Path,
        bytes: ByteArray,
    ) {
        openForReplace(file).use { writeFully(it, bytes) }
    }

    /** Removes group and other bits, keeping the owner bits exactly; writes only if something changed. */
    fun tighten(path: Path) {
        if (!isPosix(path)) return
        val current = Files.getPosixFilePermissions(path)
        val ownerOnly = current.filter { it in OWNER_BITS }.toSet()
        if (ownerOnly != current) {
            Files.setPosixFilePermissions(path, ownerOnly)
        }
    }

    private fun open(
        file: Path,
        options: Set<OpenOption>,
    ): SeekableByteChannel {
        val posix = isPosix(file)
        val channel =
            if (posix) Files.newByteChannel(file, options, OWNER_ONLY_FILE) else Files.newByteChannel(file, options)
        try {
            if (posix) tighten(file)
        } catch (e: java.io.IOException) {
            channel.close()
            throw e
        }
        return channel
    }

    private fun writeFully(
        channel: SeekableByteChannel,
        bytes: ByteArray,
    ) {
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) {
            channel.write(buffer)
        }
    }
}
