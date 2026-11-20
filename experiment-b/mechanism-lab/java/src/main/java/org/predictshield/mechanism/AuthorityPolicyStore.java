package org.predictshield.mechanism;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Lab-only atomic policy snapshot file. A digest detects accidental corruption,
 * not malicious modification; this is NOT an authenticated production policy store.
 *
 * A malformed or unreadable existing file must never be replaced with an
 * implicit allowed policy. No automatic fallback to clean state is permitted.
 */
public final class AuthorityPolicyStore {
    private static final String HEADER = "PREDICT_SHIELD_AUTHORITY_V1";
    private final Path path;

    public AuthorityPolicyStore(Path path) {
        this.path = path.toAbsolutePath().normalize();
    }

    public synchronized PolicyRevision loadOrInitialize() {
        if (Files.isSymbolicLink(path)) {
            throw new IllegalStateException("Refusing authority state symlink");
        }
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            PolicyRevision fresh = new PolicyRevision(0, false);
            save(fresh);
            return fresh;
        }
        try {
            String[] fields = Files.readString(path, StandardCharsets.UTF_8).split("\\n", -1);
            if (fields.length != 6 || !HEADER.equals(fields[0]) ||
                    !fields[1].startsWith("revision=") ||
                    !fields[2].startsWith("revoked=") ||
                    !fields[3].startsWith("trial=") ||
                    !fields[4].startsWith("sha256=") || !fields[5].isEmpty()) {
                throw new IllegalStateException("Invalid durable authority state schema");
            }
            String data = String.join("\n", fields[0], fields[1], fields[2], fields[3]) + "\n";
            if (!digest(data).equals(fields[4].substring(7))) {
                throw new IllegalStateException("Durable authority state digest mismatch");
            }
            String flag = fields[2].substring("revoked=".length());
            if (!flag.equals("true") && !flag.equals("false")) {
                throw new IllegalStateException("Invalid durable revoked value");
            }
            String trial = fields[3].substring("trial=".length());
            if (!trial.equals("unassigned") && !trial.matches("[0-9a-fA-F-]{36}")) {
                throw new IllegalStateException("Invalid durable trial identity");
            }
            return new PolicyRevision(
                    Long.parseLong(fields[1].substring("revision=".length())),
                    Boolean.parseBoolean(flag), trial);
        } catch (IOException | NumberFormatException ex) {
            throw new IllegalStateException("Could not restore durable authority policy", ex);
        }
    }

    public synchronized void save(PolicyRevision policy) {
        if (policy == null || Files.isSymbolicLink(path)) {
            throw new IllegalStateException("Invalid authority persistence destination");
        }
        Path tmp = null;
        try {
            Files.createDirectories(path.getParent());
            String data = HEADER + "\nrevision=" + policy.revision() +
                    "\nrevoked=" + policy.revoked() +
                    "\ntrial=" + policy.trialId() + "\n";
            String payload = data + "sha256=" + digest(data) + "\n";
            tmp = path.resolveSibling(path.getFileName() + "." + UUID.randomUUID() + ".tmp");
            byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException ex) {
            throw new IllegalStateException("Atomic state replacement not supported", ex);
        } catch (IOException ex) {
            throw new IllegalStateException("Durable authority policy write failed", ex);
        } finally {
            if (tmp != null) {
                try { Files.deleteIfExists(tmp); } catch (IOException ignored) { }
            }
        }
    }

    private static String digest(String source) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(source.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("JVM missing SHA-256", ex);
        }
    }
}
