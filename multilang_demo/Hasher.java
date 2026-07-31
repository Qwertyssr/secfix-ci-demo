package com.example;

import java.security.MessageDigest;

public class Hasher {
    public static byte[] hash(byte[] data) throws Exception {
        // VULN (Fortify: Weak Cryptographic Hash) -> should become SHA-256
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
