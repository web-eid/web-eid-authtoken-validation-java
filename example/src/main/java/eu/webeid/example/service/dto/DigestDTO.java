// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.service.dto;

public class DigestDTO {
    private String hash;
    private String hashFunction;

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getHashFunction() {
        return hashFunction;
    }

    public void setHashFunction(String hashFunction) {
        this.hashFunction = hashFunction;
    }
}
