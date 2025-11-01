package com.cryochat.model;

public class FileInfo {
    private String originalName;
    private String storedName;
    private long size;
    private String mimeType;

    public FileInfo() {}

    public FileInfo(String originalName, String storedName, long size, String mimeType) {
        this.originalName = originalName;
        this.storedName = storedName;
        this.size = size;
        this.mimeType = mimeType;
    }

    // Getters and Setters
    public String getOriginalName() { return originalName; }
    public void setOriginalName(String originalName) { this.originalName = originalName; }

    public String getStoredName() { return storedName; }
    public void setStoredName(String storedName) { this.storedName = storedName; }

    public long getSize() { return size; }
    public void setSize(long size) { this.size = size; }

    public String getMimeType() { return mimeType; }
    public void setMimeType(String mimeType) { this.mimeType = mimeType; }
}