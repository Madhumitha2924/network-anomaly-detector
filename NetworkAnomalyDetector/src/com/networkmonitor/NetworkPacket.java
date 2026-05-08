package com.networkmonitor;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a single network traffic packet/flow record.
 * Each packet captures key telemetry fields used for anomaly detection.
 */
public class NetworkPacket {

    public enum Protocol { TCP, UDP, ICMP, HTTP, HTTPS, DNS, FTP, SSH }
    public enum AnomalyType { NONE, PORT_SCAN, DDOS, LARGE_TRANSFER, HIGH_FREQUENCY, SUSPICIOUS_PORT, BRUTE_FORCE }

    private final String packetId;
    private final String sourceIP;
    private final String destinationIP;
    private final int sourcePort;
    private final int destinationPort;
    private final Protocol protocol;
    private final long bytesSent;
    private final long packetCount;
    private final double durationMs;
    private final LocalDateTime timestamp;

    // Derived / labeled fields
    private AnomalyType anomalyType;
    private double anomalyScore;    // 0.0 (normal) to 1.0 (highly anomalous)
    private boolean flagged;

    public NetworkPacket(String packetId, String sourceIP, String destinationIP,
                         int sourcePort, int destinationPort, Protocol protocol,
                         long bytesSent, long packetCount, double durationMs,
                         LocalDateTime timestamp) {
        this.packetId = packetId;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.bytesSent = bytesSent;
        this.packetCount = packetCount;
        this.durationMs = durationMs;
        this.timestamp = timestamp;
        this.anomalyType = AnomalyType.NONE;
        this.anomalyScore = 0.0;
        this.flagged = false;
    }

    // ---- Getters ----
    public String getPacketId()        { return packetId; }
    public String getSourceIP()        { return sourceIP; }
    public String getDestinationIP()   { return destinationIP; }
    public int getSourcePort()         { return sourcePort; }
    public int getDestinationPort()    { return destinationPort; }
    public Protocol getProtocol()      { return protocol; }
    public long getBytesSent()         { return bytesSent; }
    public long getPacketCount()       { return packetCount; }
    public double getDurationMs()      { return durationMs; }
    public LocalDateTime getTimestamp(){ return timestamp; }
    public AnomalyType getAnomalyType(){ return anomalyType; }
    public double getAnomalyScore()    { return anomalyScore; }
    public boolean isFlagged()         { return flagged; }

    // ---- Setters ----
    public void setAnomalyType(AnomalyType type)  { this.anomalyType = type; }
    public void setAnomalyScore(double score)      { this.anomalyScore = Math.min(1.0, Math.max(0.0, score)); }
    public void setFlagged(boolean flagged)        { this.flagged = flagged; }

    // ---- Derived features used by detector ----
    public double getBytesPerPacket() {
        return packetCount == 0 ? 0 : (double) bytesSent / packetCount;
    }

    public double getPacketsPerMs() {
        return durationMs == 0 ? 0 : (double) packetCount / durationMs;
    }

    public boolean isSuspiciousPort() {
        int dp = destinationPort;
        return dp == 22 || dp == 23 || dp == 3389 || dp == 445 ||
               dp == 1433 || dp == 3306 || dp == 5900 || dp == 6666 ||
               dp == 4444 || dp == 31337;
    }

    public boolean isWellKnownPort() {
        return destinationPort == 80 || destinationPort == 443 ||
               destinationPort == 53  || destinationPort == 25;
    }

    @Override
    public String toString() {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("HH:mm:ss");
        return String.format("[%s] %s → %s:%d | %s | %,d bytes | score=%.2f | %s",
            timestamp.format(fmt), sourceIP, destinationIP, destinationPort,
            protocol, bytesSent, anomalyScore,
            flagged ? "*** " + anomalyType + " ***" : "NORMAL");
    }
}
