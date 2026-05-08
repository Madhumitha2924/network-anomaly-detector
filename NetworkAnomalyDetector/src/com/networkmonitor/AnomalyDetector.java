package com.networkmonitor;

import java.util.*;
import java.util.stream.Collectors;

/**
 * AnomalyDetector — Core ML-style detection engine (pure Java, no external libs).
 *
 * Algorithms implemented:
 *   1. Z-Score Detection  — flags packets whose features deviate > threshold std deviations
 *   2. IQR (Interquartile Range) — robust outlier detection for skewed traffic distributions
 *   3. Rule-Based Heuristics — domain-specific telecom/network rules (port scans, DDoS patterns)
 *   4. IP Frequency Analysis — detects IPs generating abnormally high request volumes
 *
 * This mirrors Nokia Bell Labs' AIOps approach: combine statistical baselines
 * with domain-expert rules for network anomaly detection.
 */
public class AnomalyDetector {

    // ---- Thresholds (tunable) ----
    private static final double Z_SCORE_THRESHOLD      = 2.5;   // std deviations from mean
    private static final double HIGH_BYTES_IQR_FACTOR  = 2.0;   // IQR multiplier for large transfer
    private static final long   DDOS_PACKET_THRESHOLD  = 5000;  // packets in a single flow
    private static final double HIGH_FREQ_PPS           = 50.0;  // packets per ms threshold
    private static final int    PORT_SCAN_UNIQUE_PORTS  = 10;    // unique dest ports per source IP
    private static final int    BRUTE_FORCE_MIN_PACKETS = 200;   // repeated hits on auth port

    // ---- Baseline statistics (computed from training data) ----
    private double meanBytes, stdBytes;
    private double meanPackets, stdPackets;
    private double meanDuration, stdDuration;
    private double q1Bytes, q3Bytes, iqrBytes;

    // ---- State for IP-level analysis ----
    private final Map<String, List<NetworkPacket>> packetsBySourceIP = new HashMap<>();
    private final Map<String, Set<Integer>> portsBySourceIP = new HashMap<>();

    private boolean baselineFitted = false;

    /**
     * Step 1: Fit the detector on a "normal" baseline dataset.
     * Computes mean, std, and IQR for key features.
     */
    public void fit(List<NetworkPacket> baselinePackets) {
        if (baselinePackets.isEmpty()) throw new IllegalArgumentException("Baseline cannot be empty");

        double[] bytes    = baselinePackets.stream().mapToDouble(NetworkPacket::getBytesSent).toArray();
        double[] packets  = baselinePackets.stream().mapToDouble(NetworkPacket::getPacketCount).toArray();
        double[] duration = baselinePackets.stream().mapToDouble(NetworkPacket::getDurationMs).toArray();

        meanBytes    = mean(bytes);    stdBytes    = std(bytes,    meanBytes);
        meanPackets  = mean(packets);  stdPackets  = std(packets,  meanPackets);
        meanDuration = mean(duration); stdDuration = std(duration, meanDuration);

        // IQR for bytes
        double[] sortedBytes = Arrays.copyOf(bytes, bytes.length);
        Arrays.sort(sortedBytes);
        q1Bytes  = percentile(sortedBytes, 25);
        q3Bytes  = percentile(sortedBytes, 75);
        iqrBytes = q3Bytes - q1Bytes;

        baselineFitted = true;
        System.out.printf("[Detector] Baseline fitted on %d packets%n", baselinePackets.size());
        System.out.printf("           Bytes  — mean: %,.0f  std: %,.0f  IQR: %,.0f%n", meanBytes, stdBytes, iqrBytes);
        System.out.printf("           Packets— mean: %,.0f  std: %,.0f%n", meanPackets, stdPackets);
    }

    /**
     * Step 2: Analyze a batch of incoming packets and flag anomalies.
     * Returns only the flagged (anomalous) packets.
     */
    public List<NetworkPacket> detect(List<NetworkPacket> packets) {
        if (!baselineFitted) throw new IllegalStateException("Call fit() before detect()");

        // Build IP-level indexes
        buildIPIndex(packets);

        for (NetworkPacket p : packets) {
            double score = 0.0;
            NetworkPacket.AnomalyType type = NetworkPacket.AnomalyType.NONE;

            // --- Rule 1: Z-Score on bytes sent ---
            double zBytes = zScore(p.getBytesSent(), meanBytes, stdBytes);
            if (zBytes > Z_SCORE_THRESHOLD) {
                score = Math.max(score, normalize(zBytes, Z_SCORE_THRESHOLD, 6.0));
                type = NetworkPacket.AnomalyType.LARGE_TRANSFER;
            }

            // --- Rule 2: IQR outlier on bytes ---
            if (p.getBytesSent() > q3Bytes + HIGH_BYTES_IQR_FACTOR * iqrBytes) {
                score = Math.max(score, 0.75);
                type = NetworkPacket.AnomalyType.LARGE_TRANSFER;
            }

            // --- Rule 3: DDoS — huge packet count ---
            if (p.getPacketCount() > DDOS_PACKET_THRESHOLD) {
                double zPkt = zScore(p.getPacketCount(), meanPackets, stdPackets);
                score = Math.max(score, Math.min(1.0, 0.6 + normalize(zPkt, 2.0, 5.0) * 0.4));
                type = NetworkPacket.AnomalyType.DDOS;
            }

            // --- Rule 4: High frequency (packets per ms) ---
            if (p.getPacketsPerMs() > HIGH_FREQ_PPS) {
                score = Math.max(score, 0.80);
                type = NetworkPacket.AnomalyType.HIGH_FREQUENCY;
            }

            // --- Rule 5: Suspicious destination port ---
            if (p.isSuspiciousPort()) {
                score = Math.max(score, 0.65);
                type = score > 0.7 ? type : NetworkPacket.AnomalyType.SUSPICIOUS_PORT;
            }

            // --- Rule 6: Port scan — source IP hitting many unique ports ---
            String srcIP = p.getSourceIP();
            int uniquePorts = portsBySourceIP.getOrDefault(srcIP, Collections.emptySet()).size();
            if (uniquePorts >= PORT_SCAN_UNIQUE_PORTS) {
                score = Math.max(score, 0.70 + Math.min(0.25, (uniquePorts - PORT_SCAN_UNIQUE_PORTS) * 0.02));
                type = NetworkPacket.AnomalyType.PORT_SCAN;
            }

            // --- Rule 7: Brute force — high packets on SSH/RDP/FTP ---
            if ((p.getDestinationPort() == 22 || p.getDestinationPort() == 3389 || p.getDestinationPort() == 21)
                    && p.getPacketCount() > BRUTE_FORCE_MIN_PACKETS) {
                score = Math.max(score, 0.85);
                type = NetworkPacket.AnomalyType.BRUTE_FORCE;
            }

            // --- Z-Score on Z packets (secondary signal) ---
            double zPkt = zScore(p.getPacketCount(), meanPackets, stdPackets);
            if (zPkt > Z_SCORE_THRESHOLD && score < 0.5) {
                score = Math.max(score, normalize(zPkt, Z_SCORE_THRESHOLD, 5.0) * 0.6);
            }

            p.setAnomalyScore(score);
            if (score >= 0.5) {
                p.setFlagged(true);
                p.setAnomalyType(type);
            }
        }

        return packets.stream().filter(NetworkPacket::isFlagged).collect(Collectors.toList());
    }

    // ---- IP indexing helpers ----
    private void buildIPIndex(List<NetworkPacket> packets) {
        packetsBySourceIP.clear();
        portsBySourceIP.clear();
        for (NetworkPacket p : packets) {
            packetsBySourceIP.computeIfAbsent(p.getSourceIP(), k -> new ArrayList<>()).add(p);
            portsBySourceIP.computeIfAbsent(p.getSourceIP(), k -> new HashSet<>()).add(p.getDestinationPort());
        }
    }

    // ---- Statistical utilities ----
    private double mean(double[] data) {
        double sum = 0;
        for (double d : data) sum += d;
        return sum / data.length;
    }

    private double std(double[] data, double mean) {
        double variance = 0;
        for (double d : data) variance += (d - mean) * (d - mean);
        return Math.sqrt(variance / data.length);
    }

    private double zScore(double value, double mean, double std) {
        if (std == 0) return 0;
        return Math.abs((value - mean) / std);
    }

    private double percentile(double[] sorted, double p) {
        double index = (p / 100.0) * (sorted.length - 1);
        int lower = (int) index;
        int upper = Math.min(lower + 1, sorted.length - 1);
        return sorted[lower] + (index - lower) * (sorted[upper] - sorted[lower]);
    }

    // Maps a z-score [low..high] → [0..1]
    private double normalize(double value, double low, double high) {
        return Math.min(1.0, Math.max(0.0, (value - low) / (high - low)));
    }

    // ---- Getters for reporting ----
    public double getMeanBytes()   { return meanBytes; }
    public double getStdBytes()    { return stdBytes; }
    public double getMeanPackets() { return meanPackets; }
    public Map<String, List<NetworkPacket>> getPacketsBySourceIP() { return packetsBySourceIP; }
    public Map<String, Set<Integer>> getPortsBySourceIP()          { return portsBySourceIP; }
}
